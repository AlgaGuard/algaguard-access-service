import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {
  createServiceTokenProvider,
  metadataWithServiceToken,
} from "./grpc-client.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const DEVICE_PROTO_PATH = path.resolve(
  here,
  "..",
  "proto",
  "device_service.proto",
);
const DEVICE_STATUS_NAME: Record<number, "ACTIVE"> = { 5: "ACTIVE" };

export interface DeviceContext {
  schema: "urn:algaguard:schema:internal:device-context:v1";
  schemaVersion: "1.0.0";
  deviceUuid: string;
  deviceId: string;
  organizationId: string;
  status: "ACTIVE";
  ownershipVersion: string;
  resolvedAt: string;
}

export interface DeviceContextResolver {
  resolve(
    deviceUuid: string,
    correlationId?: string,
  ): Promise<DeviceContext | undefined>;
  resolveByDeviceId?(
    deviceId: string,
    correlationId?: string,
  ): Promise<DeviceContext | undefined>;
}

const contextSchema = z
  .object({
    schema: z.literal("urn:algaguard:schema:internal:device-context:v1"),
    schemaVersion: z.literal("1.0.0"),
    deviceUuid: z.string().uuid(),
    deviceId: z.string().regex(/^AG-[0-9]{6}$/),
    organizationId: z.string().uuid(),
    status: z.literal("ACTIVE"),
    ownershipVersion: z.string().regex(/^[1-9][0-9]{0,19}$/),
    resolvedAt: z.string().datetime(),
    tankId: z.string().uuid().optional(),
    contextVersion: z.literal("1").optional(),
  })
  .strict();

export class OidcDeviceContextResolver implements DeviceContextResolver {
  private token?: { value: string; expiresAt: number };

  constructor(
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  private async serviceToken() {
    if (this.token && this.token.expiresAt > Date.now() + 10_000)
      return this.token.value;
    const issuer =
      this.environment.KEYCLOAK_ISSUER ??
      "http://keycloak:8080/realms/algaguard";
    const tokenUrl =
      this.environment.KEYCLOAK_TOKEN_URL ??
      `${issuer}/protocol/openid-connect/token`;
    const clientSecret = this.environment.SERVICE_CLIENT_SECRET;
    if (!clientSecret)
      throw new Error("SERVICE_CLIENT_SECRET is required for device context");
    const response = await this.fetcher(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id:
          this.environment.SERVICE_CLIENT_ID ?? "algaguard-access-service",
        client_secret: clientSecret,
      }),
    });
    if (!response.ok) throw new Error("Device context authentication failed");
    const body = (await response.json()) as {
      access_token?: string;
      expires_in?: number;
    };
    if (!body.access_token)
      throw new Error("Device context token response was invalid");
    this.token = {
      value: body.access_token,
      expiresAt: Date.now() + Math.max(body.expires_in ?? 30, 1) * 1000,
    };
    return this.token.value;
  }

  private async request(path: string, correlationId?: string) {
    const response = await this.fetcher(
      `${this.environment.DEVICE_SERVICE_URL ?? "http://device-service:3000"}${path}`,
      {
        headers: {
          authorization: `Bearer ${await this.serviceToken()}`,
          ...(correlationId ? { "x-correlation-id": correlationId } : {}),
        },
      },
    );
    if ([404, 409, 410].includes(response.status)) return undefined;
    if (!response.ok)
      throw new Error(
        `Device context resolution failed with ${response.status}`,
      );
    const context = contextSchema.parse(await response.json());
    return context;
  }

  async resolve(deviceUuid: string, correlationId?: string) {
    const context = await this.request(
      `/v1/internal/devices/${encodeURIComponent(deviceUuid)}/context`,
      correlationId,
    );
    if (!context) return undefined;
    return context.deviceUuid === deviceUuid ? context : undefined;
  }

  async resolveByDeviceId(deviceId: string, correlationId?: string) {
    const context = await this.request(
      `/v1/internal/devices/by-device-id/${encodeURIComponent(deviceId)}/context`,
      correlationId,
    );
    if (!context) return undefined;
    return context.deviceId === deviceId ? context : undefined;
  }
}

export class GrpcDeviceContextResolver implements DeviceContextResolver {
  private readonly client: any;
  private readonly serviceToken: () => Promise<string>;

  constructor(
    address: string,
    environment: NodeJS.ProcessEnv = process.env,
    serviceToken = createServiceTokenProvider(environment),
  ) {
    const packageDefinition = protoLoader.loadSync(DEVICE_PROTO_PATH, {
      keepCase: false,
      longs: String,
      enums: Number,
      defaults: true,
      oneofs: true,
      includeDirs: [path.dirname(DEVICE_PROTO_PATH)],
    });
    const proto = grpc.loadPackageDefinition(packageDefinition) as any;
    this.serviceToken = serviceToken;
    this.client = new proto.algaguard.device.v1.DeviceLookupService(
      address,
      grpc.credentials.createInsecure(),
    );
  }

  private toContext(response: any): DeviceContext {
    return {
      schema: "urn:algaguard:schema:internal:device-context:v1",
      schemaVersion: "1.0.0",
      deviceUuid: response.deviceUuid,
      deviceId: response.deviceId,
      organizationId: response.organizationId,
      status: DEVICE_STATUS_NAME[response.status] ?? "ACTIVE",
      ownershipVersion: response.ownershipVersion,
      resolvedAt: response.resolvedAt,
    };
  }

  private async call(
    method: "getContext" | "getContextByDeviceId",
    request: unknown,
    correlationId?: string,
  ) {
    const metadata = await metadataWithServiceToken(
      this.serviceToken,
      correlationId ? { "x-correlation-id": correlationId } : {},
    );
    return new Promise<any>((resolve, reject) => {
      this.client[method](
        request,
        metadata,
        (error: grpc.ServiceError, value: unknown) => {
          if (!error) {
            resolve(value);
            return;
          }
          if (
            error.code === grpc.status.NOT_FOUND ||
            error.code === grpc.status.FAILED_PRECONDITION
          ) {
            resolve(undefined);
            return;
          }
          reject(error);
        },
      );
    });
  }

  async resolve(deviceUuid: string, correlationId?: string) {
    const response = await this.call(
      "getContext",
      { deviceUuid },
      correlationId,
    );
    if (!response) return undefined;
    const context = this.toContext(response);
    return context.deviceUuid === deviceUuid ? context : undefined;
  }

  async resolveByDeviceId(deviceId: string, correlationId?: string) {
    const response = await this.call(
      "getContextByDeviceId",
      { deviceId },
      correlationId,
    );
    if (!response) return undefined;
    const context = this.toContext(response);
    return context.deviceId === deviceId ? context : undefined;
  }
}
