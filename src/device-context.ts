import { z } from "zod";

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
    const clientSecret = this.environment.SERVICE_CLIENT_SECRET;
    if (!clientSecret)
      throw new Error("SERVICE_CLIENT_SECRET is required for device context");
    const response = await this.fetcher(
      `${issuer}/protocol/openid-connect/token`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id:
            this.environment.SERVICE_CLIENT_ID ?? "algaguard-access-service",
          client_secret: clientSecret,
        }),
      },
    );
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

  async resolve(deviceUuid: string, correlationId?: string) {
    const response = await this.fetcher(
      `${this.environment.DEVICE_SERVICE_URL ?? "http://device-service:3000"}/v1/internal/devices/${encodeURIComponent(deviceUuid)}/context`,
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
    return context.deviceUuid === deviceUuid ? context : undefined;
  }
}
