import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { z } from "zod";
import { createAuthenticator, type Authenticator } from "./auth.js";
import { DomainError, type AccessRepository } from "./domain.js";
import type { DeviceContextResolver } from "./device-context.js";
import { createDecider } from "./decide.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(here, "..", "proto", "access_service.proto");

const RESOURCE_TYPE_BY_NUMBER = [
  undefined,
  "organization",
  "device",
  "profile",
  "command",
  "ota",
  "current-user",
] as const;

async function principalFromMetadata(
  authenticate: Authenticator,
  metadata: grpc.Metadata,
) {
  const [authorization] = metadata.get("authorization");
  const actor = await authenticate(
    typeof authorization === "string" ? authorization : undefined,
  );
  if (!actor.service)
    throw new DomainError(
      "SERVICE_TOKEN_REQUIRED",
      403,
      "Service token required",
    );
  return actor;
}

function grpcErrorFor(error: unknown): grpc.ServiceError {
  const [code, name, message] =
    error instanceof DomainError
      ? ([
          error.status === 403
            ? grpc.status.PERMISSION_DENIED
            : error.status === 404
              ? grpc.status.NOT_FOUND
              : error.status >= 500
                ? grpc.status.INTERNAL
                : grpc.status.INVALID_ARGUMENT,
          error.code,
          error.message,
        ] as const)
      : ([grpc.status.INTERNAL, "INTERNAL", "Internal error"] as const);
  return Object.assign(new Error(message), {
    code,
    name,
    details: message,
    metadata: new grpc.Metadata(),
  });
}

export interface GrpcServerDependencies {
  repository: AccessRepository;
  authenticate?: Authenticator;
  resolveDeviceContext?: DeviceContextResolver;
}

export function buildGrpcServer(dependencies: GrpcServerDependencies) {
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(PROTO_PATH)],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as any;
  const authenticate = dependencies.authenticate ?? createAuthenticator();
  const { repository } = dependencies;
  const decide = createDecider({
    repository,
    ...(dependencies.resolveDeviceContext
      ? { resolveDeviceContext: dependencies.resolveDeviceContext }
      : {}),
  });

  const server = new grpc.Server();

  server.addService(proto.algaguard.access.v1.AuthorizationService.service, {
    async decide(
      call: grpc.ServerUnaryCall<any, any>,
      callback: grpc.sendUnaryData<any>,
    ) {
      try {
        await principalFromMetadata(authenticate, call.metadata);
        const request = call.request;
        const resourceType = z
          .enum([
            "organization",
            "device",
            "profile",
            "command",
            "ota",
            "current-user",
          ])
          .parse(RESOURCE_TYPE_BY_NUMBER[request.resourceType]);
        const result = await decide(
          {
            subjectId: request.subjectId,
            action: request.action,
            resourceType,
            ...(request.resourceId ? { resourceId: request.resourceId } : {}),
            ...(request.organizationId
              ? { organizationId: request.organizationId }
              : {}),
          },
          call.metadata.get("x-correlation-id")[0] as string | undefined,
        );
        callback(null, {
          allowed: result.allowed,
          reason: result.allowed ? "" : result.reason,
          decidedAt: result.decidedAt,
          ttlSeconds: result.ttlSeconds,
          ownershipVersion: result.ownershipVersion ?? "",
          resolvedOrganizationId: result.organizationId ?? "",
        });
      } catch (error) {
        callback(grpcErrorFor(error));
      }
    },
  });

  server.addService(proto.algaguard.access.v1.ResourceRegistryService.service, {
    async registerResource(
      call: grpc.ServerUnaryCall<any, any>,
      callback: grpc.sendUnaryData<any>,
    ) {
      try {
        await principalFromMetadata(authenticate, call.metadata);
        const request = call.request;
        const resourceType = z
          .enum(["device", "profile", "command", "ota"])
          .parse(RESOURCE_TYPE_BY_NUMBER[request.resourceType]);
        if (resourceType === "device")
          z.string().uuid().parse(request.resourceId);
        z.string().uuid().parse(request.organizationId);
        await repository.registerResource(
          resourceType,
          request.resourceId,
          request.organizationId,
        );
        callback(null, {});
      } catch (error) {
        callback(grpcErrorFor(error));
      }
    },
  });

  return server;
}
