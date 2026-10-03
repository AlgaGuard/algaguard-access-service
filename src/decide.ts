import { z } from "zod";
import type { AccessRepository, ResourceType } from "./domain.js";
import {
  OidcDeviceContextResolver,
  type DeviceContextResolver,
} from "./device-context.js";

// Actions these registered-but-not-yet-device-context-resolvable identities
// are still allowed to attempt -- mirrors the same constant in routes.ts;
// kept in sync by being the one place both the HTTP and gRPC entry points
// import from.
const REGISTERED_DEVICE_FALLBACK_ACTIONS = new Set([
  "device.credentials.bootstrap",
  "device.bootstrap.reissue",
  "device.physical-session-handoff.approve",
]);

export interface DecideInput {
  subjectId: string;
  action: string;
  resourceType: ResourceType;
  resourceId?: string;
  organizationId?: string;
}

export function createDecider(dependencies: {
  repository: AccessRepository;
  resolveDeviceContext?: DeviceContextResolver;
}) {
  const resolveDeviceContext =
    dependencies.resolveDeviceContext ?? new OidcDeviceContextResolver();
  const { repository } = dependencies;

  return async function decide(input: DecideInput, correlationId?: string) {
    let organizationId = input.organizationId;
    let ownershipVersion: string | undefined;
    let canonicalResourceId = input.resourceId;
    if (input.resourceType === "device") {
      const parsedUuid = z.string().uuid().safeParse(input.resourceId);
      const parsedDeviceId = z
        .string()
        .regex(/^AG-[0-9]{6}$/)
        .safeParse(input.resourceId);
      if (!parsedUuid.success && !parsedDeviceId.success)
        return {
          allowed: false,
          reason: "RESOURCE_MISMATCH" as const,
          decidedAt: new Date().toISOString(),
          ttlSeconds: 0,
        };
      const context = parsedUuid.success
        ? await resolveDeviceContext.resolve(parsedUuid.data, correlationId)
        : await resolveDeviceContext.resolveByDeviceId?.(
            parsedDeviceId.data!,
            correlationId,
          );
      if (
        !context &&
        parsedUuid.success &&
        REGISTERED_DEVICE_FALLBACK_ACTIONS.has(input.action)
      )
        return {
          ...(await repository.decide(input)),
          decidedAt: new Date().toISOString(),
          ttlSeconds: 0,
        };
      if (
        !context ||
        (organizationId && organizationId !== context.organizationId)
      )
        return {
          allowed: false,
          reason: "RESOURCE_MISMATCH" as const,
          decidedAt: new Date().toISOString(),
          ttlSeconds: 0,
        };
      organizationId = context.organizationId;
      ownershipVersion = context.ownershipVersion;
      canonicalResourceId = context.deviceUuid;
    }
    return {
      ...(await repository.decide({
        ...input,
        ...(canonicalResourceId ? { resourceId: canonicalResourceId } : {}),
        ...(organizationId ? { organizationId } : {}),
      })),
      decidedAt: new Date().toISOString(),
      ttlSeconds: 5,
      ...(ownershipVersion ? { ownershipVersion } : {}),
    };
  };
}

export type Decider = ReturnType<typeof createDecider>;
