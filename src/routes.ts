import { Router, type Request } from "express";
import { z } from "zod";
import {
  createAuthenticator,
  type Authenticator,
  type Principal,
} from "./auth.js";
import {
  DomainError,
  type AccessRepository,
  type ResourceType,
} from "./domain.js";
import {
  OidcDeviceContextResolver,
  type DeviceContextResolver,
} from "./device-context.js";

class FixedWindowLimiter {
  private readonly windows = new Map<
    string,
    { count: number; resetsAt: number }
  >();
  constructor(
    private readonly maximum = 30,
    private readonly windowMs = 60_000,
  ) {}
  take(key: string, now = Date.now()) {
    const current = this.windows.get(key);
    if (!current || current.resetsAt <= now) {
      this.windows.set(key, { count: 1, resetsAt: now + this.windowMs });
      return true;
    }
    current.count += 1;
    return current.count <= this.maximum;
  }
}

export interface RouteDependencies {
  repository: AccessRepository;
  authenticate?: Authenticator;
  resolveDeviceContext?: DeviceContextResolver;
}

async function principal(request: Request, authenticate: Authenticator) {
  return authenticate(request.header("authorization"));
}

async function requireOrganizationPermission(
  repository: AccessRepository,
  actor: Principal,
  organizationId: string,
  action: string,
) {
  const decision = await repository.decide({
    subjectId: actor.subjectId,
    action,
    resourceType: "organization",
    resourceId: organizationId,
  });
  if (!decision.allowed)
    throw new DomainError("FORBIDDEN", 403, "Operation is not authorized");
}

export function createRouter(dependencies: RouteDependencies) {
  const router = Router();
  const authenticate = dependencies.authenticate ?? createAuthenticator();
  const resolveDeviceContext =
    dependencies.resolveDeviceContext ?? new OidcDeviceContextResolver();
  const { repository } = dependencies;
  const limiter = new FixedWindowLimiter();

  async function decide(
    input: {
      subjectId: string;
      action: string;
      resourceType: ResourceType;
      resourceId?: string;
      organizationId?: string;
    },
    request: Request,
  ) {
    let organizationId = input.organizationId;
    let ownershipVersion: string | undefined;
    if (input.resourceType === "device") {
      const parsedUuid = z.string().uuid().safeParse(input.resourceId);
      if (!parsedUuid.success)
        return {
          allowed: false,
          reason: "RESOURCE_MISMATCH" as const,
          decidedAt: new Date().toISOString(),
          ttlSeconds: 0,
        };
      const context = await resolveDeviceContext.resolve(
        parsedUuid.data,
        request.header("x-correlation-id"),
      );
      if (!context && input.action === "device.credentials.bootstrap")
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
    }
    return {
      ...(await repository.decide({
        ...input,
        ...(organizationId ? { organizationId } : {}),
      })),
      decidedAt: new Date().toISOString(),
      ttlSeconds: 5,
      ...(ownershipVersion ? { ownershipVersion } : {}),
    };
  }

  router.post("/organizations", async (request, response) => {
    const actor = await principal(request, authenticate);
    const input = z
      .object({ name: z.string().trim().min(1).max(120) })
      .parse(request.body);
    response
      .status(201)
      .json(await repository.createOrganization(input.name, actor.subjectId));
  });

  router.get("/organizations", async (request, response) => {
    const actor = await principal(request, authenticate);
    response.json({
      items: await repository.organizationsFor(actor.subjectId),
    });
  });

  router.post("/organizations/:id/invitations", async (request, response) => {
    const actor = await principal(request, authenticate);
    if (!limiter.take(`invite:${actor.subjectId}`))
      throw new DomainError(
        "RATE_LIMITED",
        429,
        "Invitation rate limit exceeded",
      );
    await requireOrganizationPermission(
      repository,
      actor,
      request.params.id,
      "access.manage",
    );
    const input = z
      .object({
        email: z.string().email(),
        role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]).default("VIEWER"),
        expiresInSeconds: z.number().int().min(60).max(604_800).default(86_400),
      })
      .parse(request.body);
    const result = await repository.createInvitation({
      organizationId: request.params.id,
      email: input.email,
      role: input.role,
      invitedBy: actor.subjectId,
      expiresAt: new Date(Date.now() + input.expiresInSeconds * 1000),
    });
    response.status(201).json(result);
  });

  router.post("/invitations/accept", async (request, response) => {
    const actor = await principal(request, authenticate);
    if (!limiter.take(`accept:${actor.subjectId}`))
      throw new DomainError(
        "RATE_LIMITED",
        429,
        "Invitation acceptance rate limit exceeded",
      );
    if (!actor.email)
      throw new DomainError(
        "EMAIL_REQUIRED",
        403,
        "A verified token email is required",
      );
    const input = z
      .object({ token: z.string().min(32).max(256) })
      .parse(request.body);
    response.json(
      await repository.acceptInvitation(
        input.token,
        actor.subjectId,
        actor.email,
      ),
    );
  });

  router.patch(
    "/organizations/:id/memberships/:subjectId",
    async (request, response) => {
      const actor = await principal(request, authenticate);
      await requireOrganizationPermission(
        repository,
        actor,
        request.params.id,
        "access.manage",
      );
      const input = z
        .object({ role: z.enum(["OWNER", "ADMIN", "OPERATOR", "VIEWER"]) })
        .parse(request.body);
      if (input.role === "OWNER")
        throw new DomainError(
          "USE_OWNERSHIP_TRANSFER",
          409,
          "Use the atomic ownership transfer endpoint",
        );
      response.json(
        await repository.changeRole(
          request.params.id,
          request.params.subjectId,
          input.role,
        ),
      );
    },
  );

  router.post(
    "/organizations/:id/ownership-transfer",
    async (request, response) => {
      const actor = await principal(request, authenticate);
      await requireOrganizationPermission(
        repository,
        actor,
        request.params.id,
        "organization.transfer",
      );
      const input = z
        .object({ nextOwnerSubjectId: z.string().min(1).max(255) })
        .parse(request.body);
      response.json(
        await repository.transferOwnership(
          request.params.id,
          actor.subjectId,
          input.nextOwnerSubjectId,
        ),
      );
    },
  );

  router.delete(
    "/organizations/:id/memberships/:subjectId",
    async (request, response) => {
      const actor = await principal(request, authenticate);
      await requireOrganizationPermission(
        repository,
        actor,
        request.params.id,
        "access.manage",
      );
      await repository.revokeMembership(
        request.params.id,
        request.params.subjectId,
      );
      response.status(204).end();
    },
  );

  router.put(
    "/internal/resources/:resourceType/:resourceId",
    async (request, response) => {
      const actor = await principal(request, authenticate);
      if (!actor.service)
        throw new DomainError(
          "SERVICE_TOKEN_REQUIRED",
          403,
          "Service token required",
        );
      const resourceType = z
        .enum(["device", "profile", "command", "ota"])
        .parse(request.params.resourceType);
      if (resourceType === "device")
        z.string().uuid().parse(request.params.resourceId);
      const input = z
        .object({ organizationId: z.string().uuid() })
        .strict()
        .parse(request.body);
      await repository.registerResource(
        resourceType,
        request.params.resourceId,
        input.organizationId,
      );
      response.status(204).end();
    },
  );

  router.post("/internal/authorizations/decide", async (request, response) => {
    const actor = await principal(request, authenticate);
    if (!actor.service)
      throw new DomainError(
        "SERVICE_TOKEN_REQUIRED",
        403,
        "Service token required",
      );
    const input = z
      .object({
        subjectId: z.string().min(1).max(255),
        action: z.string().min(1).max(64),
        resourceType: z.enum([
          "organization",
          "device",
          "profile",
          "command",
          "ota",
          "current-user",
        ]),
        resourceId: z.string().min(1).max(255).optional(),
        organizationId: z.string().uuid().optional(),
        eventTypes: z
          .array(z.string().min(1).max(64))
          .min(1)
          .max(10)
          .optional(),
      })
      .strict()
      .parse(request.body);
    response.json(
      await decide(
        {
          subjectId: input.subjectId,
          action: input.action,
          resourceType: input.resourceType,
          ...(input.resourceId ? { resourceId: input.resourceId } : {}),
          ...(input.organizationId
            ? { organizationId: input.organizationId }
            : {}),
        },
        request,
      ),
    );
  });

  router.post("/authorizations/subscriptions", async (request, response) => {
    const actor = await principal(request, authenticate);
    const input = z
      .object({
        subjectId: z.string().min(1).optional(),
        resourceType: z.enum(["organization", "device", "current-user"]),
        resourceId: z.string().min(1).max(255).optional(),
        organizationId: z.string().uuid().optional(),
        eventTypes: z
          .array(z.string().min(1).max(64))
          .min(1)
          .max(10)
          .optional(),
      })
      .strict()
      .parse(request.body);
    if (
      input.subjectId &&
      input.subjectId !== actor.subjectId &&
      !actor.service
    )
      throw new DomainError(
        "SUBJECT_MISMATCH",
        403,
        "Cannot decide for another subject",
      );
    const resourceType: ResourceType = input.resourceType;
    response.json(
      await decide(
        {
          subjectId: input.subjectId ?? actor.subjectId,
          action: "subscription.read",
          resourceType,
          ...(input.resourceId ? { resourceId: input.resourceId } : {}),
          ...(input.organizationId
            ? { organizationId: input.organizationId }
            : {}),
        },
        request,
      ),
    );
  });

  return router;
}
