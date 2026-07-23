import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import { configuredServiceClients, type Authenticator } from "../src/auth.js";
import { MemoryAccessRepository } from "../src/domain.js";
import {
  OidcDeviceContextResolver,
  type DeviceContextResolver,
} from "../src/device-context.js";

const authenticate: Authenticator = async (authorization) => {
  const subjectId = authorization?.replace("Bearer ", "") || "anonymous";
  return {
    subjectId,
    email: `${subjectId}@example.test`,
    clientId:
      subjectId === "service" ? "algaguard-device-service" : "algaguard-web",
    service: subjectId === "service",
  };
};

function app() {
  return buildApp({ repository: new MemoryAccessRepository(), authenticate });
}

test("liveness, readiness, and correlation middleware are available", async () => {
  const instance = app();
  const live = await request(instance)
    .get("/health/live")
    .set("x-correlation-id", "test-correlation");
  assert.equal(live.status, 200);
  assert.equal(live.headers["x-correlation-id"], "test-correlation");
  assert.equal((await request(instance).get("/health/ready")).status, 200);
});

test("organization APIs derive ownership from the authenticated subject", async () => {
  const instance = app();
  const created = await request(instance)
    .post("/v1/organizations")
    .set("authorization", "Bearer owner")
    .send({ name: "Lab" });
  assert.equal(created.status, 201);
  const listed = await request(instance)
    .get("/v1/organizations")
    .set("authorization", "Bearer owner");
  assert.equal(listed.body.items[0].id, created.body.id);
});

test("internal authorization decisions require a validated service principal", async () => {
  const instance = app();
  const denied = await request(instance)
    .post("/v1/internal/authorizations/decide")
    .set("authorization", "Bearer user")
    .send({
      subjectId: "user",
      action: "device.read",
      resourceType: "device",
      resourceId: "AG-000001",
    });
  assert.equal(denied.status, 403);
  const accepted = await request(instance)
    .post("/v1/internal/authorizations/decide")
    .set("authorization", "Bearer service")
    .send({
      subjectId: "user",
      action: "device.read",
      resourceType: "device",
      resourceId: "AG-000001",
    });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.allowed, false);
});

test("unknown routes use bounded problem details", async () => {
  const response = await request(app()).get("/missing");
  assert.equal(response.status, 404);
  assert.match(
    response.headers["content-type"] ?? "",
    /application\/problem\+json/,
  );
});

test("telemetry is an allowlisted authorization-decision client", () => {
  assert.equal(
    configuredServiceClients({}).has("algaguard-telemetry-service"),
    true,
  );
});

test("device decisions verify UUID ownership and react to revocation and transfer", async () => {
  const repository = new MemoryAccessRepository();
  const organizationA = await repository.createOrganization("A", "owner-a");
  const organizationB = await repository.createOrganization("B", "owner-b");
  const deviceUuid = "20000000-0000-4000-8000-000000000001";
  await repository.registerResource("device", deviceUuid, organizationA.id);
  let contextOrganizationId = organizationA.id;
  let ownershipVersion = "1";
  const resolver: DeviceContextResolver = {
    async resolve(requestedUuid) {
      if (requestedUuid !== deviceUuid) return undefined;
      return {
        schema: "urn:algaguard:schema:internal:device-context:v1",
        schemaVersion: "1.0.0",
        deviceUuid,
        deviceId: "AG-000001",
        organizationId: contextOrganizationId,
        status: "ACTIVE",
        ownershipVersion,
        resolvedAt: new Date().toISOString(),
      };
    },
  };
  const instance = buildApp({
    repository,
    authenticate,
    resolveDeviceContext: resolver,
  });
  const decide = (subjectId: string, overrides: Record<string, unknown> = {}) =>
    request(instance)
      .post("/v1/internal/authorizations/decide")
      .set("authorization", "Bearer service")
      .send({
        subjectId,
        action: "device.credentials.view",
        resourceType: "device",
        resourceId: deviceUuid,
        organizationId: contextOrganizationId,
        eventTypes: ["telemetry.updated"],
        ...overrides,
      });

  const allowed = await decide("owner-a");
  assert.equal(allowed.body.allowed, true);
  assert.equal(allowed.body.ownershipVersion, "1");
  assert.equal(allowed.body.ttlSeconds, 5);
  assert.match(allowed.body.decidedAt, /Z$/);
  assert.equal((await decide("owner-b")).body.allowed, false);
  assert.equal(
    (
      await decide("owner-a", {
        resourceId: "not-a-uuid",
      })
    ).body.allowed,
    false,
  );
  assert.equal(
    (
      await decide("owner-a", {
        organizationId: organizationB.id,
      })
    ).body.reason,
    "RESOURCE_MISMATCH",
  );

  const invitation = await repository.createInvitation({
    organizationId: organizationA.id,
    email: "viewer@example.test",
    role: "VIEWER",
    invitedBy: "owner-a",
    expiresAt: new Date(Date.now() + 60_000),
  });
  await repository.acceptInvitation(
    invitation.token,
    "viewer",
    "viewer@example.test",
  );
  assert.equal((await decide("viewer")).body.allowed, true);
  await repository.revokeMembership(organizationA.id, "viewer");
  assert.equal((await decide("viewer")).body.allowed, false);

  contextOrganizationId = organizationB.id;
  ownershipVersion = "2";
  await repository.registerResource("device", deviceUuid, organizationB.id);
  assert.equal((await decide("owner-a")).body.allowed, false);
  const newOwner = await decide("owner-b");
  assert.equal(newOwner.body.allowed, true);
  assert.equal(newOwner.body.ownershipVersion, "2");
});

test("Device Service context resolution uses client credentials and validates identity", async () => {
  const deviceUuid = "20000000-0000-4000-8000-000000000001";
  const calls: Array<{ url: string; authorization?: string }> = [];
  const fetcher = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = input.toString();
    const authorization =
      new Headers(init?.headers).get("authorization") ?? undefined;
    calls.push({
      url,
      ...(authorization ? { authorization } : {}),
    });
    if (url.endsWith("/protocol/openid-connect/token"))
      return Response.json({ access_token: "service-token", expires_in: 30 });
    return Response.json({
      schema: "urn:algaguard:schema:internal:device-context:v1",
      schemaVersion: "1.0.0",
      deviceUuid,
      deviceId: "AG-000001",
      organizationId: "60000000-0000-4000-8000-000000000001",
      status: "ACTIVE",
      ownershipVersion: "1",
      resolvedAt: "2026-07-23T16:00:00Z",
      contextVersion: "1",
    });
  }) as typeof fetch;
  const resolver = new OidcDeviceContextResolver(
    {
      KEYCLOAK_ISSUER: "http://identity.test/realms/algaguard",
      DEVICE_SERVICE_URL: "http://device.test",
      SERVICE_CLIENT_ID: "algaguard-access-service",
      SERVICE_CLIENT_SECRET: "test-only",
    },
    fetcher,
  );
  assert.equal((await resolver.resolve(deviceUuid))?.deviceId, "AG-000001");
  assert.equal(calls[1]?.authorization, "Bearer service-token");
  assert.match(calls[1]?.url ?? "", new RegExp(`${deviceUuid}/context$`));
});
