import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import { configuredServiceClients, type Authenticator } from "../src/auth.js";
import { MemoryAccessRepository } from "../src/domain.js";

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
