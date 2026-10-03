import assert from "node:assert/strict";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { buildGrpcServer } from "../src/grpc-server.js";
import type { Authenticator } from "../src/auth.js";
import { MemoryAccessRepository } from "../src/domain.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(here, "..", "proto", "access_service.proto");

const authenticate: Authenticator = async (authorization) => {
  const subjectId = authorization?.replace("Bearer ", "") || "anonymous";
  return {
    subjectId,
    service: subjectId === "service",
  };
};

async function startServer(repository = new MemoryAccessRepository()) {
  const server = buildGrpcServer({ repository, authenticate });
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      grpc.ServerCredentials.createInsecure(),
      (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
    );
  });
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(PROTO_PATH)],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as any;
  const authorizationClient =
    new proto.algaguard.access.v1.AuthorizationService(
      `127.0.0.1:${port}`,
      grpc.credentials.createInsecure(),
    );
  const registryClient = new proto.algaguard.access.v1.ResourceRegistryService(
    `127.0.0.1:${port}`,
    grpc.credentials.createInsecure(),
  );
  return {
    repository,
    authorizationClient,
    registryClient,
    stop: () =>
      new Promise<void>((resolve) => server.tryShutdown(() => resolve())),
  };
}

function metadataFor(bearer: string) {
  const metadata = new grpc.Metadata();
  metadata.set("authorization", `Bearer ${bearer}`);
  return metadata;
}

test("gRPC Decide requires a service principal", async () => {
  const { authorizationClient, stop } = await startServer();
  try {
    await assert.rejects(
      () =>
        new Promise((resolve, reject) => {
          authorizationClient.decide(
            {
              subjectId: "user-1",
              action: "organization.read",
              resourceType: 1,
            },
            metadataFor("user-1"),
            (error: grpc.ServiceError, response: unknown) =>
              error ? reject(error) : resolve(response),
          );
        }),
      (error: grpc.ServiceError) => {
        assert.equal(error.code, grpc.status.PERMISSION_DENIED);
        return true;
      },
    );
  } finally {
    await stop();
  }
});

test("gRPC Decide and RegisterResource round-trip for a service caller", async () => {
  const repository = new MemoryAccessRepository();
  const owner = await repository.createOrganization("Lab", "owner-1");
  const { authorizationClient, registryClient, stop } =
    await startServer(repository);
  try {
    const registerResponse = await new Promise((resolve, reject) => {
      registryClient.registerResource(
        {
          resourceType: 2, // device
          resourceId: randomUUID(),
          organizationId: owner.id,
        },
        metadataFor("service"),
        (error: grpc.ServiceError, response: unknown) =>
          error ? reject(error) : resolve(response),
      );
    });
    assert.ok(registerResponse);

    const decideResponse = await new Promise<any>((resolve, reject) => {
      authorizationClient.decide(
        {
          subjectId: "owner-1",
          action: "organization.read",
          resourceType: 1, // organization
          resourceId: owner.id,
        },
        metadataFor("service"),
        (error: grpc.ServiceError, response: unknown) =>
          error ? reject(error) : resolve(response),
      );
    });
    assert.equal(decideResponse.allowed, true);
    assert.equal(decideResponse.reason, "");
  } finally {
    await stop();
  }
});
