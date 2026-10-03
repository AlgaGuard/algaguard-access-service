import assert from "node:assert/strict";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { GrpcDeviceContextResolver } from "../src/device-context.js";

const here = path.dirname(fileURLToPath(import.meta.url));
function loadProto(file: string) {
  const protoPath = path.resolve(here, "..", "proto", file);
  const packageDefinition = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(protoPath)],
  });
  return grpc.loadPackageDefinition(packageDefinition) as any;
}

function withFakeTokenEndpoint(
  testFn: (environment: NodeJS.ProcessEnv) => Promise<void>,
) {
  return async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: any) => {
      if (String(input).includes("/protocol/openid-connect/token"))
        return new Response(
          JSON.stringify({ access_token: "fake-token", expires_in: 300 }),
          { status: 200 },
        );
      return originalFetch(input);
    }) as typeof fetch;
    try {
      await testFn({
        SERVICE_CLIENT_SECRET: "test-secret",
        SERVICE_CLIENT_ID: "algaguard-access-service",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  };
}

test(
  "GrpcDeviceContextResolver resolves by UUID and by device id, and treats a 409/410-equivalent as absent",
  withFakeTokenEndpoint(async (environment) => {
    const proto = loadProto("device_service.proto");
    const deviceUuid = randomUUID();
    const organizationId = randomUUID();
    const server = new grpc.Server();
    server.addService(proto.algaguard.device.v1.DeviceLookupService.service, {
      getContext(
        call: grpc.ServerUnaryCall<any, any>,
        callback: grpc.sendUnaryData<any>,
      ) {
        if (call.request.deviceUuid !== deviceUuid) {
          callback(
            Object.assign(new Error("not found"), {
              code: grpc.status.NOT_FOUND,
            }),
          );
          return;
        }
        callback(null, {
          deviceUuid,
          deviceId: "AG-000001",
          organizationId,
          status: 5, // ACTIVE
          ownershipVersion: "1",
          resolvedAt: new Date().toISOString(),
          tankId: "",
          contextVersion: "1",
        });
      },
      getContextByDeviceId(
        call: grpc.ServerUnaryCall<any, any>,
        callback: grpc.sendUnaryData<any>,
      ) {
        if (call.request.deviceId !== "AG-000001") {
          callback(
            Object.assign(new Error("unclaimed"), {
              code: grpc.status.FAILED_PRECONDITION,
            }),
          );
          return;
        }
        callback(null, {
          deviceUuid,
          deviceId: "AG-000001",
          organizationId,
          status: 5,
          ownershipVersion: "1",
          resolvedAt: new Date().toISOString(),
          tankId: "",
          contextVersion: "1",
        });
      },
    });
    const port = await new Promise<number>((resolve, reject) => {
      server.bindAsync(
        "127.0.0.1:0",
        grpc.ServerCredentials.createInsecure(),
        (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
      );
    });
    try {
      const resolver = new GrpcDeviceContextResolver(
        `127.0.0.1:${port}`,
        environment,
      );
      const byUuid = await resolver.resolve(deviceUuid);
      assert.equal(byUuid?.organizationId, organizationId);

      const byDeviceId = await resolver.resolveByDeviceId("AG-000001");
      assert.equal(byDeviceId?.deviceUuid, deviceUuid);

      const missingByUuid = await resolver.resolve(randomUUID());
      assert.equal(missingByUuid, undefined);

      const missingByDeviceId = await resolver.resolveByDeviceId("AG-999999");
      assert.equal(missingByDeviceId, undefined);
    } finally {
      await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
    }
  }),
);
