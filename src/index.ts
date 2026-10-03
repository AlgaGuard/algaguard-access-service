import * as grpc from "@grpc/grpc-js";
import { buildApp } from "./app.js";
import { createPostgresPool } from "./adapters.js";
import { createAuthenticator } from "./auth.js";
import { loadConfig } from "./config.js";
import { GrpcDeviceContextResolver } from "./device-context.js";
import { PostgresAccessRepository } from "./repository.js";
import { buildGrpcServer } from "./grpc-server.js";

const config = loadConfig();
const repository = new PostgresAccessRepository(createPostgresPool(config));
const authenticate = createAuthenticator();
const resolveDeviceContext = new GrpcDeviceContextResolver(
  config.DEVICE_SERVICE_GRPC_ADDRESS,
);
const server = buildApp({
  repository,
  authenticate,
  resolveDeviceContext,
}).listen(config.PORT, () => {
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-access-service", message: "listening", port: config.PORT })}\n`,
  );
});

const grpcServer = buildGrpcServer({
  repository,
  authenticate,
  resolveDeviceContext,
});
grpcServer.bindAsync(
  `0.0.0.0:${config.GRPC_PORT}`,
  grpc.ServerCredentials.createInsecure(),
  (error, port) => {
    if (error) throw error;
    process.stdout.write(
      `${JSON.stringify({ level: "info", service: "algaguard-access-service", message: "grpc listening", port })}\n`,
    );
  },
);

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-access-service", message: "shutdown", signal })}\n`,
  );
  const deadline = setTimeout(() => process.exit(1), 10_000);
  deadline.unref();
  grpcServer.tryShutdown(() => {});
  server.close(async (error) => {
    try {
      await repository.close();
      clearTimeout(deadline);
      process.exit(error ? 1 : 0);
    } catch {
      process.exit(1);
    }
  });
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
