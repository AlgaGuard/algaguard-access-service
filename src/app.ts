import { randomUUID } from "node:crypto";
import { trace } from "@opentelemetry/api";
import express, {
  type ErrorRequestHandler,
  type RequestHandler,
} from "express";
import pino from "pino";
import { ZodError } from "zod";
import { AuthenticationError, type Authenticator } from "./auth.js";
import { DomainError, type AccessRepository } from "./domain.js";
import type { DeviceContextResolver } from "./device-context.js";
import { createRouter } from "./routes.js";

const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: [
    "req.headers.authorization",
    "token",
    "invitationToken",
    "claimCode",
    "password",
  ],
});

const requestContext: RequestHandler = (request, response, next) => {
  const supplied = request.header("x-correlation-id");
  const correlationId =
    supplied && supplied.length <= 128 ? supplied : randomUUID();
  response.setHeader("x-correlation-id", correlationId);
  const span = trace
    .getTracer("algaguard-access-service")
    .startSpan(`${request.method} ${request.path}`);
  const startedAt = Date.now();
  response.on("finish", () => {
    logger.info(
      {
        correlationId,
        method: request.method,
        path: request.path,
        status: response.statusCode,
        durationMs: Date.now() - startedAt,
      },
      "request completed",
    );
    span.end();
  });
  next();
};

export function buildApp(dependencies: {
  repository: AccessRepository;
  authenticate?: Authenticator;
  resolveDeviceContext?: DeviceContextResolver;
}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "256kb" }));
  app.use(requestContext);
  app.get("/health/live", (_request, response) =>
    response.json({ status: "UP", service: "algaguard-access-service" }),
  );
  app.get("/health/ready", async (_request, response) => {
    try {
      await dependencies.repository.health();
      response.json({
        status: "READY",
        service: "algaguard-access-service",
        dependencies: { postgres: "UP" },
      });
    } catch {
      response.status(503).json({
        status: "NOT_READY",
        service: "algaguard-access-service",
        dependencies: { postgres: "DOWN" },
      });
    }
  });
  app.use("/v1", createRouter(dependencies));
  app.use((_request, response) =>
    response.status(404).type("application/problem+json").json({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      code: "NOT_FOUND",
    }),
  );
  const errors: ErrorRequestHandler = (error, _request, response, _next) => {
    const correlationId =
      response.getHeader("x-correlation-id")?.toString() ?? randomUUID();
    const status =
      error instanceof DomainError
        ? error.status
        : error instanceof AuthenticationError
          ? 401
          : error instanceof ZodError
            ? 400
            : 500;
    const code =
      error instanceof DomainError
        ? error.code
        : error instanceof AuthenticationError
          ? "UNAUTHENTICATED"
          : error instanceof ZodError
            ? "VALIDATION_ERROR"
            : "INTERNAL_ERROR";
    if (status >= 500)
      logger.error(
        {
          errorName: error instanceof Error ? error.name : "Unknown",
          correlationId,
        },
        "request failed",
      );
    response
      .status(status)
      .type("application/problem+json")
      .json({
        type: "about:blank",
        title:
          status === 500
            ? "Internal Server Error"
            : error instanceof Error
              ? error.message
              : "Request failed",
        status,
        code,
        correlationId,
      });
  };
  app.use(errors);
  return app;
}
