import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface Principal {
  subjectId: string;
  email?: string;
  clientId?: string;
  service: boolean;
}

export type Authenticator = (
  authorization: string | undefined,
) => Promise<Principal>;

export class AuthenticationError extends Error {}

export function configuredServiceClients(
  environment: NodeJS.ProcessEnv = process.env,
) {
  return new Set(
    (
      environment.SERVICE_CLIENT_IDS ??
      "algaguard-device-service,algaguard-profile-service,algaguard-command-service,algaguard-ota-service,algaguard-realtime-service,algaguard-telemetry-service"
    )
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
}

function principal(
  payload: JWTPayload,
  serviceClients: Set<string>,
): Principal {
  if (!payload.sub) throw new AuthenticationError("Token subject is required");
  const clientId =
    typeof payload.azp === "string"
      ? payload.azp
      : typeof payload.client_id === "string"
        ? payload.client_id
        : undefined;
  return {
    subjectId: payload.sub,
    ...(typeof payload.email === "string" ? { email: payload.email } : {}),
    ...(clientId ? { clientId } : {}),
    service: Boolean(clientId && serviceClients.has(clientId)),
  };
}

export function createAuthenticator(
  environment: NodeJS.ProcessEnv = process.env,
): Authenticator {
  const issuer =
    environment.KEYCLOAK_ISSUER ?? "http://keycloak:8080/realms/algaguard";
  const audience = environment.KEYCLOAK_AUDIENCE ?? "algaguard-api";
  const serviceClients = configuredServiceClients(environment);
  const jwks = createRemoteJWKSet(
    new URL(`${issuer}/protocol/openid-connect/certs`),
  );
  return async (authorization) => {
    const match = /^Bearer ([^ ]+)$/.exec(authorization ?? "");
    if (!match?.[1]) throw new AuthenticationError("Bearer token required");
    const verified = await jwtVerify(match[1], jwks, { issuer, audience });
    return principal(verified.payload, serviceClients);
  };
}
