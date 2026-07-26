import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createAuthenticator } from "../src/auth.js";

test("validates a public issuer token using a separately configured private JWKS endpoint", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "development-key";
  let jwksRequests = 0;
  const server = http.createServer((_request, response) => {
    jwksRequests += 1;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: [jwk] }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Test server did not expose a port");

  const issuer = "https://dev.algaguard.example/auth/realms/algaguard";
  const token = await new SignJWT({ email: "demo@algaguard.local" })
    .setProtectedHeader({ alg: "RS256", kid: "development-key" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .setIssuer(issuer)
    .setAudience("algaguard-api")
    .setSubject("demo-user")
    .sign(privateKey);
  try {
    const authenticate = createAuthenticator({
      KEYCLOAK_ISSUER: issuer,
      KEYCLOAK_AUDIENCE: "algaguard-api",
      KEYCLOAK_JWKS_URL: `http://127.0.0.1:${address.port}/internal/certs`,
    });
    assert.deepEqual(await authenticate(`Bearer ${token}`), {
      subjectId: "demo-user",
      email: "demo@algaguard.local",
      service: false,
    });
    assert.equal(jwksRequests, 1);
  } finally {
    server.close();
    await once(server, "close");
  }
});
