# algaguard-access-service

Durable multi-tenant organization, membership, invitation, resource-ownership, and authorization service.

PostgreSQL is the runtime source of truth. `MemoryAccessRepository` is an explicitly injected test adapter and is never selected by production startup. Human and service callers present Keycloak bearer tokens; internal decisions require an allowlisted service client identity rather than trusted subject headers. The default allowlist includes the telemetry service so HTTPS telemetry reads can obtain authoritative device-access decisions.

Device authorization uses the internal UUID resource, not the canonical MQTT identifier. Each device decision resolves current `deviceUuid`, `organizationId`, active status, and `ownershipVersion` through the authenticated Device Service API and verifies that context against the local resource registration. The service deliberately keeps no device-context authorization cache; transfer and revocation therefore affect the next decision without a stale-allow window. Decision responses include a timestamp and a maximum five-second consumer cache hint.

Credential metadata and audit viewing are available to active organization members. Bootstrap creation, rotation, recovery, revocation, and compromise marking require an `OWNER` or `ADMIN`. Every decision remains scoped to the authoritative current device organization; operators and viewers cannot mutate credential state, revoked memberships are denied, and ownership transfer takes effect on the next authenticated internal decision.

## Commands

```sh
npm ci
npm run migrate
npm run check
npm run test:integration
npm run dev
```

Migrations are explicit, checksum-guarded, serialized with a PostgreSQL advisory lock, and never reset data. Invitation tokens are returned only at creation, stored as SHA-256 digests, consumed transactionally, and redacted from logs. Ownership transfer and last-owner protection lock the affected membership rows.

The integration test requires `TEST_DATABASE_URL` (or `DATABASE_URL`) and proves that organizations and consumed invitations remain authoritative after constructing a new repository instance. No production deployment is claimed.
