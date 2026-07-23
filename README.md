# algaguard-access-service

Durable multi-tenant organization, membership, invitation, resource-ownership, and authorization service.

PostgreSQL is the runtime source of truth. `MemoryAccessRepository` is an explicitly injected test adapter and is never selected by production startup. Human and service callers present Keycloak bearer tokens; internal decisions require an allowlisted service client identity rather than trusted subject headers.

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
