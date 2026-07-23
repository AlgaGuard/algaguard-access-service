import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import { DomainError } from "../src/domain.js";
import { PostgresAccessRepository } from "../src/repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

test(
  "PostgreSQL state survives repository restart and invitation consumption is atomic",
  { skip: !databaseUrl },
  async () => {
    const cleanup = new pg.Pool({ connectionString: databaseUrl });
    await cleanup.query(
      "TRUNCATE resource_ownership, invitations, memberships, organizations CASCADE",
    );
    await cleanup.end();

    const first = new PostgresAccessRepository(
      new pg.Pool({ connectionString: databaseUrl }),
    );
    const organization = await first.createOrganization(
      "Persistent Lab",
      "owner",
    );
    const created = await first.createInvitation({
      organizationId: organization.id,
      email: "member@example.test",
      role: "OPERATOR",
      invitedBy: "owner",
      expiresAt: new Date(Date.now() + 60_000),
    });
    const outcomes = await Promise.allSettled([
      first.acceptInvitation(created.token, "member", "member@example.test"),
      first.acceptInvitation(created.token, "other", "member@example.test"),
    ]);
    assert.equal(
      outcomes.filter((value) => value.status === "fulfilled").length,
      1,
    );
    assert.equal(
      outcomes.filter((value) => value.status === "rejected").length,
      1,
    );
    await first.close();

    const restarted = new PostgresAccessRepository(
      new pg.Pool({ connectionString: databaseUrl }),
    );
    assert.equal(
      (await restarted.organizationsFor("owner"))[0]?.id,
      organization.id,
    );
    await assert.rejects(
      restarted.acceptInvitation(created.token, "third", "member@example.test"),
      (error: unknown) =>
        error instanceof DomainError && error.code === "INVITATION_USED",
    );
    await restarted.close();
  },
);
