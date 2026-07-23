import assert from "node:assert/strict";
import test from "node:test";
import { DomainError, MemoryAccessRepository } from "../src/domain.js";

async function fixture() {
  const repository = new MemoryAccessRepository();
  const organization = await repository.createOrganization("Lab", "owner");
  return { repository, organization };
}

test("duplicate membership is prevented and an invitation is one-use", async () => {
  const { repository, organization } = await fixture();
  const { token } = await repository.createInvitation({
    organizationId: organization.id,
    email: "member@example.test",
    role: "OPERATOR",
    invitedBy: "owner",
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal(
    (await repository.acceptInvitation(token, "member", "member@example.test"))
      .role,
    "OPERATOR",
  );
  await assert.rejects(
    repository.acceptInvitation(token, "other", "member@example.test"),
    (error: unknown) =>
      error instanceof DomainError && error.code === "INVITATION_USED",
  );
});

test("expired invitations are rejected", async () => {
  const { repository, organization } = await fixture();
  const { token } = await repository.createInvitation({
    organizationId: organization.id,
    email: "member@example.test",
    role: "VIEWER",
    invitedBy: "owner",
    expiresAt: new Date(Date.now() - 1),
  });
  await assert.rejects(
    repository.acceptInvitation(token, "member", "member@example.test"),
    (error: unknown) =>
      error instanceof DomainError && error.code === "INVITATION_EXPIRED",
  );
});

test("ownership transfer is atomic and last-owner protection is enforced", async () => {
  const { repository, organization } = await fixture();
  const { token } = await repository.createInvitation({
    organizationId: organization.id,
    email: "admin@example.test",
    role: "ADMIN",
    invitedBy: "owner",
    expiresAt: new Date(Date.now() + 60_000),
  });
  await repository.acceptInvitation(token, "admin", "admin@example.test");
  assert.equal(
    (await repository.changeRole(organization.id, "admin", "OPERATOR")).role,
    "OPERATOR",
  );
  await repository.changeRole(organization.id, "admin", "ADMIN");
  await assert.rejects(
    repository.changeRole(organization.id, "owner", "VIEWER"),
    (error: unknown) =>
      error instanceof DomainError && error.code === "LAST_OWNER",
  );
  const transfer = await repository.transferOwnership(
    organization.id,
    "owner",
    "admin",
  );
  assert.equal(transfer.previousOwner.role, "ADMIN");
  assert.equal(transfer.owner.role, "OWNER");
});

test("resource decisions enforce tenant, role, and revocation", async () => {
  const { repository, organization } = await fixture();
  const other = await repository.createOrganization("Other", "other-owner");
  await repository.registerResource("device", "AG-000001", organization.id);
  assert.equal(
    (
      await repository.decide({
        subjectId: "owner",
        action: "device.manage",
        resourceType: "device",
        resourceId: "AG-000001",
        organizationId: organization.id,
      })
    ).allowed,
    true,
  );
  assert.equal(
    (
      await repository.decide({
        subjectId: "owner",
        action: "device.read",
        resourceType: "device",
        resourceId: "AG-000001",
        organizationId: other.id,
      })
    ).reason,
    "RESOURCE_MISMATCH",
  );
  const invitation = await repository.createInvitation({
    organizationId: organization.id,
    email: "viewer@example.test",
    role: "VIEWER",
    invitedBy: "owner",
    expiresAt: new Date(Date.now() + 60_000),
  });
  await repository.acceptInvitation(
    invitation.token,
    "viewer",
    "viewer@example.test",
  );
  assert.equal(
    (
      await repository.decide({
        subjectId: "viewer",
        action: "subscription.read",
        resourceType: "device",
        resourceId: "AG-000001",
      })
    ).allowed,
    true,
  );
  await repository.revokeMembership(organization.id, "viewer");
  assert.equal(
    (
      await repository.decide({
        subjectId: "viewer",
        action: "subscription.read",
        resourceType: "device",
        resourceId: "AG-000001",
      })
    ).reason,
    "NO_MEMBERSHIP",
  );
});
