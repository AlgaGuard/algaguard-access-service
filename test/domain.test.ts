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

test("credential operations use least-privilege roles and current membership", async () => {
  const { repository, organization } = await fixture();
  const deviceUuid = "20000000-0000-4000-8000-000000000001";
  await repository.registerResource("device", deviceUuid, organization.id);

  for (const [subjectId, email, role] of [
    ["admin", "admin@example.test", "ADMIN"],
    ["operator", "operator@example.test", "OPERATOR"],
    ["viewer", "viewer@example.test", "VIEWER"],
  ] as const) {
    const invitation = await repository.createInvitation({
      organizationId: organization.id,
      email,
      role,
      invitedBy: "owner",
      expiresAt: new Date(Date.now() + 60_000),
    });
    await repository.acceptInvitation(invitation.token, subjectId, email);
  }

  const decide = (subjectId: string, action: string) =>
    repository.decide({
      subjectId,
      action,
      resourceType: "device",
      resourceId: deviceUuid,
    });
  const readActions = ["device.credentials.view", "device.credentials.audit"];
  const administrativeActions = [
    "device.credentials.bootstrap",
    "device.credentials.rotate",
    "device.credentials.recover",
    "device.credentials.revoke",
    "device.credentials.compromise",
  ];

  for (const action of readActions)
    for (const subjectId of ["owner", "admin", "operator", "viewer"])
      assert.equal((await decide(subjectId, action)).allowed, true);
  for (const action of administrativeActions) {
    assert.equal((await decide("owner", action)).allowed, true);
    assert.equal((await decide("admin", action)).allowed, true);
    assert.equal(
      (await decide("operator", action)).reason,
      "INSUFFICIENT_ROLE",
    );
    assert.equal((await decide("viewer", action)).reason, "INSUFFICIENT_ROLE");
  }

  await repository.revokeMembership(organization.id, "admin");
  assert.equal(
    (await decide("admin", "device.credentials.revoke")).reason,
    "NO_MEMBERSHIP",
  );
});
