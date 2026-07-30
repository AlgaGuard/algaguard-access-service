import { createHash, randomBytes, randomUUID } from "node:crypto";

export type Role = "OWNER" | "ADMIN" | "OPERATOR" | "VIEWER";
export type ResourceType =
  "organization" | "device" | "profile" | "command" | "ota" | "current-user";

export interface Organization {
  id: string;
  name: string;
  createdAt: string;
}

export interface Membership {
  organizationId: string;
  subjectId: string;
  role: Role;
  revokedAt?: string;
}

export interface Invitation {
  id: string;
  organizationId: string;
  email: string;
  role: Exclude<Role, "OWNER">;
  expiresAt: string;
  consumedAt?: string;
}

export interface AuthorizationDecision {
  allowed: boolean;
  reason:
    "ALLOWED" | "NO_MEMBERSHIP" | "INSUFFICIENT_ROLE" | "RESOURCE_MISMATCH";
  organizationId?: string;
  role?: Role;
  decidedAt?: string;
  ttlSeconds?: number;
  ownershipVersion?: string;
}

export class DomainError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function invitationDigest(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export function rolesForAction(action: string): Role[] {
  if (["organization.transfer", "organization.delete"].includes(action))
    return ["OWNER"];
  if (
    [
      "access.manage",
      "device.claim",
      "device.manage",
      "device.bootstrap.reissue",
      "device.physical-session-handoff.approve",
      "device.credentials.bootstrap",
      "device.credentials.rotate",
      "device.credentials.recover",
      "device.credentials.revoke",
      "device.credentials.compromise",
      "profile.manage",
      "ota.manage",
    ].includes(action)
  )
    return ["OWNER", "ADMIN"];
  if (["command.create", "profile.assign", "device.operate"].includes(action))
    return ["OWNER", "ADMIN", "OPERATOR"];
  return ["OWNER", "ADMIN", "OPERATOR", "VIEWER"];
}

export interface AccessRepository {
  createOrganization(
    name: string,
    ownerSubjectId: string,
  ): Promise<Organization>;
  organizationsFor(subjectId: string): Promise<Organization[]>;
  membership(
    organizationId: string,
    subjectId: string,
  ): Promise<Membership | undefined>;
  createInvitation(input: {
    organizationId: string;
    email: string;
    role: Exclude<Role, "OWNER">;
    invitedBy: string;
    expiresAt: Date;
  }): Promise<{ invitation: Invitation; token: string }>;
  acceptInvitation(
    token: string,
    subjectId: string,
    email: string,
  ): Promise<Membership>;
  changeRole(
    organizationId: string,
    subjectId: string,
    role: Role,
  ): Promise<Membership>;
  transferOwnership(
    organizationId: string,
    currentOwnerSubjectId: string,
    nextOwnerSubjectId: string,
  ): Promise<{ previousOwner: Membership; owner: Membership }>;
  revokeMembership(organizationId: string, subjectId: string): Promise<void>;
  registerResource(
    resourceType: Exclude<ResourceType, "organization" | "current-user">,
    resourceId: string,
    organizationId: string,
  ): Promise<void>;
  decide(input: {
    subjectId: string;
    action: string;
    resourceType: ResourceType;
    resourceId?: string;
    organizationId?: string;
  }): Promise<AuthorizationDecision>;
  health(): Promise<void>;
  close(): Promise<void>;
}

interface StoredInvitation extends Invitation {
  digest: string;
}

export class MemoryAccessRepository implements AccessRepository {
  private readonly organizations = new Map<string, Organization>();
  private readonly memberships = new Map<string, Membership>();
  private readonly invitations = new Map<string, StoredInvitation>();
  private readonly resources = new Map<string, string>();

  private membershipKey(organizationId: string, subjectId: string) {
    return `${organizationId}:${subjectId}`;
  }

  async createOrganization(name: string, ownerSubjectId: string) {
    const organization = {
      id: randomUUID(),
      name,
      createdAt: new Date().toISOString(),
    };
    this.organizations.set(organization.id, organization);
    this.memberships.set(this.membershipKey(organization.id, ownerSubjectId), {
      organizationId: organization.id,
      subjectId: ownerSubjectId,
      role: "OWNER",
    });
    return organization;
  }

  async organizationsFor(subjectId: string) {
    const ids = new Set(
      [...this.memberships.values()]
        .filter((value) => value.subjectId === subjectId && !value.revokedAt)
        .map((value) => value.organizationId),
    );
    return [...this.organizations.values()].filter((value) =>
      ids.has(value.id),
    );
  }

  async membership(organizationId: string, subjectId: string) {
    const value = this.memberships.get(
      this.membershipKey(organizationId, subjectId),
    );
    return value && !value.revokedAt ? structuredClone(value) : undefined;
  }

  async createInvitation(input: {
    organizationId: string;
    email: string;
    role: Exclude<Role, "OWNER">;
    invitedBy: string;
    expiresAt: Date;
  }) {
    if (!this.organizations.has(input.organizationId))
      throw new DomainError(
        "ORGANIZATION_NOT_FOUND",
        404,
        "Organization not found",
      );
    const token = randomBytes(32).toString("base64url");
    const invitation: StoredInvitation = {
      id: randomUUID(),
      organizationId: input.organizationId,
      email: input.email.toLowerCase(),
      role: input.role,
      expiresAt: input.expiresAt.toISOString(),
      digest: invitationDigest(token),
    };
    this.invitations.set(invitation.id, invitation);
    return { invitation: structuredClone(invitation), token };
  }

  async acceptInvitation(token: string, subjectId: string, email: string) {
    const digest = invitationDigest(token);
    const invitation = [...this.invitations.values()].find(
      (value) => value.digest === digest,
    );
    if (!invitation || invitation.consumedAt)
      throw new DomainError(
        "INVITATION_USED",
        410,
        "Invitation is unavailable",
      );
    if (Date.parse(invitation.expiresAt) <= Date.now())
      throw new DomainError("INVITATION_EXPIRED", 410, "Invitation expired");
    if (invitation.email !== email.toLowerCase())
      throw new DomainError(
        "INVITATION_EMAIL_MISMATCH",
        403,
        "Invitation email does not match",
      );
    const key = this.membershipKey(invitation.organizationId, subjectId);
    if (this.memberships.has(key) && !this.memberships.get(key)?.revokedAt)
      throw new DomainError(
        "DUPLICATE_MEMBERSHIP",
        409,
        "Membership already exists",
      );
    invitation.consumedAt = new Date().toISOString();
    const membership: Membership = {
      organizationId: invitation.organizationId,
      subjectId,
      role: invitation.role,
    };
    this.memberships.set(key, membership);
    return structuredClone(membership);
  }

  async changeRole(organizationId: string, subjectId: string, role: Role) {
    const key = this.membershipKey(organizationId, subjectId);
    const membership = this.memberships.get(key);
    if (!membership || membership.revokedAt)
      throw new DomainError(
        "MEMBERSHIP_NOT_FOUND",
        404,
        "Membership not found",
      );
    if (
      membership.role === "OWNER" &&
      role !== "OWNER" &&
      this.activeOwnerCount(organizationId) === 1
    )
      throw new DomainError(
        "LAST_OWNER",
        409,
        "The last owner cannot be demoted",
      );
    membership.role = role;
    return structuredClone(membership);
  }

  async transferOwnership(
    organizationId: string,
    currentOwnerSubjectId: string,
    nextOwnerSubjectId: string,
  ) {
    const current = this.memberships.get(
      this.membershipKey(organizationId, currentOwnerSubjectId),
    );
    const next = this.memberships.get(
      this.membershipKey(organizationId, nextOwnerSubjectId),
    );
    if (!current || current.revokedAt || current.role !== "OWNER")
      throw new DomainError(
        "OWNER_REQUIRED",
        403,
        "Current subject is not an owner",
      );
    if (!next || next.revokedAt)
      throw new DomainError(
        "MEMBERSHIP_NOT_FOUND",
        404,
        "Next owner must be an active member",
      );
    current.role = "ADMIN";
    next.role = "OWNER";
    return {
      previousOwner: structuredClone(current),
      owner: structuredClone(next),
    };
  }

  async revokeMembership(organizationId: string, subjectId: string) {
    const membership = this.memberships.get(
      this.membershipKey(organizationId, subjectId),
    );
    if (!membership || membership.revokedAt) return;
    if (
      membership.role === "OWNER" &&
      this.activeOwnerCount(organizationId) === 1
    )
      throw new DomainError(
        "LAST_OWNER",
        409,
        "The last owner cannot be revoked",
      );
    membership.revokedAt = new Date().toISOString();
  }

  async registerResource(
    resourceType: Exclude<ResourceType, "organization" | "current-user">,
    resourceId: string,
    organizationId: string,
  ) {
    if (!this.organizations.has(organizationId))
      throw new DomainError(
        "ORGANIZATION_NOT_FOUND",
        404,
        "Organization not found",
      );
    this.resources.set(`${resourceType}:${resourceId}`, organizationId);
  }

  async decide(input: {
    subjectId: string;
    action: string;
    resourceType: ResourceType;
    resourceId?: string;
    organizationId?: string;
  }): Promise<AuthorizationDecision> {
    if (input.resourceType === "current-user")
      return input.resourceId === undefined ||
        input.resourceId === input.subjectId
        ? { allowed: true, reason: "ALLOWED" }
        : { allowed: false, reason: "RESOURCE_MISMATCH" };
    const organizationId =
      input.resourceType === "organization"
        ? (input.resourceId ?? input.organizationId)
        : input.resourceId
          ? this.resources.get(`${input.resourceType}:${input.resourceId}`)
          : input.organizationId;
    if (
      !organizationId ||
      (input.organizationId && input.organizationId !== organizationId)
    )
      return { allowed: false, reason: "RESOURCE_MISMATCH" };
    const membership = await this.membership(organizationId, input.subjectId);
    if (!membership)
      return { allowed: false, reason: "NO_MEMBERSHIP", organizationId };
    if (!rolesForAction(input.action).includes(membership.role))
      return {
        allowed: false,
        reason: "INSUFFICIENT_ROLE",
        organizationId,
        role: membership.role,
      };
    return {
      allowed: true,
      reason: "ALLOWED",
      organizationId,
      role: membership.role,
    };
  }

  private activeOwnerCount(organizationId: string) {
    return [...this.memberships.values()].filter(
      (value) =>
        value.organizationId === organizationId &&
        value.role === "OWNER" &&
        !value.revokedAt,
    ).length;
  }

  async health() {}
  async close() {}
}
