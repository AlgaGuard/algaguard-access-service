import { randomUUID } from "node:crypto";
export type Role = "OWNER" | "ADMIN" | "OPERATOR" | "VIEWER";
export interface Membership {
  organizationId: string;
  subjectId: string;
  role: Role;
}
export class AccessStore {
  readonly organizations = new Map<string, { id: string; name: string }>();
  readonly memberships: Membership[] = [];
  readonly invitations = new Map<
    string,
    { organizationId: string; email: string; expiresAt: number; used: boolean }
  >();
  createOrganization(name: string, ownerSubjectId: string) {
    const organization = { id: randomUUID(), name };
    this.organizations.set(organization.id, organization);
    this.memberships.push({
      organizationId: organization.id,
      subjectId: ownerSubjectId,
      role: "OWNER",
    });
    return organization;
  }
  addMembership(organizationId: string, subjectId: string, role: Role) {
    const existing = this.memberships.find(
      (value) =>
        value.organizationId === organizationId &&
        value.subjectId === subjectId,
    );
    if (existing) existing.role = role;
    else this.memberships.push({ organizationId, subjectId, role });
    return this.memberships.find(
      (value) =>
        value.organizationId === organizationId &&
        value.subjectId === subjectId,
    )!;
  }
  invite(organizationId: string, email: string, ttlMs: number) {
    const token = randomUUID();
    this.invitations.set(token, {
      organizationId,
      email,
      expiresAt: Date.now() + ttlMs,
      used: false,
    });
    return token;
  }
  authorize(
    subjectId: string,
    organizationId: string,
    roles: Role[] = ["OWNER", "ADMIN", "OPERATOR", "VIEWER"],
  ) {
    return this.memberships.some(
      (membership) =>
        membership.subjectId === subjectId &&
        membership.organizationId === organizationId &&
        roles.includes(membership.role),
    );
  }
  authorizeSubscription(
    subjectId: string,
    resourceType: "organization" | "device" | "current-user",
    resourceId?: string,
  ) {
    if (resourceType === "current-user") return true;
    if (!resourceId) return false;
    return this.authorize(subjectId, resourceId);
  }
  organizationsFor(subjectId?: string) {
    if (!subjectId) return [...this.organizations.values()];
    const ids = new Set(
      this.memberships
        .filter((membership) => membership.subjectId === subjectId)
        .map((membership) => membership.organizationId),
    );
    return [...this.organizations.values()].filter((value) =>
      ids.has(value.id),
    );
  }
}
