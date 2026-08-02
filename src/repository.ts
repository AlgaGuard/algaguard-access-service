import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import {
  DomainError,
  invitationDigest,
  rolesForAction,
  type AccessRepository,
  type AuthorizationDecision,
  type Invitation,
  type Membership,
  type Organization,
  type ResourceType,
  type Role,
} from "./domain.js";

function iso(value: Date | string) {
  return value instanceof Date
    ? value.toISOString()
    : new Date(value).toISOString();
}

function organization(row: Record<string, unknown>): Organization {
  return {
    id: String(row.id),
    name: String(row.name),
    createdAt: iso(row.created_at as Date),
  };
}

function membership(row: Record<string, unknown>): Membership {
  return {
    organizationId: String(row.organization_id),
    subjectId: String(row.subject_id),
    role: row.role as Role,
    ...(row.revoked_at ? { revokedAt: iso(row.revoked_at as Date) } : {}),
  };
}

function invitation(row: Record<string, unknown>): Invitation {
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    email: String(row.email),
    role: row.role as Invitation["role"],
    expiresAt: iso(row.expires_at as Date),
    ...(row.consumed_at ? { consumedAt: iso(row.consumed_at as Date) } : {}),
    ...(row.rejected_at ? { rejectedAt: iso(row.rejected_at as Date) } : {}),
    ...(row.organization_name
      ? { organizationName: String(row.organization_name) }
      : {}),
  };
}

export class PostgresAccessRepository implements AccessRepository {
  constructor(readonly pool: pg.Pool) {}

  async createOrganization(name: string, ownerSubjectId: string) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const id = randomUUID();
      const created = await client.query(
        "INSERT INTO organizations (id, name) VALUES ($1, $2) RETURNING *",
        [id, name],
      );
      await client.query(
        "INSERT INTO memberships (organization_id, subject_id, role) VALUES ($1, $2, 'OWNER')",
        [id, ownerSubjectId],
      );
      await client.query("COMMIT");
      return organization(created.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async organizationsFor(subjectId: string) {
    const result = await this.pool.query(
      `SELECT o.* FROM organizations o
         JOIN memberships m ON m.organization_id = o.id
        WHERE m.subject_id = $1 AND m.revoked_at IS NULL
        ORDER BY o.name, o.id`,
      [subjectId],
    );
    return result.rows.map((row) =>
      organization(row as Record<string, unknown>),
    );
  }

  async membership(organizationId: string, subjectId: string) {
    const result = await this.pool.query(
      `SELECT * FROM memberships
        WHERE organization_id = $1 AND subject_id = $2 AND revoked_at IS NULL`,
      [organizationId, subjectId],
    );
    return result.rows[0]
      ? membership(result.rows[0] as Record<string, unknown>)
      : undefined;
  }

  async createInvitation(input: {
    organizationId: string;
    email: string;
    role: Exclude<Role, "OWNER">;
    invitedBy: string;
    expiresAt: Date;
  }) {
    const token = randomBytes(32).toString("base64url");
    try {
      const result = await this.pool.query(
        `INSERT INTO invitations
           (id, organization_id, email, token_hash, role, expires_at, invited_by)
         VALUES ($1, $2, lower($3), $4, $5, $6, $7)
         RETURNING *`,
        [
          randomUUID(),
          input.organizationId,
          input.email,
          invitationDigest(token),
          input.role,
          input.expiresAt,
          input.invitedBy,
        ],
      );
      return {
        invitation: invitation(result.rows[0] as Record<string, unknown>),
        token,
      };
    } catch (error) {
      if ((error as { code?: string }).code === "23503")
        throw new DomainError(
          "ORGANIZATION_NOT_FOUND",
          404,
          "Organization not found",
        );
      throw error;
    }
  }

  async acceptInvitation(token: string, subjectId: string, email: string) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT * FROM invitations WHERE token_hash = $1 FOR UPDATE",
        [invitationDigest(token)],
      );
      const row = found.rows[0] as Record<string, unknown> | undefined;
      if (!row || row.consumed_at || row.rejected_at)
        throw new DomainError(
          "INVITATION_USED",
          410,
          "Invitation is unavailable",
        );
      if (new Date(row.expires_at as string | Date).getTime() <= Date.now())
        throw new DomainError("INVITATION_EXPIRED", 410, "Invitation expired");
      if (String(row.email).toLowerCase() !== email.toLowerCase())
        throw new DomainError(
          "INVITATION_EMAIL_MISMATCH",
          403,
          "Invitation email does not match",
        );
      const duplicate = await client.query(
        `SELECT 1 FROM memberships
          WHERE organization_id = $1 AND subject_id = $2 AND revoked_at IS NULL`,
        [row.organization_id, subjectId],
      );
      if (duplicate.rowCount)
        throw new DomainError(
          "DUPLICATE_MEMBERSHIP",
          409,
          "Membership already exists",
        );
      const added = await client.query(
        `INSERT INTO memberships (organization_id, subject_id, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (organization_id, subject_id) DO UPDATE
           SET role = EXCLUDED.role, revoked_at = NULL, updated_at = now()
         RETURNING *`,
        [row.organization_id, subjectId, row.role],
      );
      await client.query(
        "UPDATE invitations SET consumed_at = now() WHERE id = $1",
        [row.id],
      );
      await client.query("COMMIT");
      return membership(added.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async pendingInvitations(email: string) {
    const result = await this.pool.query(
      `SELECT i.*, o.name AS organization_name
         FROM invitations i
         JOIN organizations o ON o.id = i.organization_id
        WHERE i.email = lower($1) AND i.consumed_at IS NULL
          AND i.rejected_at IS NULL AND i.expires_at > now()
        ORDER BY i.expires_at`,
      [email],
    );
    return result.rows.map((row) => invitation(row as Record<string, unknown>));
  }

  async acceptInvitationById(
    invitationId: string,
    subjectId: string,
    email: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT * FROM invitations WHERE id=$1 FOR UPDATE",
        [invitationId],
      );
      const row = found.rows[0] as Record<string, unknown> | undefined;
      if (
        !row ||
        row.consumed_at ||
        row.rejected_at ||
        String(row.email).toLowerCase() !== email.toLowerCase() ||
        new Date(row.expires_at as string | Date).getTime() <= Date.now()
      ) {
        throw new DomainError(
          "INVITATION_UNAVAILABLE",
          410,
          "Invitation unavailable",
        );
      }
      const duplicate = await client.query(
        `SELECT 1 FROM memberships WHERE organization_id=$1 AND subject_id=$2
          AND revoked_at IS NULL`,
        [row.organization_id, subjectId],
      );
      if (duplicate.rowCount) {
        throw new DomainError(
          "DUPLICATE_MEMBERSHIP",
          409,
          "Membership already exists",
        );
      }
      const added = await client.query(
        `INSERT INTO memberships (organization_id, subject_id, role)
         VALUES ($1,$2,$3)
         ON CONFLICT (organization_id, subject_id) DO UPDATE
           SET role=EXCLUDED.role, revoked_at=NULL, updated_at=now()
         RETURNING *`,
        [row.organization_id, subjectId, row.role],
      );
      await client.query(
        "UPDATE invitations SET consumed_at=now() WHERE id=$1",
        [invitationId],
      );
      await client.query("COMMIT");
      return membership(added.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async rejectInvitation(invitationId: string, email: string) {
    const result = await this.pool.query(
      `UPDATE invitations SET rejected_at=now()
        WHERE id=$1 AND email=lower($2) AND consumed_at IS NULL
          AND rejected_at IS NULL AND expires_at > now()`,
      [invitationId, email],
    );
    if (!result.rowCount) {
      throw new DomainError(
        "INVITATION_UNAVAILABLE",
        410,
        "Invitation unavailable",
      );
    }
  }

  async changeRole(organizationId: string, subjectId: string, role: Role) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(
        `SELECT * FROM memberships
          WHERE organization_id = $1 AND subject_id = $2 AND revoked_at IS NULL
          FOR UPDATE`,
        [organizationId, subjectId],
      );
      const row = current.rows[0] as Record<string, unknown> | undefined;
      if (!row)
        throw new DomainError(
          "MEMBERSHIP_NOT_FOUND",
          404,
          "Membership not found",
        );
      if (row.role === "OWNER" && role !== "OWNER") {
        const owners = await client.query(
          `SELECT subject_id FROM memberships
            WHERE organization_id = $1 AND role = 'OWNER' AND revoked_at IS NULL
            FOR UPDATE`,
          [organizationId],
        );
        if (owners.rowCount === 1)
          throw new DomainError(
            "LAST_OWNER",
            409,
            "The last owner cannot be demoted",
          );
      }
      const changed = await client.query(
        `UPDATE memberships SET role = $3, updated_at = now()
          WHERE organization_id = $1 AND subject_id = $2 RETURNING *`,
        [organizationId, subjectId, role],
      );
      await client.query("COMMIT");
      return membership(changed.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async transferOwnership(
    organizationId: string,
    currentOwnerSubjectId: string,
    nextOwnerSubjectId: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(
        `SELECT * FROM memberships
          WHERE organization_id = $1 AND subject_id = ANY($2::text[]) AND revoked_at IS NULL
          FOR UPDATE`,
        [organizationId, [currentOwnerSubjectId, nextOwnerSubjectId]],
      );
      const current = locked.rows.find(
        (row) => row.subject_id === currentOwnerSubjectId,
      );
      const next = locked.rows.find(
        (row) => row.subject_id === nextOwnerSubjectId,
      );
      if (!current || current.role !== "OWNER")
        throw new DomainError(
          "OWNER_REQUIRED",
          403,
          "Current subject is not an owner",
        );
      if (!next)
        throw new DomainError(
          "MEMBERSHIP_NOT_FOUND",
          404,
          "Next owner must be an active member",
        );
      const changed = await client.query(
        `UPDATE memberships
            SET role = CASE
                         WHEN subject_id = $2 THEN 'ADMIN'
                         WHEN subject_id = $3 THEN 'OWNER'
                         ELSE role
                       END,
                updated_at = now()
          WHERE organization_id = $1 AND subject_id = ANY($4::text[])
          RETURNING *`,
        [
          organizationId,
          currentOwnerSubjectId,
          nextOwnerSubjectId,
          [currentOwnerSubjectId, nextOwnerSubjectId],
        ],
      );
      await client.query("COMMIT");
      return {
        previousOwner: membership(
          changed.rows.find(
            (row) => row.subject_id === currentOwnerSubjectId,
          ) as Record<string, unknown>,
        ),
        owner: membership(
          changed.rows.find(
            (row) => row.subject_id === nextOwnerSubjectId,
          ) as Record<string, unknown>,
        ),
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async revokeMembership(organizationId: string, subjectId: string) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(
        `SELECT * FROM memberships
          WHERE organization_id = $1 AND subject_id = $2 AND revoked_at IS NULL
          FOR UPDATE`,
        [organizationId, subjectId],
      );
      const row = current.rows[0] as Record<string, unknown> | undefined;
      if (!row) {
        await client.query("COMMIT");
        return;
      }
      if (row.role === "OWNER") {
        const owners = await client.query(
          `SELECT subject_id FROM memberships
            WHERE organization_id = $1 AND role = 'OWNER' AND revoked_at IS NULL
            FOR UPDATE`,
          [organizationId],
        );
        if (owners.rowCount === 1)
          throw new DomainError(
            "LAST_OWNER",
            409,
            "The last owner cannot be revoked",
          );
      }
      await client.query(
        `UPDATE memberships SET revoked_at = now(), updated_at = now()
          WHERE organization_id = $1 AND subject_id = $2`,
        [organizationId, subjectId],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async registerResource(
    resourceType: Exclude<ResourceType, "organization" | "current-user">,
    resourceId: string,
    organizationId: string,
  ) {
    try {
      await this.pool.query(
        `INSERT INTO resource_ownership (resource_type, resource_id, organization_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (resource_type, resource_id) DO UPDATE
           SET organization_id = EXCLUDED.organization_id, updated_at = now()`,
        [resourceType, resourceId, organizationId],
      );
    } catch (error) {
      if ((error as { code?: string }).code === "23503")
        throw new DomainError(
          "ORGANIZATION_NOT_FOUND",
          404,
          "Organization not found",
        );
      throw error;
    }
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
    let organizationId = input.organizationId;
    if (input.resourceType === "organization")
      organizationId = input.resourceId ?? organizationId;
    else if (input.resourceId) {
      const owner = await this.pool.query(
        `SELECT organization_id FROM resource_ownership
          WHERE resource_type = $1 AND resource_id = $2`,
        [input.resourceType, input.resourceId],
      );
      const resourceOrganization = owner.rows[0]?.organization_id as
        string | undefined;
      if (
        !resourceOrganization ||
        (organizationId && organizationId !== resourceOrganization)
      )
        return { allowed: false, reason: "RESOURCE_MISMATCH" };
      organizationId = resourceOrganization;
    }
    if (!organizationId) return { allowed: false, reason: "RESOURCE_MISMATCH" };
    const active = await this.membership(organizationId, input.subjectId);
    if (!active)
      return { allowed: false, reason: "NO_MEMBERSHIP", organizationId };
    if (!rolesForAction(input.action).includes(active.role))
      return {
        allowed: false,
        reason: "INSUFFICIENT_ROLE",
        organizationId,
        role: active.role,
      };
    return {
      allowed: true,
      reason: "ALLOWED",
      organizationId,
      role: active.role,
    };
  }

  async health() {
    await this.pool.query("SELECT 1");
  }

  async close() {
    await this.pool.end();
  }
}
