ALTER TABLE memberships
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE invitations
  ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'VIEWER',
  ADD COLUMN IF NOT EXISTS invited_by text NOT NULL DEFAULT 'migration:unknown',
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'invitations_role_check'
  ) THEN
    ALTER TABLE invitations
      ADD CONSTRAINT invitations_role_check CHECK (role IN ('ADMIN','OPERATOR','VIEWER'));
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS memberships_subject_active
  ON memberships(subject_id, organization_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS invitations_expiry
  ON invitations(expires_at)
  WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS resource_ownership (
  resource_type text NOT NULL CHECK (resource_type IN ('device','profile','command','ota')),
  resource_id text NOT NULL,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS resource_ownership_organization
  ON resource_ownership(organization_id, resource_type);
