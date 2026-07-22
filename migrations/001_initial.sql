CREATE TABLE organizations (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE memberships (organization_id uuid NOT NULL REFERENCES organizations(id), subject_id text NOT NULL, role text NOT NULL CHECK (role IN ('OWNER','ADMIN','OPERATOR','VIEWER')), PRIMARY KEY (organization_id, subject_id));
CREATE TABLE invitations (id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), email text NOT NULL, token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL, consumed_at timestamptz);

