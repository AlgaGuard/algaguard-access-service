ALTER TABLE invitations
  ADD COLUMN IF NOT EXISTS rejected_at timestamptz;

CREATE INDEX IF NOT EXISTS invitations_pending_email_idx
  ON invitations (email, expires_at)
  WHERE consumed_at IS NULL AND rejected_at IS NULL;
