import psycopg
from psycopg.rows import dict_row
from .config import load_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_objects (
  id UUID PRIMARY KEY,
  compartment TEXT NOT NULL,
  classification TEXT NOT NULL,
  protection_profile TEXT,
  name TEXT NOT NULL,
  envelope JSONB NOT NULL,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  military_branch TEXT,
  tracking_number TEXT,
  operation_location TEXT,
  deleted_at TIMESTAMPTZ,
  deleted_by TEXT,
  delete_tracking_number TEXT
);
CREATE TABLE IF NOT EXISTS vault_audit (
  seq BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_id TEXT,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS protection_profile TEXT;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS military_branch TEXT;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS tracking_number TEXT;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS operation_location TEXT;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS deleted_by TEXT;
ALTER TABLE vault_objects ADD COLUMN IF NOT EXISTS delete_tracking_number TEXT;
CREATE INDEX IF NOT EXISTS ix_vault_objects_compartment ON vault_objects(compartment);
CREATE UNIQUE INDEX IF NOT EXISTS ux_vault_objects_tracking ON vault_objects(tracking_number) WHERE tracking_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_vault_objects_military_branch ON vault_objects(military_branch) WHERE military_branch IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_vault_objects_deleted_at ON vault_objects(deleted_at);
CREATE INDEX IF NOT EXISTS ix_vault_audit_created_at ON vault_audit(created_at DESC);
CREATE TABLE IF NOT EXISTS military_release_requests (
  id UUID PRIMARY KEY,
  file_name TEXT NOT NULL,
  file_sha256 TEXT NOT NULL,
  military_branch TEXT NOT NULL,
  redaction_percentage INTEGER NOT NULL,
  reason TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  approved_by JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_military_release_status ON military_release_requests(status,created_at DESC);
CREATE INDEX IF NOT EXISTS ix_military_release_hash ON military_release_requests(file_sha256);
CREATE TABLE IF NOT EXISTS vault_scif_sessions (
  id UUID PRIMARY KEY,
  object_id UUID NOT NULL REFERENCES vault_objects(id) ON DELETE CASCADE,
  owner TEXT NOT NULL,
  mode TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  approvals_required INTEGER NOT NULL DEFAULT 0,
  approved_by JSONB NOT NULL DEFAULT '[]'::jsonb,
  approved_at JSONB NOT NULL DEFAULT '{}'::jsonb,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  opened_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  auth_envelope JSONB,
  last_verified_at TIMESTAMPTZ,
  revoked_reason TEXT,
  device_binding_hash TEXT,
  device_claim TEXT,
  cookie_hash TEXT,
  failed_entry_attempts INTEGER NOT NULL DEFAULT 0,
  failed_cookie_attempts INTEGER NOT NULL DEFAULT 0,
  device_public_jwk JSONB
);
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS approved_at JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS cookie_hash TEXT;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS failed_entry_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS failed_cookie_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS device_public_jwk JSONB;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS device_binding_hash TEXT;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS device_claim TEXT;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS auth_envelope JSONB;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE vault_scif_sessions ADD COLUMN IF NOT EXISTS revoked_reason TEXT;
CREATE INDEX IF NOT EXISTS ix_vault_scif_sessions_owner ON vault_scif_sessions(owner, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_vault_scif_sessions_expires ON vault_scif_sessions(expires_at);
"""

def connect():
    return psycopg.connect(load_settings().database_url, row_factory=dict_row)

def init_db():
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
