import psycopg
from psycopg.rows import dict_row
from .config import load_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_objects (
  id UUID PRIMARY KEY,
  compartment TEXT NOT NULL,
  classification TEXT NOT NULL,
  name TEXT NOT NULL,
  envelope JSONB NOT NULL,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
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
CREATE INDEX IF NOT EXISTS ix_vault_objects_compartment ON vault_objects(compartment);
CREATE INDEX IF NOT EXISTS ix_vault_audit_created_at ON vault_audit(created_at DESC);
CREATE TABLE IF NOT EXISTS vault_scif_sessions (
  id UUID PRIMARY KEY,
  object_id UUID NOT NULL REFERENCES vault_objects(id) ON DELETE CASCADE,
  owner TEXT NOT NULL,
  mode TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  approvals_required INTEGER NOT NULL DEFAULT 0,
  approved_by JSONB NOT NULL DEFAULT '[]'::jsonb,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  opened_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  auth_envelope JSONB,
  last_verified_at TIMESTAMPTZ,
  revoked_reason TEXT,
  device_binding_hash TEXT,
  device_claim TEXT
);
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
