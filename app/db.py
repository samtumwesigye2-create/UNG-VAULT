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
CREATE TABLE IF NOT EXISTS vault_files (
  id UUID PRIMARY KEY,
  compartment TEXT NOT NULL,
  classification TEXT NOT NULL,
  name TEXT NOT NULL,
  content_type TEXT,
  storage_key TEXT NOT NULL UNIQUE,
  ciphertext_sha256 TEXT NOT NULL,
  plaintext_sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
  key_version INTEGER NOT NULL CHECK (key_version > 0),
  envelope JSONB NOT NULL,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vault_shares (
  id UUID PRIMARY KEY,
  file_id UUID NOT NULL REFERENCES vault_files(id) ON DELETE CASCADE,
  security_level INTEGER NOT NULL CHECK (security_level BETWEEN 1 AND 3),
  access_wrap JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
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
CREATE INDEX IF NOT EXISTS ix_vault_files_compartment ON vault_files(compartment);
CREATE INDEX IF NOT EXISTS ix_vault_files_created_at ON vault_files(created_at DESC);
CREATE INDEX IF NOT EXISTS ix_vault_shares_file_id ON vault_shares(file_id);
CREATE INDEX IF NOT EXISTS ix_vault_shares_expires_at ON vault_shares(expires_at);
CREATE INDEX IF NOT EXISTS ix_vault_audit_created_at ON vault_audit(created_at DESC);
"""

def connect():
    return psycopg.connect(load_settings().database_url, row_factory=dict_row)

def init_db():
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
