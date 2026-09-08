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
"""

def connect():
    return psycopg.connect(load_settings().database_url, row_factory=dict_row)

def init_db():
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
