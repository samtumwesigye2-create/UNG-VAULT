from app.db import SCHEMA


def test_vault_shares_schema_persists_revocable_share_metadata():
    normalized = " ".join(SCHEMA.lower().split())

    assert "create table if not exists vault_shares" in normalized
    assert "file_id uuid not null" in normalized
    assert "security_level integer not null" in normalized
    assert "access_wrap jsonb not null" in normalized
    assert "expires_at timestamptz not null" in normalized
    assert "revoked_at timestamptz" in normalized
    assert "created_by text not null" in normalized


def test_vault_shares_schema_never_persists_raw_access_code():
    normalized = " ".join(SCHEMA.lower().split())

    assert "access_code text" not in normalized
    assert "plaintext_key" not in normalized
