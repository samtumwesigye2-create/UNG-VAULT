from pathlib import Path


def test_secure_storage_schema_tracks_ciphertext_only_file_metadata():
    db = Path("app/db.py").read_text()
    assert "CREATE TABLE IF NOT EXISTS vault_files" in db
    for column in (
        "storage_key TEXT NOT NULL",
        "ciphertext_sha256 TEXT NOT NULL",
        "plaintext_sha256 TEXT NOT NULL",
        "size_bytes BIGINT NOT NULL",
        "key_version INTEGER NOT NULL",
    ):
        assert column in db


def test_secure_storage_schema_never_adds_plaintext_payload_column():
    db = Path("app/db.py").read_text().lower()
    assert "plaintext bytea" not in db
    assert "plaintext text" not in db
