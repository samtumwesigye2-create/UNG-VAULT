import json

from app.file_repository import VaultFileRepository


class FakeCursor:
    def __init__(self, row=None):
        self.row = row
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params):
        self.executed.append((sql, params))

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row=None):
        self.cursor_instance = FakeCursor(row)

    def cursor(self):
        return self.cursor_instance


def sample_record():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "compartment": "OPS",
        "classification": "PROTECTED",
        "name": "mission.pdf",
        "content_type": "application/pdf",
        "storage_key": "files/file-123.bin",
        "ciphertext_sha256": "cipher-hash",
        "plaintext_sha256": "plain-hash",
        "size_bytes": 1234,
        "key_version": 2,
        "envelope": {
            "v": 2,
            "wrap_provider": "aws-kms",
            "wrap_key_id": "key-1",
            "ciphertext": "MUST-NOT-BE-IN-POSTGRES",
        },
        "created_by": "janus:user-1",
    }


def test_create_persists_metadata_without_ciphertext_payload():
    conn = FakeConnection()
    repo = VaultFileRepository(conn)
    record = sample_record()

    repo.create(record)

    sql, params = conn.cursor_instance.executed[0]
    assert "INSERT INTO vault_files" in sql
    serialized = json.dumps(params, default=str)
    assert "MUST-NOT-BE-IN-POSTGRES" not in serialized
    assert "ciphertext" not in params[10]
    assert params[5] == record["storage_key"]
    assert params[6] == record["ciphertext_sha256"]


def test_get_returns_file_metadata():
    row = sample_record()
    row["envelope"] = {"v": 2, "wrap_provider": "aws-kms", "wrap_key_id": "key-1"}
    conn = FakeConnection(row)
    repo = VaultFileRepository(conn)

    result = repo.get(row["id"])

    assert result == row
    sql, params = conn.cursor_instance.executed[0]
    assert "FROM vault_files" in sql
    assert params == (row["id"],)
