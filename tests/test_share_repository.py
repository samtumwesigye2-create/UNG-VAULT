from datetime import datetime, timezone

from app.share_repository import VaultShareRepository


class FakeCursor:
    def __init__(self, row=None):
        self.row = row
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, row=None):
        self.cursor_obj = FakeCursor(row)

    def cursor(self):
        return self.cursor_obj


def test_create_persists_wrapped_share_without_raw_code():
    conn = FakeConnection()
    repo = VaultShareRepository(conn)
    expires = datetime(2026, 9, 16, tzinfo=timezone.utc)
    record = {
        "id": "00000000-0000-0000-0000-000000000001",
        "file_id": "00000000-0000-0000-0000-000000000002",
        "security_level": 1,
        "access_wrap": {"v": 1, "wrapped_key": "ciphertext-only"},
        "expires_at": expires,
        "revoked_at": None,
        "created_by": "janus:user-1",
    }

    repo.create(record)

    sql, params = conn.cursor_obj.calls[-1]
    assert "INSERT INTO vault_shares" in sql
    assert params[0] == record["id"]
    assert params[1] == record["file_id"]
    assert params[2] == 1
    assert params[3] == record["access_wrap"]
    assert "access_code" not in str(params).lower()


def test_get_returns_share_metadata():
    row = {"id": "share-1", "security_level": 1}
    conn = FakeConnection(row)
    repo = VaultShareRepository(conn)

    assert repo.get("share-1") == row
    sql, params = conn.cursor_obj.calls[-1]
    assert "FROM vault_shares" in sql
    assert params == ("share-1",)


def test_revoke_updates_revoked_at():
    conn = FakeConnection()
    repo = VaultShareRepository(conn)
    revoked_at = datetime(2026, 9, 15, 1, 30, tzinfo=timezone.utc)

    repo.revoke("share-1", revoked_at)

    sql, params = conn.cursor_obj.calls[-1]
    assert "UPDATE vault_shares" in sql
    assert "revoked_at = %s" in sql
    assert params == (revoked_at, "share-1")
