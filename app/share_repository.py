from __future__ import annotations

from datetime import datetime
from typing import Any


class VaultShareRepository:
    """PostgreSQL repository for revocable secure-share metadata."""

    def __init__(self, connection):
        self.connection = connection

    def create(self, record: dict[str, Any]) -> None:
        params = (
            record["id"],
            record["file_id"],
            record["security_level"],
            record["access_wrap"],
            record["expires_at"],
            record.get("revoked_at"),
            record["created_by"],
        )
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vault_shares (
                    id, file_id, security_level, access_wrap,
                    expires_at, revoked_at, created_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                params,
            )

    def get(self, share_id: str):
        with self.connection.cursor() as cur:
            cur.execute(
                """
                SELECT id, file_id, security_level, access_wrap,
                       expires_at, revoked_at, created_by, created_at
                FROM vault_shares
                WHERE id = %s
                """,
                (share_id,),
            )
            return cur.fetchone()

    def revoke(self, share_id: str, revoked_at: datetime) -> None:
        with self.connection.cursor() as cur:
            cur.execute(
                """
                UPDATE vault_shares
                SET revoked_at = %s
                WHERE id = %s AND revoked_at IS NULL
                """,
                (revoked_at, share_id),
            )
