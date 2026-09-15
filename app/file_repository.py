from __future__ import annotations

import json
from typing import Any


class VaultFileRepository:
    """PostgreSQL metadata repository. Encrypted payload bytes stay in file storage."""

    def __init__(self, connection):
        self.connection = connection

    def create(self, record: dict[str, Any]) -> None:
        envelope = dict(record["envelope"])
        envelope.pop("ciphertext", None)
        params = (
            record["id"],
            record["compartment"],
            record["classification"],
            record["name"],
            record.get("content_type"),
            record["storage_key"],
            record["ciphertext_sha256"],
            record["plaintext_sha256"],
            record["size_bytes"],
            record["key_version"],
            envelope,
            record["created_by"],
        )
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vault_files (
                    id, compartment, classification, name, content_type,
                    storage_key, ciphertext_sha256, plaintext_sha256,
                    size_bytes, key_version, envelope, created_by
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                params,
            )

    def get(self, file_id: str):
        with self.connection.cursor() as cur:
            cur.execute(
                """
                SELECT id, compartment, classification, name, content_type,
                       storage_key, ciphertext_sha256, plaintext_sha256,
                       size_bytes, key_version, envelope, created_by, created_at
                FROM vault_files
                WHERE id = %s
                """,
                (file_id,),
            )
            return cur.fetchone()
