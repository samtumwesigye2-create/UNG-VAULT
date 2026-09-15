from __future__ import annotations

import base64
import hashlib
from typing import Protocol

from .file_store import LocalCiphertextStore


class FileCrypto(Protocol):
    def encrypt(self, plaintext: bytes, aad: bytes) -> dict: ...
    def decrypt(self, envelope: dict, aad: bytes) -> bytes: ...


class StoredFileService:
    """Encrypts before persistence and decrypts only after verified retrieval."""

    def __init__(self, store: LocalCiphertextStore, crypto: FileCrypto):
        self.store = store
        self.crypto = crypto

    @staticmethod
    def _sha256(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def store(self, file_id: str, plaintext: bytes) -> dict:
        if not file_id:
            raise ValueError("file_id is required")
        aad = file_id.encode("utf-8")
        envelope = self.crypto.encrypt(plaintext, aad)
        encoded = envelope.get("ciphertext")
        if not isinstance(encoded, str) or not encoded:
            raise ValueError("crypto envelope missing ciphertext")
        ciphertext = base64.b64decode(encoded, validate=True)
        storage_key = f"files/{file_id}.bin"
        ciphertext_sha256 = self.store.put(storage_key, ciphertext)
        return {
            "id": file_id,
            "storage_key": storage_key,
            "plaintext_sha256": self._sha256(plaintext),
            "ciphertext_sha256": ciphertext_sha256,
            "size_bytes": len(plaintext),
            "key_version": int(envelope.get("v", 1)),
            "envelope": envelope,
        }

    def retrieve(self, file_id: str, record: dict) -> bytes:
        if record.get("id") != file_id:
            raise ValueError("file metadata does not match requested id")
        ciphertext = self.store.get(
            record["storage_key"], expected_sha256=record["ciphertext_sha256"]
        )
        envelope = dict(record["envelope"])
        envelope["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        plaintext = self.crypto.decrypt(envelope, file_id.encode("utf-8"))
        if self._sha256(plaintext) != record["plaintext_sha256"]:
            raise ValueError("decrypted plaintext integrity verification failed")
        return plaintext
