from __future__ import annotations

import hashlib
import os
from pathlib import Path


class StorageIntegrityError(RuntimeError):
    """Raised when stored ciphertext no longer matches its recorded digest."""


class LocalCiphertextStore:
    """Filesystem storage adapter for encrypted payload bytes only."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not key or Path(key).is_absolute():
            raise ValueError("storage key must be a non-empty relative path")
        target = (self.root / key).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("storage key escapes ciphertext root") from exc
        return target

    @staticmethod
    def _sha256(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def put(self, key: str, ciphertext: bytes) -> str:
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            temp.write_bytes(ciphertext)
            os.replace(temp, target)
        finally:
            temp.unlink(missing_ok=True)
        return self._sha256(ciphertext)

    def get(self, key: str, *, expected_sha256: str) -> bytes:
        payload = self._path(key).read_bytes()
        actual = self._sha256(payload)
        if not expected_sha256 or actual != expected_sha256:
            raise StorageIntegrityError("stored ciphertext integrity verification failed")
        return payload

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)
