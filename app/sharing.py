from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from .file_crypto import AccessCodeError, create_access_code_wrap, unwrap_with_access_code


class ShareAccessError(ValueError):
    """Raised when a secure share cannot be accessed."""


class ShareService:
    def __init__(self, now: Callable[[], datetime] | None = None):
        self._now = now or (lambda: datetime.now(timezone.utc))

    def create_level1(
        self,
        *,
        file_id: str,
        file_key: bytes,
        access_code: str,
        expires_at: datetime,
    ) -> dict:
        if not file_id:
            raise ValueError("file_id is required")
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return {
            "id": str(uuid4()),
            "file_id": file_id,
            "security_level": 1,
            "access_wrap": create_access_code_wrap(file_key, access_code),
            "expires_at": expires_at,
            "revoked_at": None,
            "created_at": self._now(),
        }

    def unlock(self, share: dict, access_code: str) -> bytes:
        if share.get("revoked_at") is not None:
            raise ShareAccessError("share has been revoked")
        expires_at = share.get("expires_at")
        if not isinstance(expires_at, datetime) or expires_at <= self._now():
            raise ShareAccessError("share has expired")
        try:
            return unwrap_with_access_code(share["access_wrap"], access_code)
        except (AccessCodeError, KeyError, TypeError) as exc:
            raise ShareAccessError("invalid access code") from exc

    def revoke(self, share: dict) -> None:
        if share.get("revoked_at") is None:
            share["revoked_at"] = self._now()
