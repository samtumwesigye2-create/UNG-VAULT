from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone


class VerificationError(Exception):
    pass


def _digest(secret: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 310_000).hex()


class VerificationService:
    """Level 2 second-factor verifier. Raw OTPs and secret keys are never persisted."""

    def __init__(self, ttl_minutes: int = 10):
        self.ttl_minutes = ttl_minutes

    def issue_email_grant(self, share_id: str, email: str, now: datetime | None = None):
        now = now or datetime.now(timezone.utc)
        otp = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_bytes(16)
        grant = {
            "kind": "email",
            "share_id": share_id,
            "recipient_hash": hashlib.sha256(email.strip().lower().encode()).hexdigest(),
            "salt": base64.b64encode(salt).decode(),
            "otp_hash": _digest(otp, salt),
            "expires_at": now + timedelta(minutes=self.ttl_minutes),
            "used": False,
        }
        return grant, otp

    def verify_email_grant(self, grant: dict, otp: str, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        if grant.get("kind") != "email" or grant.get("used") or now >= grant["expires_at"]:
            raise VerificationError("Verification failed")
        salt = base64.b64decode(grant["salt"])
        if not hmac.compare_digest(_digest(otp, salt), grant["otp_hash"]):
            raise VerificationError("Verification failed")
        grant["used"] = True

    def issue_secret_key_grant(self, share_id: str):
        secret = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        grant = {
            "kind": "secret_key",
            "share_id": share_id,
            "salt": base64.b64encode(salt).decode(),
            "secret_hash": _digest(secret, salt),
        }
        return grant, secret

    def verify_secret_key_grant(self, grant: dict, secret: str) -> None:
        if grant.get("kind") != "secret_key":
            raise VerificationError("Verification failed")
        salt = base64.b64decode(grant["salt"])
        if not hmac.compare_digest(_digest(secret, salt), grant["secret_hash"]):
            raise VerificationError("Verification failed")
