from datetime import datetime, timedelta, timezone
import pytest

from app.verification import VerificationError, VerificationService


def test_email_grant_is_single_use_and_expires():
    svc = VerificationService()
    now = datetime.now(timezone.utc)
    grant, otp = svc.issue_email_grant("share-1", "friend@example.com", now=now)
    assert "otp_hash" in grant and otp not in str(grant)
    svc.verify_email_grant(grant, otp, now=now)
    with pytest.raises(VerificationError):
        svc.verify_email_grant(grant, otp, now=now)


def test_secret_key_possession_round_trip_and_wrong_key_rejected():
    svc = VerificationService()
    grant, secret = svc.issue_secret_key_grant("share-2")
    assert secret not in str(grant)
    svc.verify_secret_key_grant(grant, secret)
    with pytest.raises(VerificationError):
        svc.verify_secret_key_grant(grant, "wrong-secret")


def test_expired_email_grant_is_rejected():
    svc = VerificationService(ttl_minutes=5)
    now = datetime.now(timezone.utc)
    grant, otp = svc.issue_email_grant("share-3", "friend@example.com", now=now)
    with pytest.raises(VerificationError):
        svc.verify_email_grant(grant, otp, now=now + timedelta(minutes=6))
