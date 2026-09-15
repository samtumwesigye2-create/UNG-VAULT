from datetime import datetime, timedelta, timezone

import pytest

from app.sharing import ShareAccessError, ShareService


NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def test_level1_share_unlocks_only_with_exact_code():
    service = ShareService(now=lambda: NOW)
    file_key = bytes(range(32))

    share = service.create_level1(
        file_id="file-1",
        file_key=file_key,
        access_code="River-Quartz-4821",
        expires_at=NOW + timedelta(hours=2),
    )

    assert service.unlock(share, "River-Quartz-4821") == file_key
    assert "River-Quartz-4821" not in str(share)
    assert share["security_level"] == 1
    assert share["revoked_at"] is None

    with pytest.raises(ShareAccessError):
        service.unlock(share, "wrong-code")


def test_expired_share_is_rejected():
    service = ShareService(now=lambda: NOW)
    share = service.create_level1(
        file_id="file-1",
        file_key=bytes(range(32)),
        access_code="correct-code",
        expires_at=NOW - timedelta(seconds=1),
    )

    with pytest.raises(ShareAccessError, match="expired"):
        service.unlock(share, "correct-code")


def test_revoked_share_is_rejected():
    service = ShareService(now=lambda: NOW)
    share = service.create_level1(
        file_id="file-1",
        file_key=bytes(range(32)),
        access_code="correct-code",
        expires_at=NOW + timedelta(hours=1),
    )
    service.revoke(share)

    with pytest.raises(ShareAccessError, match="revoked"):
        service.unlock(share, "correct-code")
