import pytest

from app.file_crypto import AccessCodeError, create_access_code_wrap, unwrap_with_access_code


def test_access_code_wrap_round_trips_secret_key():
    secret_key = bytes(range(32))
    wrapped = create_access_code_wrap(secret_key, "River-Quartz-4821")

    assert unwrap_with_access_code(wrapped, "River-Quartz-4821") == secret_key
    assert wrapped["kdf"] == "scrypt"
    assert wrapped["salt"]
    assert wrapped["nonce"]
    assert wrapped["wrapped_key"]
    assert "River-Quartz-4821" not in str(wrapped)


def test_wrong_access_code_is_rejected():
    wrapped = create_access_code_wrap(bytes(range(32)), "correct-code")

    with pytest.raises(AccessCodeError):
        unwrap_with_access_code(wrapped, "wrong-code")


def test_same_code_uses_unique_random_salt_and_wrap():
    secret_key = bytes(range(32))
    first = create_access_code_wrap(secret_key, "same-code")
    second = create_access_code_wrap(secret_key, "same-code")

    assert first["salt"] != second["salt"]
    assert first["wrapped_key"] != second["wrapped_key"]
