from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class AccessCodeError(ValueError):
    """Raised when an access code cannot unwrap protected key material."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _derive_key(access_code: str, salt: bytes) -> bytes:
    if not isinstance(access_code, str) or not access_code:
        raise AccessCodeError("access code is required")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
        access_code.encode("utf-8")
    )


def create_access_code_wrap(secret_key: bytes, access_code: str) -> dict:
    if not isinstance(secret_key, bytes) or len(secret_key) != 32:
        raise ValueError("secret key must be 32 bytes")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrapping_key = _derive_key(access_code, salt)
    wrapped_key = AESGCM(wrapping_key).encrypt(nonce, secret_key, b"UNG-VAULT-ACCESS-CODE-V1")
    return {
        "v": 1,
        "kdf": "scrypt",
        "n": 2**15,
        "r": 8,
        "p": 1,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
    }


def unwrap_with_access_code(wrapped: dict, access_code: str) -> bytes:
    try:
        if wrapped.get("v") != 1 or wrapped.get("kdf") != "scrypt":
            raise AccessCodeError("unsupported access-code envelope")
        salt = _unb64(wrapped["salt"])
        nonce = _unb64(wrapped["nonce"])
        wrapped_key = _unb64(wrapped["wrapped_key"])
        wrapping_key = _derive_key(access_code, salt)
        return AESGCM(wrapping_key).decrypt(
            nonce, wrapped_key, b"UNG-VAULT-ACCESS-CODE-V1"
        )
    except AccessCodeError:
        raise
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise AccessCodeError("invalid access code or protected key data") from exc
