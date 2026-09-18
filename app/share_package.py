from __future__ import annotations

import base64
import io
import json
import os
import secrets
import zipfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .redaction import redact_file

MAGIC = "UNG-VAULT-SHARE"
VERSION = 1


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_key(code: str, salt: bytes) -> bytes:
    if len(code) < 12:
        raise ValueError("Full-access code must be at least 12 characters")
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(code.encode("utf-8"))


def build_share_package(
    original: bytes,
    filename: str,
    media_type: str,
    percentage: int,
    access_code: str,
) -> bytes:
    preview = redact_file(original, percentage, media_type, filename)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(access_code, salt)

    aad_obj = {
        "format": MAGIC,
        "version": VERSION,
        "filename": Path(filename).name,
        "media_type": media_type or "application/octet-stream",
        "percentage": percentage,
    }
    aad = json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, original, aad)

    manifest = {
        **aad_obj,
        "kdf": {
            "name": "scrypt",
            "salt": _b64(salt),
            "n": 32768,
            "r": 8,
            "p": 1,
        },
        "cipher": {
            "name": "AES-256-GCM",
            "nonce": _b64(nonce),
            "ciphertext_file": "full-access.bin",
        },
        "preview": {
            "filename": "preview" + preview.suffix,
            "media_type": preview.media_type,
        },
    }

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr(manifest["preview"]["filename"], preview.data)
        zf.writestr("full-access.bin", ciphertext)
    return out.getvalue()


def unlock_share_package(package_bytes: bytes, access_code: str) -> tuple[bytes, str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))
            ciphertext = zf.read(manifest["cipher"]["ciphertext_file"])
    except Exception as exc:
        raise ValueError("Invalid UNG-VAULT sharing package") from exc

    if manifest.get("format") != MAGIC or manifest.get("version") != VERSION:
        raise ValueError("Unsupported UNG-VAULT sharing package")

    kdf_info = manifest.get("kdf") or {}
    cipher_info = manifest.get("cipher") or {}
    if kdf_info.get("name") != "scrypt" or cipher_info.get("name") != "AES-256-GCM":
        raise ValueError("Unsupported sharing package cryptography")

    salt = _unb64(kdf_info["salt"])
    nonce = _unb64(cipher_info["nonce"])
    key = _derive_key(access_code, salt)

    aad_obj = {
        "format": manifest["format"],
        "version": manifest["version"],
        "filename": manifest["filename"],
        "media_type": manifest["media_type"],
        "percentage": manifest["percentage"],
    }
    aad = json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        original = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError("Full-access code is incorrect or package integrity check failed") from exc

    return original, str(manifest["filename"]), str(manifest["media_type"])
