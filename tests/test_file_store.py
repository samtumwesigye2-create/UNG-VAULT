from pathlib import Path

import pytest

from app.file_store import LocalCiphertextStore, StorageIntegrityError


def test_ciphertext_store_round_trip(tmp_path: Path):
    store = LocalCiphertextStore(tmp_path)
    key = "files/abc123.bin"
    payload = b"encrypted-ciphertext-only"

    digest = store.put(key, payload)

    assert store.get(key, expected_sha256=digest) == payload
    assert (tmp_path / key).read_bytes() == payload


def test_ciphertext_store_rejects_path_escape(tmp_path: Path):
    store = LocalCiphertextStore(tmp_path)
    with pytest.raises(ValueError):
        store.put("../plaintext.txt", b"no")


def test_ciphertext_store_detects_tampering(tmp_path: Path):
    store = LocalCiphertextStore(tmp_path)
    key = "files/abc123.bin"
    digest = store.put(key, b"ciphertext")
    (tmp_path / key).write_bytes(b"tampered")

    with pytest.raises(StorageIntegrityError):
        store.get(key, expected_sha256=digest)
