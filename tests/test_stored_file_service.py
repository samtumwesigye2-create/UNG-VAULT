import base64
import hashlib
from pathlib import Path

from app.file_store import LocalCiphertextStore
from app.stored_files import StoredFileService


class FakeCrypto:
    def encrypt(self, plaintext: bytes, aad: bytes) -> dict:
        return {"v": 99, "ciphertext": base64.b64encode(b"ENC:" + plaintext).decode()}

    def decrypt(self, envelope: dict, aad: bytes) -> bytes:
        raw = base64.b64decode(envelope["ciphertext"])
        assert raw.startswith(b"ENC:")
        return raw[4:]


def test_store_persists_ciphertext_not_plaintext(tmp_path: Path):
    store = LocalCiphertextStore(tmp_path)
    service = StoredFileService(store, FakeCrypto())
    plaintext = b"classified mission notes"

    record = service.store("file-123", plaintext)
    stored = (tmp_path / record["storage_key"]).read_bytes()

    assert plaintext not in stored
    assert stored == base64.b64decode(record["envelope"]["ciphertext"])
    assert record["plaintext_sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert record["ciphertext_sha256"] == hashlib.sha256(stored).hexdigest()


def test_retrieve_verifies_ciphertext_then_decrypts(tmp_path: Path):
    store = LocalCiphertextStore(tmp_path)
    service = StoredFileService(store, FakeCrypto())
    plaintext = b"vault payload"

    record = service.store("file-456", plaintext)

    assert service.retrieve("file-456", record) == plaintext
