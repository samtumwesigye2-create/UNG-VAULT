import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class WrappedKey:
    provider: str
    key_id: str
    ciphertext: bytes


class KeyProvider(Protocol):
    name: str
    key_id: str

    def wrap_key(self, dek: bytes, aad: bytes = b"") -> WrappedKey: ...
    def unwrap_key(self, wrapped: WrappedKey, aad: bytes = b"") -> bytes: ...


class LocalKeyProvider:
    name = "local"

    def __init__(self, master_key: bytes, key_id: str = "local-master"):
        if len(master_key) != 32:
            raise RuntimeError("local master key must be exactly 32 bytes")
        self.master_key = master_key
        self.key_id = key_id

    def wrap_key(self, dek: bytes, aad: bytes = b"") -> WrappedKey:
        nonce = secrets.token_bytes(12)
        ciphertext = nonce + AESGCM(self.master_key).encrypt(nonce, dek, aad)
        return WrappedKey(self.name, self.key_id, ciphertext)

    def unwrap_key(self, wrapped: WrappedKey, aad: bytes = b"") -> bytes:
        nonce, ciphertext = wrapped.ciphertext[:12], wrapped.ciphertext[12:]
        return AESGCM(self.master_key).decrypt(nonce, ciphertext, aad)


class AwsKmsKeyProvider:
    name = "aws-kms"

    def __init__(self, key_id: str, client=None):
        if not key_id:
            raise RuntimeError("AWS_KMS_KEY_ID is required")
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise RuntimeError("boto3 is required for aws-kms backend") from exc
            client = boto3.client("kms")
        self.client = client
        self.key_id = key_id

    @staticmethod
    def _context(aad: bytes) -> dict[str, str]:
        return {"aad_sha256": hashlib.sha256(aad).hexdigest()} if aad else {}

    def wrap_key(self, dek: bytes, aad: bytes = b"") -> WrappedKey:
        kwargs = {"KeyId": self.key_id, "Plaintext": dek}
        context = self._context(aad)
        if context:
            kwargs["EncryptionContext"] = context
        response = self.client.encrypt(**kwargs)
        return WrappedKey(self.name, self.key_id, bytes(response["CiphertextBlob"]))

    def unwrap_key(self, wrapped: WrappedKey, aad: bytes = b"") -> bytes:
        kwargs = {"CiphertextBlob": wrapped.ciphertext, "KeyId": wrapped.key_id}
        context = self._context(aad)
        if context:
            kwargs["EncryptionContext"] = context
        response = self.client.decrypt(**kwargs)
        return bytes(response["Plaintext"])


class GcpKmsKeyProvider:
    name = "gcp-kms"

    def __init__(self, key_id: str, client=None):
        if not key_id:
            raise RuntimeError("GCP_KMS_KEY_NAME is required")
        if client is None:
            try:
                from google.cloud import kms_v1
            except ImportError as exc:
                raise RuntimeError("google-cloud-kms is required for gcp-kms backend") from exc
            client = kms_v1.KeyManagementServiceClient()
        self.client = client
        self.key_id = key_id

    def wrap_key(self, dek: bytes, aad: bytes = b"") -> WrappedKey:
        request = {"name": self.key_id, "plaintext": dek}
        if aad:
            request["additional_authenticated_data"] = aad
        response = self.client.encrypt(request=request)
        return WrappedKey(self.name, self.key_id, bytes(response.ciphertext))

    def unwrap_key(self, wrapped: WrappedKey, aad: bytes = b"") -> bytes:
        request = {"name": wrapped.key_id, "ciphertext": wrapped.ciphertext}
        if aad:
            request["additional_authenticated_data"] = aad
        response = self.client.decrypt(request=request)
        return bytes(response.plaintext)


class HashicorpVaultTransitKeyProvider:
    name = "hashicorp-vault"

    def __init__(self, key_id: str, addr: str, token: str, mount_point: str = "transit", client=None):
        if not key_id:
            raise RuntimeError("HASHICORP_VAULT_TRANSIT_KEY is required")
        if not addr:
            raise RuntimeError("HASHICORP_VAULT_ADDR is required")
        if not token:
            raise RuntimeError("HASHICORP_VAULT_TOKEN is required")
        if client is None:
            try:
                import hvac
            except ImportError as exc:
                raise RuntimeError("hvac is required for hashicorp-vault backend") from exc
            client = hvac.Client(url=addr, token=token)
            if not client.is_authenticated():
                raise RuntimeError("HashiCorp Vault authentication failed")
        self.client = client
        self.key_id = key_id
        self.mount_point = mount_point

    def wrap_key(self, dek: bytes, aad: bytes = b"") -> WrappedKey:
        kwargs = {
            "name": self.key_id,
            "plaintext": base64.b64encode(dek).decode(),
            "mount_point": self.mount_point,
        }
        if aad:
            kwargs["context"] = base64.b64encode(aad).decode()
        response = self.client.secrets.transit.encrypt_data(**kwargs)
        ciphertext = response["data"]["ciphertext"].encode()
        return WrappedKey(self.name, self.key_id, ciphertext)

    def unwrap_key(self, wrapped: WrappedKey, aad: bytes = b"") -> bytes:
        kwargs = {
            "name": wrapped.key_id,
            "ciphertext": wrapped.ciphertext.decode(),
            "mount_point": self.mount_point,
        }
        if aad:
            kwargs["context"] = base64.b64encode(aad).decode()
        response = self.client.secrets.transit.decrypt_data(**kwargs)
        return base64.b64decode(response["data"]["plaintext"])


def _load_local_master_key() -> bytes:
    value = os.getenv("VAULT_MASTER_KEY_B64", "").strip()
    if not value:
        raise RuntimeError("VAULT_MASTER_KEY_B64 is required for local key backend")
    try:
        key = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must be valid base64") from exc
    if len(key) != 32:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must decode to exactly 32 bytes")
    return key


def get_key_provider(provider_name: str | None = None, key_id: str | None = None) -> KeyProvider:
    backend = (provider_name or os.getenv("VAULT_KEY_BACKEND", "local")).strip().lower()

    if backend == "local":
        return LocalKeyProvider(_load_local_master_key(), key_id or "local-master")
    if backend == "aws-kms":
        return AwsKmsKeyProvider(key_id or os.getenv("AWS_KMS_KEY_ID", "").strip())
    if backend == "gcp-kms":
        return GcpKmsKeyProvider(key_id or os.getenv("GCP_KMS_KEY_NAME", "").strip())
    if backend == "hashicorp-vault":
        return HashicorpVaultTransitKeyProvider(
            key_id or os.getenv("HASHICORP_VAULT_TRANSIT_KEY", "").strip(),
            os.getenv("HASHICORP_VAULT_ADDR", "").strip(),
            os.getenv("HASHICORP_VAULT_TOKEN", "").strip(),
            os.getenv("HASHICORP_VAULT_TRANSIT_MOUNT", "transit").strip() or "transit",
        )
    raise RuntimeError(f"Unsupported VAULT_KEY_BACKEND: {backend}")
