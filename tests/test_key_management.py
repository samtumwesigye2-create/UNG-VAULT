import base64

import pytest


def test_local_key_provider_wrap_unwrap_round_trip():
    from app.key_management import LocalKeyProvider

    provider = LocalKeyProvider(b"k" * 32)
    dek = b"d" * 32
    aad = b"order:123"

    wrapped = provider.wrap_key(dek, aad)

    assert wrapped.provider == "local"
    assert provider.unwrap_key(wrapped, aad) == dek


def test_provider_factory_rejects_unknown_backend(monkeypatch):
    from app.key_management import get_key_provider

    monkeypatch.setenv("VAULT_KEY_BACKEND", "unknown")
    with pytest.raises(RuntimeError, match="Unsupported VAULT_KEY_BACKEND"):
        get_key_provider()


def test_aws_kms_provider_preserves_aad_context():
    from app.key_management import AwsKmsKeyProvider, WrappedKey

    class Client:
        def encrypt(self, **kwargs):
            assert kwargs["KeyId"] == "arn:aws:kms:us-east-1:1:key/test"
            assert kwargs["EncryptionContext"]["aad_sha256"]
            return {"CiphertextBlob": b"aws-wrapped"}

        def decrypt(self, **kwargs):
            assert kwargs["CiphertextBlob"] == b"aws-wrapped"
            assert kwargs["EncryptionContext"]["aad_sha256"]
            return {"Plaintext": b"d" * 32}

    provider = AwsKmsKeyProvider("arn:aws:kms:us-east-1:1:key/test", client=Client())
    wrapped = provider.wrap_key(b"d" * 32, b"shipment:42")
    assert wrapped == WrappedKey("aws-kms", provider.key_id, b"aws-wrapped")
    assert provider.unwrap_key(wrapped, b"shipment:42") == b"d" * 32


def test_gcp_kms_provider_preserves_aad():
    from app.key_management import GcpKmsKeyProvider

    class Response:
        ciphertext = b"gcp-wrapped"
        plaintext = b"d" * 32

    class Client:
        def encrypt(self, request):
            assert request["additional_authenticated_data"] == b"shipment:42"
            return Response()

        def decrypt(self, request):
            assert request["additional_authenticated_data"] == b"shipment:42"
            return Response()

    provider = GcpKmsKeyProvider("projects/p/locations/l/keyRings/r/cryptoKeys/k", client=Client())
    wrapped = provider.wrap_key(b"d" * 32, b"shipment:42")
    assert wrapped.provider == "gcp-kms"
    assert provider.unwrap_key(wrapped, b"shipment:42") == b"d" * 32


def test_hashicorp_vault_transit_provider_round_trip_contract():
    from app.key_management import HashicorpVaultTransitKeyProvider

    class Transit:
        def encrypt_data(self, **kwargs):
            assert kwargs["context"] == base64.b64encode(b"shipment:42").decode()
            return {"data": {"ciphertext": "vault:v1:wrapped"}}

        def decrypt_data(self, **kwargs):
            assert kwargs["ciphertext"] == "vault:v1:wrapped"
            return {"data": {"plaintext": base64.b64encode(b"d" * 32).decode()}}

    class Secrets:
        transit = Transit()

    class Client:
        secrets = Secrets()

    provider = HashicorpVaultTransitKeyProvider(
        "ung-vault-dek", "https://vault.example", "token", client=Client()
    )
    wrapped = provider.wrap_key(b"d" * 32, b"shipment:42")
    assert wrapped.provider == "hashicorp-vault"
    assert provider.unwrap_key(wrapped, b"shipment:42") == b"d" * 32


def test_crypto_uses_provider_envelope_v2(monkeypatch):
    from app import crypto
    from app.key_management import WrappedKey

    class FakeProvider:
        name = "fake-kms"
        key_id = "fake-key"

        def wrap_key(self, dek: bytes, aad: bytes) -> WrappedKey:
            return WrappedKey(self.name, self.key_id, b"wrapped:" + dek)

        def unwrap_key(self, wrapped: WrappedKey, aad: bytes) -> bytes:
            assert wrapped.provider == self.name
            assert wrapped.key_id == self.key_id
            return wrapped.ciphertext.removeprefix(b"wrapped:")

    monkeypatch.setattr(crypto, "get_key_provider", lambda *args, **kwargs: FakeProvider())

    envelope = crypto.encrypt_bytes(b"secret payload", b"shipment:42")

    assert envelope["v"] == 2
    assert envelope["wrap_provider"] == "fake-kms"
    assert envelope["wrap_key_id"] == "fake-key"
    assert crypto.decrypt_bytes(envelope, b"shipment:42") == b"secret payload"


def test_legacy_v1_envelope_remains_decryptable(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app import crypto

    master = b"m" * 32
    dek = b"d" * 32
    aad = b"legacy"
    wrap_nonce = b"1" * 12
    data_nonce = b"2" * 12
    envelope = {
        "v": 1,
        "alg": "AES-256-GCM",
        "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
        "wrapped_dek": base64.b64encode(AESGCM(master).encrypt(wrap_nonce, dek, aad)).decode(),
        "data_nonce": base64.b64encode(data_nonce).decode(),
        "ciphertext": base64.b64encode(AESGCM(dek).encrypt(data_nonce, b"old secret", aad)).decode(),
    }

    class Settings:
        master_key = master

    monkeypatch.setattr(crypto, "load_settings", lambda: Settings())

    assert crypto.decrypt_bytes(envelope, aad) == b"old secret"
