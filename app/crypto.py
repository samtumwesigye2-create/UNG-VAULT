import base64, json, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import load_settings
from .key_management import WrappedKey, get_key_provider


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def encrypt_bytes(plaintext: bytes, aad: bytes = b"") -> dict:
    provider = get_key_provider()
    dek = secrets.token_bytes(32)
    data_nonce = secrets.token_bytes(12)
    wrapped = provider.wrap_key(dek, aad)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad)
    return {
        "v": 2,
        "alg": "AES-256-GCM",
        "wrap_provider": wrapped.provider,
        "wrap_key_id": wrapped.key_id,
        "wrapped_dek": _b64(wrapped.ciphertext),
        "data_nonce": _b64(data_nonce),
        "ciphertext": _b64(ciphertext),
    }


def _decrypt_legacy_v1(envelope: dict, aad: bytes) -> bytes:
    settings = load_settings()
    master = settings.master_key
    if master is None:
        raise RuntimeError(
            "VAULT_MASTER_KEY_B64 is required to decrypt legacy v1 envelopes"
        )
    dek = AESGCM(master).decrypt(
        _unb64(envelope["wrap_nonce"]),
        _unb64(envelope["wrapped_dek"]),
        aad,
    )
    return AESGCM(dek).decrypt(
        _unb64(envelope["data_nonce"]),
        _unb64(envelope["ciphertext"]),
        aad,
    )


def decrypt_bytes(envelope: dict, aad: bytes = b"") -> bytes:
    if envelope.get("alg") != "AES-256-GCM":
        raise ValueError("Unsupported envelope format")

    version = envelope.get("v")
    if version == 1:
        return _decrypt_legacy_v1(envelope, aad)
    if version != 2:
        raise ValueError("Unsupported envelope format")

    provider_name = envelope.get("wrap_provider", "")
    key_id = envelope.get("wrap_key_id", "")
    if not provider_name or not key_id:
        raise ValueError("Invalid v2 envelope: missing key provider metadata")

    provider = get_key_provider(provider_name, key_id)
    wrapped = WrappedKey(provider_name, key_id, _unb64(envelope["wrapped_dek"]))
    dek = provider.unwrap_key(wrapped, aad)
    return AESGCM(dek).decrypt(
        _unb64(envelope["data_nonce"]),
        _unb64(envelope["ciphertext"]),
        aad,
    )


def canonical_envelope(envelope: dict) -> str:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))
