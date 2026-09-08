import base64, json, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import load_settings


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def encrypt_bytes(plaintext: bytes, aad: bytes = b"") -> dict:
    master = load_settings().master_key
    dek = secrets.token_bytes(32)
    wrap_nonce = secrets.token_bytes(12)
    data_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(master).encrypt(wrap_nonce, dek, aad)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad)
    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "wrap_nonce": _b64(wrap_nonce),
        "wrapped_dek": _b64(wrapped_dek),
        "data_nonce": _b64(data_nonce),
        "ciphertext": _b64(ciphertext),
    }


def decrypt_bytes(envelope: dict, aad: bytes = b"") -> bytes:
    if envelope.get("v") != 1 or envelope.get("alg") != "AES-256-GCM":
        raise ValueError("Unsupported envelope format")
    master = load_settings().master_key
    dek = AESGCM(master).decrypt(_unb64(envelope["wrap_nonce"]), _unb64(envelope["wrapped_dek"]), aad)
    return AESGCM(dek).decrypt(_unb64(envelope["data_nonce"]), _unb64(envelope["ciphertext"]), aad)


def canonical_envelope(envelope: dict) -> str:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))
