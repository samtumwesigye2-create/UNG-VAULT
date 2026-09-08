import base64, os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    database_url: str
    master_key: bytes
    janus_introspect_url: str
    janus_timeout_seconds: float


def load_settings() -> Settings:
    database_url = os.getenv("DATABASE_URL", "").strip()
    key_b64 = os.getenv("VAULT_MASTER_KEY_B64", "").strip()
    janus_introspect_url = os.getenv("JANUS_INTROSPECT_URL", "").strip()
    janus_timeout_seconds = float(os.getenv("JANUS_TIMEOUT_SECONDS", "3"))
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if not key_b64:
        raise RuntimeError("VAULT_MASTER_KEY_B64 is required")
    try:
        master_key = base64.b64decode(key_b64, validate=True)
    except Exception as e:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must be valid base64") from e
    if len(master_key) != 32:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must decode to exactly 32 bytes")
    if not janus_introspect_url:
        raise RuntimeError("JANUS_INTROSPECT_URL is required")
    return Settings(database_url, master_key, janus_introspect_url, janus_timeout_seconds)
