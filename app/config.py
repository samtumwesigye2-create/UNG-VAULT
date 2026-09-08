import base64, os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    database_url: str
    master_key: bytes
    janus_public_key: str
    janus_audience: str | None
    janus_algorithms: tuple[str, ...]


def load_settings() -> Settings:
    database_url = os.getenv("DATABASE_URL", "").strip()
    key_b64 = os.getenv("VAULT_MASTER_KEY_B64", "").strip()
    janus_public_key = os.getenv("JANUS_JWT_PUBLIC_KEY", "").strip()
    audience = os.getenv("JANUS_JWT_AUDIENCE", "").strip() or None
    algorithms = tuple(a.strip() for a in os.getenv("JANUS_JWT_ALGORITHMS", "RS256,EdDSA").split(",") if a.strip())
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
    if not janus_public_key:
        raise RuntimeError("JANUS_JWT_PUBLIC_KEY is required")
    return Settings(database_url, master_key, janus_public_key, audience, algorithms)
