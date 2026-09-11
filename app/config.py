import base64, os
from dataclasses import dataclass


_ALLOWED_KEY_BACKENDS = {"local", "aws-kms", "gcp-kms", "hashicorp-vault"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    master_key: bytes | None
    janus_introspect_url: str
    janus_timeout_seconds: float
    key_backend: str
    environment: str


def _optional_master_key() -> bytes | None:
    key_b64 = os.getenv("VAULT_MASTER_KEY_B64", "").strip()
    if not key_b64:
        return None
    try:
        master_key = base64.b64decode(key_b64, validate=True)
    except Exception as e:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must be valid base64") from e
    if len(master_key) != 32:
        raise RuntimeError("VAULT_MASTER_KEY_B64 must decode to exactly 32 bytes")
    return master_key


def load_settings() -> Settings:
    database_url = os.getenv("DATABASE_URL", "").strip()
    janus_introspect_url = os.getenv("JANUS_INTROSPECT_URL", "").strip()
    janus_timeout_seconds = float(os.getenv("JANUS_TIMEOUT_SECONDS", "3"))
    key_backend = os.getenv("VAULT_KEY_BACKEND", "local").strip().lower() or "local"
    environment = os.getenv("ENVIRONMENT", "development").strip().lower() or "development"
    master_key = _optional_master_key()

    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if not janus_introspect_url:
        raise RuntimeError("JANUS_INTROSPECT_URL is required")
    if key_backend not in _ALLOWED_KEY_BACKENDS:
        raise RuntimeError(f"Unsupported VAULT_KEY_BACKEND: {key_backend}")
    if key_backend == "local" and master_key is None:
        raise RuntimeError("VAULT_MASTER_KEY_B64 is required for local key backend")
    if environment == "production" and key_backend == "local":
        raise RuntimeError("production requires a managed key backend")

    return Settings(
        database_url=database_url,
        master_key=master_key,
        janus_introspect_url=janus_introspect_url,
        janus_timeout_seconds=janus_timeout_seconds,
        key_backend=key_backend,
        environment=environment,
    )
