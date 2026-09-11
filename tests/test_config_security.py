import pytest


def _base_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://vault:test@db/vault")
    monkeypatch.setenv("JANUS_INTROSPECT_URL", "https://janus.example/v1/auth/introspect")


def test_production_rejects_local_key_backend(monkeypatch):
    from app.config import load_settings

    _base_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("VAULT_KEY_BACKEND", "local")
    monkeypatch.setenv("VAULT_MASTER_KEY_B64", "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=")

    with pytest.raises(RuntimeError, match="managed key backend"):
        load_settings()


def test_unknown_key_backend_is_rejected(monkeypatch):
    from app.config import load_settings

    _base_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VAULT_KEY_BACKEND", "mystery-kms")
    monkeypatch.delenv("VAULT_MASTER_KEY_B64", raising=False)

    with pytest.raises(RuntimeError, match="Unsupported VAULT_KEY_BACKEND"):
        load_settings()


def test_managed_backend_does_not_require_local_master_key(monkeypatch):
    from app.config import load_settings

    _base_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("VAULT_KEY_BACKEND", "aws-kms")
    monkeypatch.delenv("VAULT_MASTER_KEY_B64", raising=False)

    settings = load_settings()
    assert settings.key_backend == "aws-kms"
    assert settings.master_key is None
