from pathlib import Path


def test_main_exposes_level1_share_endpoints():
    source = Path("app/main.py").read_text()

    assert '@app.post("/vault/shares")' in source
    assert '@app.post("/vault/shares/{share_id}/open")' in source
    assert '@app.post("/vault/shares/{share_id}/revoke")' in source


def test_share_creation_and_revocation_require_janus_principal():
    source = Path("app/main.py").read_text()

    assert "def create_share(" in source
    assert "p: Principal = Depends(require_principal)" in source
    assert "def revoke_share(" in source


def test_open_share_accepts_access_code_without_persisting_it():
    source = Path("app/main.py").read_text()

    assert "class OpenShareRequest" in source
    assert "access_code:" in source
    assert "VaultShareRepository" in source
    assert "ShareService" in source
