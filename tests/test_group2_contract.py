from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app" / "main.py").read_text()
UI = (ROOT / "ui" / "index.html").read_text()


def test_admin_api_contract():
    for route in (
        '@app.get("/admin/files")',
        '@app.get("/admin/shares")',
        '@app.post("/admin/shares/{share_id}/revoke")',
        '@app.get("/admin/audit")',
    ):
        assert route in MAIN
    assert "require_admin" in MAIN


def test_user_ui_has_persistent_vault_and_sharing():
    assert 'data-view="myvault"' in UI
    assert 'data-view="share"' in UI
    assert "/vault/files" in UI
    assert "/vault/shares" in UI


def test_admin_portal_is_exposed_in_ui():
    assert 'data-view="admin"' in UI
    assert "/admin/files" in UI
    assert "/admin/shares" in UI
    assert "/admin/audit" in UI
