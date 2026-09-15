from pathlib import Path


def test_my_vault_exposes_upload_list_and_download_endpoints():
    source = Path("app/main.py").read_text()
    assert '@app.post("/vault/files")' in source
    assert '@app.get("/vault/files")' in source
    assert '@app.get("/vault/files/{file_id}/download")' in source


def test_my_vault_requires_janus_and_governed_authorization():
    source = Path("app/main.py").read_text()
    assert "def list_vault_files(" in source
    assert "async def store_vault_file(" in source
    assert "def download_vault_file(" in source
    assert "authorize(p," in source


def test_my_vault_uses_encrypted_storage_services():
    source = Path("app/main.py").read_text()
    assert "StoredFileService" in source
    assert "LocalCiphertextStore" in source
    assert "VaultFileRepository" in source
