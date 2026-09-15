import json, uuid, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, quote
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, Field
from .auth import Principal, authorize, require_principal
from .audit import append_audit, verify_chain
from .crypto import decrypt_bytes, encrypt_bytes
from .db import connect, init_db
from .config import load_settings
from .share_repository import VaultShareRepository
from .sharing import ShareAccessError, ShareService

app = FastAPI(title="UNG-VAULT", version="1.2.0")

class StoreRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    compartment: str = Field(min_length=1, max_length=100)
    classification: str
    value: str

class CreateShareRequest(BaseModel):
    file_id: str = Field(min_length=1)
    access_code: str = Field(min_length=8, max_length=256)
    expires_minutes: int = Field(default=60, ge=1, le=10080)

class OpenShareRequest(BaseModel):
    access_code: str = Field(min_length=1, max_length=256)

@app.on_event("startup")
def startup():
    load_settings()
    init_db()

@app.get("/health")
def health():
    return {"status":"ok","service":"UNG-VAULT","version":"1.2.0"}

@app.get("/ready")
def ready():
    try:
        load_settings()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"ready": True}
    except Exception as e:
        raise HTTPException(503, f"not ready: {type(e).__name__}")

@app.post("/vault/objects")
def create_object(req: StoreRequest, p: Principal = Depends(require_principal)):
    try:
        authorize(p, req.classification, req.compartment)
    except HTTPException:
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "denied_create", detail={"classification":req.classification,"compartment":req.compartment})
        raise
    object_id = str(uuid.uuid4())
    envelope = encrypt_bytes(req.value.encode(), object_id.encode())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vault_objects(id,compartment,classification,name,envelope,created_by) VALUES (%s,%s,%s,%s,%s::jsonb,%s)", (object_id,req.compartment,req.classification,req.name,json.dumps(envelope),p.subject))
            append_audit(cur, p.subject, "object_created", object_id, {"classification":req.classification,"compartment":req.compartment})
    return {"id":object_id,"name":req.name}

@app.get("/vault/objects/{object_id}")
def get_object(object_id: str, p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,compartment,classification,envelope FROM vault_objects WHERE id=%s", (object_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Object not found")
            try:
                authorize(p, row["classification"], row["compartment"])
            except HTTPException:
                append_audit(cur, p.subject, "denied_read", object_id, {"classification":row["classification"],"compartment":row["compartment"]})
                raise
            try:
                value = decrypt_bytes(row["envelope"], object_id.encode()).decode()
            except Exception:
                append_audit(cur, p.subject, "decryption_failed", object_id)
                raise HTTPException(409, "Ciphertext integrity verification failed")
            append_audit(cur, p.subject, "object_read", object_id)
            return {"id":str(row["id"]),"name":row["name"],"compartment":row["compartment"],"classification":row["classification"],"value":value}

MAX_FILE_BYTES = int(os.getenv("VAULT_MAX_FILE_BYTES", str(25 * 1024 * 1024)))
FILE_MAGIC = b"UNGVAULT1\n"

def _safe_name(name: str) -> str:
    return Path(name or "file").name.replace("\r", "_").replace("\n", "_")[:180] or "file"

@app.post("/vault/files/encrypt")
async def encrypt_file(file: UploadFile = File(...), p: Principal = Depends(require_principal)):
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
    file_id = str(uuid.uuid4())
    name = _safe_name(file.filename)
    envelope = encrypt_bytes(data, file_id.encode())
    package = {"format":"UNG-VAULT-FILE","version":1,"id":file_id,"filename":name,"envelope":envelope}
    payload = FILE_MAGIC + json.dumps(package, separators=(",", ":")).encode()
    with connect() as conn:
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "file_encrypted", file_id, {"filename":name,"bytes":len(data)})
    out = name + ".ungvault"
    return Response(payload, media_type="application/octet-stream", headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(out)}","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

@app.post("/vault/files/decrypt")
async def decrypt_file(file: UploadFile = File(...), p: Principal = Depends(require_principal)):
    raw = await file.read(MAX_FILE_BYTES + 1024 * 1024)
    if not raw.startswith(FILE_MAGIC):
        raise HTTPException(400, "Not a UNG-VAULT encrypted file")
    try:
        package = json.loads(raw[len(FILE_MAGIC):])
        if package.get("format") != "UNG-VAULT-FILE" or package.get("version") != 1:
            raise ValueError()
        file_id = str(package["id"])
        name = _safe_name(package["filename"])
        data = decrypt_bytes(package["envelope"], file_id.encode())
    except Exception:
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "file_decryption_failed")
        raise HTTPException(409, "Encrypted file integrity verification failed")
    with connect() as conn:
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "file_decrypted", file_id, {"filename":name,"bytes":len(data)})
    return Response(data, media_type="application/octet-stream", headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(name)}","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

@app.post("/vault/shares")
def create_share(req: CreateShareRequest, p: Principal = Depends(require_principal)):
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=req.expires_minutes)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,created_by FROM vault_files WHERE id=%s", (req.file_id,))
            file_row = cur.fetchone()
            if not file_row:
                raise HTTPException(404, "File not found")
            if file_row["created_by"] != p.subject:
                append_audit(cur, p.subject, "denied_share_create", req.file_id)
                raise HTTPException(403, "Only the file owner can create this share")
        share = ShareService().create_level1(file_id=req.file_id, file_key=os.urandom(32), access_code=req.access_code, expires_at=expires_at)
        share["created_by"] = p.subject
        VaultShareRepository(conn).create(share)
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "share_created", req.file_id, {"share_id":share["id"],"security_level":1,"expires_at":expires_at.isoformat()})
    return {"id":share["id"],"file_id":req.file_id,"security_level":1,"expires_at":expires_at}

@app.post("/vault/shares/{share_id}/open")
def open_share(share_id: str, req: OpenShareRequest):
    with connect() as conn:
        repo = VaultShareRepository(conn)
        share = repo.get(share_id)
        if not share:
            raise HTTPException(404, "Share not found")
        try:
            ShareService().unlock(share, req.access_code)
        except ShareAccessError:
            with conn.cursor() as cur:
                append_audit(cur, "shared-access", "share_access_denied", str(share["file_id"]), {"share_id":share_id})
            raise HTTPException(403, "Invalid, expired, or revoked share")
        with conn.cursor() as cur:
            append_audit(cur, "shared-access", "share_access_granted", str(share["file_id"]), {"share_id":share_id})
    return {"share_id":share_id,"file_id":str(share["file_id"]),"authorized":True}

@app.post("/vault/shares/{share_id}/revoke")
def revoke_share(share_id: str, p: Principal = Depends(require_principal)):
    now = datetime.now(timezone.utc)
    with connect() as conn:
        repo = VaultShareRepository(conn)
        share = repo.get(share_id)
        if not share:
            raise HTTPException(404, "Share not found")
        if share["created_by"] != p.subject:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "denied_share_revoke", str(share["file_id"]), {"share_id":share_id})
            raise HTTPException(403, "Only the share creator can revoke this share")
        repo.revoke(share_id, now)
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "share_revoked", str(share["file_id"]), {"share_id":share_id})
    return {"id":share_id,"revoked":True,"revoked_at":now}

@app.get("/audit/verify")
def audit_verify(p: Principal = Depends(require_principal)):
    if p.clearance not in {"restricted","top_secret"}:
        raise HTTPException(403, "Restricted clearance required")
    with connect() as conn:
        with conn.cursor() as cur:
            result = verify_chain(cur)
            append_audit(cur, p.subject, "audit_verified", detail=result)
            return result

from ui_portal import install_ui
_janus = urlsplit(os.getenv('JANUS_INTROSPECT_URL', 'https://ung-iam-production.up.railway.app/v1/auth/introspect'))
install_ui(app, Path(__file__).resolve().parent.parent / 'ui' / 'index.html', f'{_janus.scheme}://{_janus.netloc}')
