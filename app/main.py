import json, uuid, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, quote
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import Response
from pydantic import BaseModel, Field
from .auth import Principal, authorize, require_principal
from .audit import append_audit, verify_chain
from .crypto import decrypt_bytes, encrypt_bytes
from .db import connect, init_db
from .config import load_settings
from .file_repository import VaultFileRepository
from .file_store import LocalCiphertextStore, StorageIntegrityError
from .stored_files import EnvelopeCryptoAdapter, StoredFileService
from .share_repository import VaultShareRepository
from .sharing import ShareAccessError, ShareService

app = FastAPI(title="UNG-VAULT", version="1.4.0")

class StoreRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200); compartment: str = Field(min_length=1, max_length=100); classification: str; value: str
class CreateShareRequest(BaseModel):
    file_id: str = Field(min_length=1); access_code: str = Field(min_length=8, max_length=256); expires_minutes: int = Field(default=60, ge=1, le=10080)
class OpenShareRequest(BaseModel): access_code: str = Field(min_length=1, max_length=256)

def require_admin(p: Principal = Depends(require_principal)):
    roles={str(x).lower() for x in (p.claims.get("roles") or [])}
    if p.clearance!="top_secret" and not roles.intersection({"platform-admin","security-admin"}): raise HTTPException(403,"VAULT administrator access required")
    return p

@app.on_event("startup")
def startup(): load_settings(); init_db()
@app.get("/health")
def health(): return {"status":"ok","service":"UNG-VAULT","version":"1.4.0"}
@app.get("/ready")
def ready():
    try:
        load_settings()
        with connect() as conn:
            with conn.cursor() as cur: cur.execute("SELECT 1"); cur.fetchone()
        return {"ready":True}
    except Exception as e: raise HTTPException(503,f"not ready: {type(e).__name__}")

@app.post("/vault/objects")
def create_object(req:StoreRequest,p: Principal = Depends(require_principal)):
    authorize(p,req.classification,req.compartment); oid=str(uuid.uuid4()); env=encrypt_bytes(req.value.encode(),oid.encode())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vault_objects(id,compartment,classification,name,envelope,created_by) VALUES (%s,%s,%s,%s,%s::jsonb,%s)",(oid,req.compartment,req.classification,req.name,json.dumps(env),p.subject)); append_audit(cur,p.subject,"object_created",oid)
    return {"id":oid,"name":req.name}
@app.get("/vault/objects/{object_id}")
def get_object(object_id:str,p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,compartment,classification,envelope FROM vault_objects WHERE id=%s",(object_id,)); row=cur.fetchone()
            if not row: raise HTTPException(404,"Object not found")
            authorize(p,row["classification"],row["compartment"])
            try: value=decrypt_bytes(row["envelope"],object_id.encode()).decode()
            except Exception: append_audit(cur,p.subject,"decryption_failed",object_id); raise HTTPException(409,"Ciphertext integrity verification failed")
            append_audit(cur,p.subject,"object_read",object_id); return {"id":str(row["id"]),"name":row["name"],"compartment":row["compartment"],"classification":row["classification"],"value":value}

MAX_FILE_BYTES=int(os.getenv("VAULT_MAX_FILE_BYTES",str(25*1024*1024))); FILE_MAGIC=b"UNGVAULT1\n"
def _safe_name(name:str)->str: return Path(name or "file").name.replace("\r","_").replace("\n","_")[:180] or "file"
def _stored_service(): return StoredFileService(LocalCiphertextStore(os.getenv("VAULT_STORAGE_PATH","/tmp/ung-vault-ciphertext")),EnvelopeCryptoAdapter())

@app.post("/vault/files")
async def store_vault_file(file:UploadFile=File(...),compartment:str=Form(...),classification:str=Form(...),p: Principal = Depends(require_principal)):
    authorize(p,classification,compartment); data=await file.read(MAX_FILE_BYTES+1)
    if len(data)>MAX_FILE_BYTES: raise HTTPException(413,"File too large")
    fid=str(uuid.uuid4()); name=_safe_name(file.filename); record=_stored_service().store(fid,data); record.update({"compartment":compartment,"classification":classification,"name":name,"content_type":file.content_type,"created_by":p.subject})
    try:
        with connect() as conn:
            VaultFileRepository(conn).create(record)
            with conn.cursor() as cur: append_audit(cur,p.subject,"stored_file_created",fid,{"bytes":len(data)})
    except Exception: _stored_service().ciphertext_store.delete(record["storage_key"]); raise
    return {"id":fid,"name":name,"classification":classification,"compartment":compartment,"size_bytes":len(data)}
@app.get("/vault/files")
def list_vault_files(p: Principal = Depends(require_principal)):
    with connect() as conn: rows=VaultFileRepository(conn).list_for_owner(p.subject)
    return [{**dict(r),"id":str(r["id"])} for r in rows]
@app.get("/vault/files/{file_id}/download")
def download_vault_file(file_id:str,p: Principal = Depends(require_principal)):
    with connect() as conn:
        row=VaultFileRepository(conn).get(file_id)
        if not row: raise HTTPException(404,"File not found")
        authorize(p,row["classification"],row["compartment"])
        if row["created_by"]!=p.subject: raise HTTPException(403,"File owner access required")
        try: data=_stored_service().retrieve(file_id,dict(row))
        except (StorageIntegrityError,ValueError,KeyError): raise HTTPException(409,"Stored file integrity verification failed")
        with conn.cursor() as cur: append_audit(cur,p.subject,"stored_file_downloaded",file_id)
    return Response(data,media_type=row.get("content_type") or "application/octet-stream",headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(_safe_name(row['name']))}","Cache-Control":"no-store"})

@app.post("/vault/files/encrypt")
async def encrypt_file(file:UploadFile=File(...),p: Principal = Depends(require_principal)):
    data=await file.read(MAX_FILE_BYTES+1)
    if len(data)>MAX_FILE_BYTES: raise HTTPException(413,"File too large")
    fid=str(uuid.uuid4()); name=_safe_name(file.filename); env=encrypt_bytes(data,fid.encode()); payload=FILE_MAGIC+json.dumps({"format":"UNG-VAULT-FILE","version":1,"id":fid,"filename":name,"envelope":env},separators=(",",":")).encode()
    return Response(payload,media_type="application/octet-stream",headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(name+'.ungvault')}"})
@app.post("/vault/files/decrypt")
async def decrypt_file(file:UploadFile=File(...),p: Principal = Depends(require_principal)):
    raw=await file.read(MAX_FILE_BYTES+1024*1024)
    if not raw.startswith(FILE_MAGIC): raise HTTPException(400,"Not a UNG-VAULT encrypted file")
    try:
        pkg=json.loads(raw[len(FILE_MAGIC):]); fid=str(pkg["id"]); name=_safe_name(pkg["filename"]); data=decrypt_bytes(pkg["envelope"],fid.encode())
    except Exception: raise HTTPException(409,"Encrypted file integrity verification failed")
    return Response(data,media_type="application/octet-stream",headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(name)}"})

@app.post("/vault/shares")
def create_share(req:CreateShareRequest,p: Principal = Depends(require_principal)):
    exp=datetime.now(timezone.utc)+timedelta(minutes=req.expires_minutes)
    with connect() as conn:
        f=VaultFileRepository(conn).get(req.file_id)
        if not f: raise HTTPException(404,"File not found")
        if f["created_by"]!=p.subject: raise HTTPException(403,"Only the file owner can create this share")
        s=ShareService().create_level1(req.file_id,os.urandom(32),req.access_code,exp); s["created_by"]=p.subject; VaultShareRepository(conn).create(s)
        with conn.cursor() as cur: append_audit(cur,p.subject,"share_created",req.file_id,{"share_id":s["id"]})
    return {"id":s["id"],"file_id":req.file_id,"security_level":1,"expires_at":exp}
@app.post("/vault/shares/{share_id}/open")
def open_share(share_id:str,req:OpenShareRequest):
    with connect() as conn:
        s=VaultShareRepository(conn).get(share_id)
        if not s: raise HTTPException(404,"Share not found")
        try: ShareService().unlock(s,req.access_code)
        except ShareAccessError: raise HTTPException(403,"Invalid, expired, or revoked share")
    return {"share_id":share_id,"file_id":str(s["file_id"]),"authorized":True}
@app.post("/vault/shares/{share_id}/revoke")
def revoke_share(share_id:str,p: Principal = Depends(require_principal)):
    now=datetime.now(timezone.utc)
    with connect() as conn:
        repo=VaultShareRepository(conn); s=repo.get(share_id)
        if not s: raise HTTPException(404,"Share not found")
        if s["created_by"]!=p.subject: raise HTTPException(403,"Only the share creator can revoke this share")
        repo.revoke(share_id,now)
    return {"id":share_id,"revoked":True,"revoked_at":now}

@app.get("/admin/files")
def admin_files(p: Principal = Depends(require_admin)):
    with connect() as conn:
        with conn.cursor() as cur: cur.execute("SELECT id,name,classification,compartment,size_bytes,created_by,created_at FROM vault_files ORDER BY created_at DESC LIMIT 500"); return [dict(x) for x in cur.fetchall()]
@app.get("/admin/shares")
def admin_shares(p: Principal = Depends(require_admin)):
    with connect() as conn:
        with conn.cursor() as cur: cur.execute("SELECT id,file_id,security_level,expires_at,revoked_at,created_by,created_at FROM vault_shares ORDER BY created_at DESC LIMIT 500"); return [dict(x) for x in cur.fetchall()]
@app.post("/admin/shares/{share_id}/revoke")
def admin_revoke_share(share_id:str,p: Principal = Depends(require_admin)):
    now=datetime.now(timezone.utc)
    with connect() as conn:
        VaultShareRepository(conn).revoke(share_id,now)
        with conn.cursor() as cur: append_audit(cur,p.subject,"admin_share_revoked",detail={"share_id":share_id})
    return {"id":share_id,"revoked":True,"revoked_at":now}
@app.get("/admin/audit")
def admin_audit(p: Principal = Depends(require_admin)):
    with connect() as conn:
        with conn.cursor() as cur: cur.execute("SELECT seq,actor,action,object_id,detail,entry_hash FROM vault_audit ORDER BY seq DESC LIMIT 500"); return [dict(x) for x in cur.fetchall()]
@app.get("/audit/verify")
def audit_verify(p: Principal = Depends(require_principal)):
    if p.clearance not in {"restricted","top_secret"}: raise HTTPException(403,"Restricted clearance required")
    with connect() as conn:
        with conn.cursor() as cur: result=verify_chain(cur); append_audit(cur,p.subject,"audit_verified",detail=result); return result

from ui_portal import install_ui
_janus=urlsplit(os.getenv('JANUS_INTROSPECT_URL','https://ung-iam-production.up.railway.app/v1/auth/introspect'))
install_ui(app,Path(__file__).resolve().parent.parent/'ui'/'index.html',f'{_janus.scheme}://{_janus.netloc}')
