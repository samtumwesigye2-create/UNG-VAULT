import json, uuid
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from .auth import Principal, authorize, require_principal
from .audit import append_audit, verify_chain
from .crypto import decrypt_bytes, encrypt_bytes
from .db import connect, init_db
from .config import load_settings

app = FastAPI(title="UNG-VAULT", version="1.0.0")

class StoreRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    compartment: str = Field(min_length=1, max_length=100)
    classification: str
    value: str

@app.on_event("startup")
def startup():
    load_settings()
    init_db()

@app.get("/health")
def health():
    return {"status":"ok","service":"UNG-VAULT","version":"1.0.0"}

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

@app.get("/audit/verify")
def audit_verify(p: Principal = Depends(require_principal)):
    if p.clearance not in {"restricted","top_secret"}:
        raise HTTPException(403, "Restricted clearance required")
    with connect() as conn:
        with conn.cursor() as cur:
            result = verify_chain(cur)
            append_audit(cur, p.subject, "audit_verified", detail=result)
            return result
