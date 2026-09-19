import json, uuid, os, hashlib, secrets, hmac, urllib.request, urllib.error, time, threading
from pathlib import Path
from urllib.parse import urlsplit, quote
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, Cookie, Header, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .auth import Principal, authorize, require_principal, principal_from_authorization, exchange_scif_handle
from .audit import append_audit, verify_chain
from .crypto import decrypt_bytes, encrypt_bytes
from .redaction import redact_file
from .document_markings import marking_payload, pdf_marking, print_marking
from .access_policy import PROFILES, VAULT_DOCUMENT_COLORS
from .share_package import build_share_package, unlock_share_package
from .scif import (
    SCIF_MODES,
    new_session_token,
    require_scif_entitlement,
    require_trusted_device,
    require_recent_mfa,
    require_fresh_mfa,
    session_minutes,
    approval_count,
    render_scif_view,
    render_scif_image,
    utcnow,
)
from .db import connect, init_db
from .config import load_settings

app = FastAPI(title="UNG-VAULT", version="1.1.0")
PRESIDENT_INGEST_SECRET = os.getenv("PRESIDENT_INGEST_SECRET", "")
VAULT_MIL_RECEIPT_HMAC_SECRET = os.getenv("VAULT_MIL_RECEIPT_HMAC_SECRET", "")
VAULT_MIL_RECEIPT_ED25519_SEED_B64 = os.getenv("VAULT_MIL_RECEIPT_ED25519_SEED_B64", "")
VAULT_MIL_RECEIPT_KEY_ID = os.getenv("VAULT_MIL_RECEIPT_KEY_ID", "").strip()

MILITARY_PERMISSIONS={
    "vault:military:operate",
    "vault:military:approve",
    "vault:military:records-admin",
    "vault:military:audit",
}

def _military_permissions(p: Principal) -> set[str]:
    return set(map(str,p.claims.get("permissions",[])))

def _require_military_read(p: Principal, action: str="VAULT-MIL access") -> None:
    if not (_military_permissions(p) & MILITARY_PERMISSIONS):
        raise HTTPException(403, f"{action} requires a VAULT-MIL JANUS permission")

def _require_military_permission(p: Principal, permission: str, action: str, *, fresh_mfa: bool=False) -> None:
    if permission not in _military_permissions(p):
        raise HTTPException(403, f"{action} requires JANUS permission: {permission}")
    if not fresh_mfa:
        return
    if p.claims.get("credential_kind") != "session":
        raise HTTPException(403, f"{action} requires an interactive human JANUS session")
    if not p.claims.get("mfa") or not p.claims.get("mfa_time"):
        raise HTTPException(401, f"{action} requires fresh JANUS MFA step-up")
    try:
        age=time.time()-float(p.claims["mfa_time"])
    except Exception:
        raise HTTPException(401, f"{action} requires fresh JANUS MFA step-up")
    if age < 0 or age > 300:
        raise HTTPException(401, f"{action} requires JANUS MFA completed within the last 5 minutes")

def _military_receipt_signing_key() -> Ed25519PrivateKey:
    if not VAULT_MIL_RECEIPT_ED25519_SEED_B64:
        raise HTTPException(503, "Military receipt asymmetric signing is not configured")
    try:
        import base64
        raw=base64.urlsafe_b64decode(VAULT_MIL_RECEIPT_ED25519_SEED_B64 + "=" * (-len(VAULT_MIL_RECEIPT_ED25519_SEED_B64) % 4))
        if len(raw) != 32:
            raise ValueError()
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise HTTPException(503, "Military receipt signing key is invalid") from None

def _sign_military_receipt_ed25519(payload: dict) -> str:
    import base64
    canonical=json.dumps(payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    sig=_military_receipt_signing_key().sign(canonical)
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

def _military_receipt_public_key_b64() -> str:
    import base64
    raw=_military_receipt_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _military_receipt_key_id() -> str:
    raw=_military_receipt_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint=hashlib.sha256(raw).hexdigest()
    return VAULT_MIL_RECEIPT_KEY_ID or ("ed25519-"+fingerprint[:16])

def _register_military_receipt_signing_key() -> str:
    key_id=_military_receipt_key_id()
    public_key=_military_receipt_public_key_b64()
    import base64
    raw=base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
    fingerprint=hashlib.sha256(raw).hexdigest()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE military_receipt_signing_keys
                           SET is_active=FALSE,retired_at=COALESCE(retired_at,now())
                           WHERE is_active=TRUE AND key_id<>%s""",(key_id,))
            cur.execute("""INSERT INTO military_receipt_signing_keys
                           (key_id,algorithm,public_key_b64url,fingerprint_sha256,is_active,retired_at)
                           VALUES(%s,'Ed25519',%s,%s,TRUE,NULL)
                           ON CONFLICT (key_id) DO UPDATE
                           SET public_key_b64url=EXCLUDED.public_key_b64url,
                               fingerprint_sha256=EXCLUDED.fingerprint_sha256,
                               is_active=TRUE,
                               retired_at=NULL""",
                        (key_id,public_key,fingerprint))
    return key_id

def _sign_military_receipt(payload: dict) -> str:
    if not VAULT_MIL_RECEIPT_HMAC_SECRET:
        raise HTTPException(503, "Military receipt signing is not configured")
    canonical=json.dumps(payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    return hmac.new(VAULT_MIL_RECEIPT_HMAC_SECRET.encode("utf-8"),canonical,hashlib.sha256).hexdigest()

class ScifSessionRequest(BaseModel):
    object_id: str
    mode: str = "scif"
    duration_minutes: int = 30

class ScifEnterRequest(BaseModel):
    session_token: str = Field(min_length=20, max_length=256)
    device_public_jwk: dict

class ScifEmergencyRevokeRequest(BaseModel):
    owner: str | None = Field(default=None, max_length=256)
    reason: str = Field(min_length=3, max_length=500)

class PresidentRecordRequest(BaseModel):
    record_type: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    principal: str = Field(min_length=1, max_length=200)
    classification: str = "confidential"
    protection_profile: str = "VAULT-ENVELOPE"
    military_related: bool = False
    payload: dict

class StoreRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    compartment: str = Field(min_length=1, max_length=100)
    classification: str
    protection_profile: str | None = None
    military_related: bool = False
    military_branch: str | None = Field(default=None, max_length=100)
    operation_location: str | None = Field(default=None, max_length=160)
    value: str

class MilitaryTransferRequest(BaseModel):
    to_branch: str = Field(min_length=2, max_length=100)
    operation_location: str | None = Field(default=None, max_length=160)
    reason: str = Field(min_length=3, max_length=500)

class MilitaryReleaseDecisionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

@app.on_event("startup")
def startup():
    load_settings()
    init_db()
    _register_military_receipt_signing_key()
    threading.Thread(target=_sentinel_outbox_worker,name="sentinel-outbox",daemon=True).start()
    _flush_sentinel_outbox()
    print("SENTINEL_SIGNED_CHANNEL=" + ("ok" if _sentinel_signed_probe() else "degraded"))

@app.get("/health")
def health():
    return {"status":"ok","service":"UNG-VAULT","version":"1.1.0"}

@app.get("/ready")
def ready():
    try:
        load_settings()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {
            "ready": True,
            "database": "connected",
            "sentinel_signed_channel": _sentinel_signed_probe(),
        }
    except Exception as e:
        raise HTTPException(503, f"not ready: {type(e).__name__}")

def _verify_president_record_signature(req: PresidentRecordRequest, signature: str | None) -> None:
    if not PRESIDENT_INGEST_SECRET:
        raise HTTPException(503, "president_ingest_not_configured")
    raw = json.dumps(req.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(PRESIDENT_INGEST_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "invalid_president_signature")


@app.post("/vault/integrations/president/records", status_code=201)
def ingest_president_record(
    req: PresidentRecordRequest,
    x_ung_president_signature: str | None = Header(None),
):
    _verify_president_record_signature(req, x_ung_president_signature)
    if req.classification not in {"public", "internal", "confidential", "restricted", "top_secret"}:
        raise HTTPException(400, "invalid_classification")
    classification, protection_profile, military = _enforce_military_object_policy(
        military_related=(
            req.military_related
            or _contains_military_reference(req.record_type)
            or _contains_military_reference(req.name)
            or _contains_military_reference(req.payload)
        ),
        compartment="executive-presidency",
        classification=req.classification,
        profile=req.protection_profile,
    )
    if military:
        _require_military_permission(p,"vault:military:operate","Military protected record creation")
    if protection_profile not in PROFILES:
        raise HTTPException(400, "unknown_protection_profile")
    object_id = str(uuid.uuid4())
    value = json.dumps(req.payload, sort_keys=True, separators=(",", ":"))
    envelope = encrypt_bytes(value.encode("utf-8"), object_id.encode())
    compartment = "executive-presidency"
    created_by = "UNG-PRESIDENT:" + req.principal
    with connect() as conn:
        with conn.cursor() as cur:
            military_branch = None
            tracking_number = None
            operation_location = None
            if military:
                candidate_branch = str(req.payload.get("military_branch") or req.payload.get("branch") or "").strip() if isinstance(req.payload, dict) else ""
                military_branch = candidate_branch if candidate_branch in MILITARY_BRANCHES else "Joint Headquarters"
                tracking_number = _mil_tracking("MIL")
                operation_location = str(req.payload.get("operation_location") or req.payload.get("location") or "UNG-PRESIDENT").strip()[:160] if isinstance(req.payload, dict) else "UNG-PRESIDENT"
            cur.execute(
                """INSERT INTO vault_objects(id,compartment,classification,protection_profile,name,envelope,created_by,
                                             military_branch,tracking_number,operation_location)
                   VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)""",
                (object_id, compartment, classification, protection_profile, req.name, json.dumps(envelope), created_by,
                 military_branch, tracking_number, operation_location),
            )
            append_audit(cur, created_by, "military_record_created" if military else "president_record_ingested", object_id, {
                "record_type": req.record_type,
                "classification": classification,
                "protection_profile": protection_profile,
                "military_related": military,
                "source": "UNG-PRESIDENT",
                "tracking_number": tracking_number if military else None,
                "military_branch": military_branch if military else None,
                "operation_location": operation_location if military else None,
            })
    return {
        "id": object_id,
        "record_type": req.record_type,
        "classification": classification,
        "protection_profile": protection_profile,
        "military_related": military,
        "tracking_number": tracking_number if military else None,
        "military_branch": military_branch if military else None,
        "compartment": compartment,
        "encrypted": True,
    }


@app.get("/vault/objects")
def list_objects(limit: int = 100, p: Principal = Depends(require_principal)):
    limit = max(1, min(250, int(limit)))
    visible = []
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,name,compartment,classification,protection_profile,created_by,created_at
                           FROM vault_objects ORDER BY created_at DESC LIMIT %s""", (limit,))
            for row in cur.fetchall():
                try:
                    authorize(p, row["classification"], row["compartment"])
                except HTTPException:
                    continue
                visible.append({
                    "id": str(row["id"]),
                    "name": row["name"],
                    "compartment": row["compartment"],
                    "classification": row["classification"],
                    "protection_profile": row.get("protection_profile") or "VAULT-ENVELOPE",
                    "created_by": row["created_by"],
                    "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
                })
    return {"objects": visible, "count": len(visible)}


@app.get("/vault/activity")
def list_activity(limit: int = 100, p: Principal = Depends(require_principal)):
    limit = max(1, min(250, int(limit)))
    roles = set(map(str, p.claims.get("roles", [])))
    with connect() as conn:
        with conn.cursor() as cur:
            if roles.intersection({"platform-admin", "security-admin"}):
                cur.execute("""SELECT seq,actor,action,object_id,detail,created_at
                               FROM vault_audit ORDER BY seq DESC LIMIT %s""", (limit,))
            else:
                cur.execute("""SELECT seq,actor,action,object_id,detail,created_at
                               FROM vault_audit WHERE actor=%s ORDER BY seq DESC LIMIT %s""", (p.subject, limit))
            rows = cur.fetchall()
    return {
        "activity": [{
            "seq": r["seq"],
            "actor": r["actor"],
            "action": r["action"],
            "object_id": r["object_id"],
            "detail": r["detail"],
            "created_at": r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
        } for r in rows]
    }


@app.post("/vault/objects")
def create_object(req: StoreRequest, request: Request, p: Principal = Depends(require_principal)):
    classification, profile, military = _enforce_military_object_policy(
        military_related=(req.military_related or _contains_military_reference(req.name) or _contains_military_reference(req.value)),
        compartment=req.compartment,
        classification=req.classification,
        profile=req.protection_profile,
    )
    try:
        authorize(p, classification, req.compartment)
    except HTTPException:
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "denied_create", detail={"classification":classification,"compartment":req.compartment,"military_related":military})
        raise
    if profile not in PROFILES:
        raise HTTPException(400, "Unknown VAULT protection profile")
    object_id = str(uuid.uuid4())
    envelope = encrypt_bytes(req.value.encode(), object_id.encode())
    branch = (req.military_branch or "").strip() if military else None
    if military and branch and branch not in MILITARY_BRANCHES:
        raise HTTPException(400, "Unknown military branch")
    if military and not branch:
        branch = "Joint Headquarters"
    tracking = _mil_tracking("MIL") if military else None
    origin = _request_origin(request, req.operation_location)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO vault_objects(id,compartment,classification,protection_profile,name,envelope,created_by,
                                             military_branch,tracking_number,operation_location)
                   VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)""",
                (object_id,req.compartment,classification,profile,req.name,json.dumps(envelope),p.subject,
                 branch,tracking,origin["location"]),
            )
            append_audit(cur, p.subject, "military_record_created" if military else "object_created", object_id, {
                "tracking_number": tracking,
                "classification": classification,
                "compartment": req.compartment,
                "protection_profile": profile,
                "military_related": military,
                "military_branch": branch,
                "where": origin,
            })
    return {
        "id": object_id,
        "tracking_number": tracking,
        "name": req.name,
        "classification": classification,
        "protection_profile": profile,
        "military_related": military,
        "military_branch": branch,
        "operation_location": origin["location"],
        "created_by": p.subject,
        "marking": marking_payload(profile, object_id),
    }

@app.get("/vault/objects/{object_id}")
def get_object(object_id: str, p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,compartment,classification,protection_profile,envelope FROM vault_objects WHERE id=%s", (object_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Object not found")
            try:
                authorize(p, row["classification"], row["compartment"])
            except HTTPException:
                append_audit(cur, p.subject, "denied_read", object_id, {"classification":row["classification"],"compartment":row["compartment"]})
                cur.connection.commit()
                raise
            if row["classification"] in SCIF_REQUIRED_CLASSIFICATIONS:
                append_audit(cur, p.subject, "direct_plaintext_blocked_scif_required", object_id, {
                    "classification": row["classification"],
                    "compartment": row["compartment"],
                })
                _security_raise(cur, 403, "Digital SCIF required for restricted or top-secret plaintext access")
            try:
                value = decrypt_bytes(row["envelope"], object_id.encode()).decode()
            except Exception:
                append_audit(cur, p.subject, "decryption_failed", object_id)
                _security_raise(cur, 409, "Ciphertext integrity verification failed")
            profile = row.get("protection_profile") or "VAULT-ENVELOPE"
            append_audit(cur, p.subject, "military_record_accessed" if profile == "VAULT-MIL" else "object_read", object_id, {
                "classification": row["classification"],
                "compartment": row["compartment"],
            })
            return {
                "id": str(row["id"]),
                "name": row["name"],
                "compartment": row["compartment"],
                "classification": row["classification"],
                "protection_profile": profile,
                "value": value,
                "marking": marking_payload(profile, str(row["id"])) if profile in PROFILES else None,
            }

MAX_FILE_BYTES = int(os.getenv("VAULT_MAX_FILE_BYTES", str(25 * 1024 * 1024)))
FILE_MAGIC = b"UNGVAULT1\n"
MILITARY_COMPARTMENT_TERMS = ("military","defence","defense","armed-forces","armed_forces","army","air-force","air_force","navy")
MILITARY_CONTENT_TERMS = (
    "military","defence","defense","armed forces","armed-forces","army","air force","air-force","navy",
    "chief of defence","chief of defense","defence minister","defense minister","ministry of defence","ministry of defense",
    "barracks","brigade","battalion","regiment","command post","military intelligence","defence intelligence",
    "defense intelligence","joint staff","general headquarters","ghq"
)
MILITARY_MIN_REDACTION = 5
MILITARY_MAX_REDACTION = 95
MILITARY_BRANCHES = (
    "Joint Headquarters",
    "Land Forces",
    "Air Force",
    "Special Operations",
    "Reserve Force",
    "Military Intelligence",
    "Medical Services",
    "Logistics & Support",
)

def _mil_tracking(prefix: str = "MIL") -> str:
    stamp = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y%m%d")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:12].upper()}"

def _request_origin(request: Request | None, declared: str | None = None) -> dict:
    forwarded = ""
    ua = ""
    host = ""
    if request is not None:
        forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        ua = (request.headers.get("user-agent") or "")[:240]
        host = forwarded or (request.client.host if request.client else "")
    return {"location": (declared or "").strip() or "not-declared", "source_ip": host or "unknown", "user_agent": ua}

def _contains_military_reference(value) -> bool:
    try:
        if isinstance(value, dict):
            return any(_contains_military_reference(k) or _contains_military_reference(v) for k, v in value.items())
        if isinstance(value, (list, tuple, set)):
            return any(_contains_military_reference(v) for v in value)
        text = str(value or "").strip().lower()
        return any(term in text for term in MILITARY_CONTENT_TERMS)
    except Exception:
        return False

def _military_compartment(compartment: str) -> bool:
    value = (compartment or "").strip().lower().replace(" ", "-")
    return any(term in value for term in MILITARY_COMPARTMENT_TERMS)

def _enforce_military_object_policy(*, military_related: bool, compartment: str, classification: str, profile: str | None):
    military = bool(military_related or _military_compartment(compartment))
    if not military:
        return classification, profile or "VAULT-ENVELOPE", False
    rank = {"public":0,"internal":1,"confidential":2,"restricted":3,"top_secret":4}
    if classification not in rank:
        raise HTTPException(400, "Invalid security classification")
    protected_classification = classification if rank[classification] >= rank["restricted"] else "restricted"
    return protected_classification, "VAULT-MIL", True

SCIF_IDLE_SECONDS = max(30, min(900, int(os.getenv("VAULT_SCIF_IDLE_SECONDS", "90"))))
SCIF_APPROVAL_TTL_SECONDS = max(60, min(900, int(os.getenv("VAULT_SCIF_APPROVAL_TTL_SECONDS", "300"))))
SCIF_MAX_ENTRY_FAILURES = max(3, min(10, int(os.getenv("VAULT_SCIF_MAX_ENTRY_FAILURES", "5"))))
SCIF_MAX_COOKIE_FAILURES = max(2, min(10, int(os.getenv("VAULT_SCIF_MAX_COOKIE_FAILURES", "3"))))
SCIF_REQUIRED_CLASSIFICATIONS = {"restricted", "top_secret"}
SENTINEL_BASE_URL = os.getenv("SENTINEL_BASE_URL", "").rstrip("/")
SENTINEL_INGEST_SECRET = os.getenv("SENTINEL_INGEST_SECRET", "")
SENTINEL_OUTBOX_POLL_SECONDS = max(5, min(300, int(os.getenv("SENTINEL_OUTBOX_POLL_SECONDS", "30"))))

def _safe_name(name: str) -> str:
    return Path(name or "file").name.replace("\r", "_").replace("\n", "_")[:180] or "file"

@app.post("/vault/military/releases/request")
async def request_military_redacted_release(
    file: UploadFile = File(...),
    percentage: int = Form(...),
    military_branch: str = Form("Joint Headquarters"),
    reason: str = Form(...),
    p: Principal = Depends(require_principal),
):
    _require_military_permission(p,"vault:military:operate","Military release request")
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
    if percentage < MILITARY_MIN_REDACTION or percentage > MILITARY_MAX_REDACTION:
        raise HTTPException(400, f"Military redaction must be between {MILITARY_MIN_REDACTION}% and {MILITARY_MAX_REDACTION}%")
    branch = (military_branch or "").strip()
    if branch not in MILITARY_BRANCHES:
        raise HTTPException(400, "Unknown military branch")
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise HTTPException(400, "Release reason is required")
    request_id = str(uuid.uuid4())
    file_hash = hashlib.sha256(data).hexdigest()
    expires_at = utcnow() + __import__("datetime").timedelta(minutes=30)
    name = _safe_name(file.filename)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO military_release_requests
                   (id,file_name,file_sha256,military_branch,redaction_percentage,reason,requested_by,approved_by,status,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,'[]'::jsonb,'pending',%s)""",
                (request_id,name,file_hash,branch,percentage,reason,p.subject,expires_at),
            )
            append_audit(cur,p.subject,"military_release_requested",request_id,{
                "filename":name,
                "file_sha256":file_hash,
                "military_branch":branch,
                "percentage":percentage,
                "reason":reason,
                "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
                "expires_at":expires_at.isoformat(),
            })
    return {
        "request_id":request_id,
        "status":"pending",
        "filename":name,
        "file_sha256":file_hash,
        "military_branch":branch,
        "percentage":percentage,
        "reason":reason,
        "approvals":0,
        "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
        "expires_at":expires_at.isoformat(),
    }

@app.get("/vault/military/releases")
def list_military_release_requests(limit: int = 50, p: Principal = Depends(require_principal)):
    perms=_military_permissions(p)
    if not perms.intersection({"vault:military:approve","vault:military:audit","vault:military:records-admin"}):
        raise HTTPException(403,"Military release queue requires approver, records-admin, or auditor permission")
    limit=max(1,min(200,int(limit)))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE military_release_requests
                           SET status='expired'
                           WHERE status IN ('pending','approved') AND expires_at<=now()""")
            cur.execute("""SELECT id,file_name,military_branch,redaction_percentage,reason,requested_by,approved_by,status,expires_at,created_at,consumed_at
                           FROM military_release_requests
                           ORDER BY created_at DESC LIMIT %s""",(limit,))
            rows=cur.fetchall()
    out=[]
    for row in rows:
        approvals=row["approved_by"] or []
        out.append({
            "request_id":str(row["id"]),
            "filename":row["file_name"],
            "military_branch":row["military_branch"],
            "percentage":row["redaction_percentage"],
            "reason":row["reason"],
            "requested_by":row["requested_by"],
            "approved_by":approvals,
            "approvals":len(approvals),
            "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
            "status":row["status"],
            "expires_at":row["expires_at"].isoformat() if hasattr(row["expires_at"],"isoformat") else str(row["expires_at"]),
            "created_at":row["created_at"].isoformat() if hasattr(row["created_at"],"isoformat") else str(row["created_at"]),
            "consumed_at":row["consumed_at"].isoformat() if row["consumed_at"] and hasattr(row["consumed_at"],"isoformat") else (str(row["consumed_at"]) if row["consumed_at"] else None),
        })
    return {"requests":out}

@app.get("/vault/military/receipt-public-key")
def military_receipt_public_key(p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","Military receipt public key")
    return {
        "key_id":_military_receipt_key_id(),
        "algorithm":"Ed25519",
        "public_key_b64url":_military_receipt_public_key_b64(),
        "usage":"Verify UNG-VAULT military release receipt signatures",
    }

@app.get("/vault/military/receipt-keys")
def military_receipt_keys(p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","Military receipt key registry")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT key_id,algorithm,public_key_b64url,fingerprint_sha256,
                                  activated_at,retired_at,is_active
                           FROM military_receipt_signing_keys
                           ORDER BY activated_at DESC""")
            rows=cur.fetchall()
    return {"keys":[{
        "key_id":r["key_id"],
        "algorithm":r["algorithm"],
        "public_key_b64url":r["public_key_b64url"],
        "fingerprint_sha256":r["fingerprint_sha256"],
        "activated_at":r["activated_at"].isoformat() if r["activated_at"] else None,
        "retired_at":r["retired_at"].isoformat() if r["retired_at"] else None,
        "is_active":bool(r["is_active"]),
    } for r in rows]}

@app.post("/vault/military/receipt/verify-file")
async def verify_military_receipt_file(
    file: UploadFile = File(...),
    p: Principal = Depends(require_principal),
):
    _require_military_permission(p,"vault:military:audit","Military receipt verification")
    raw=await file.read(1024*1024)
    try:
        receipt=json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(400,"Receipt must be valid JSON") from None
    key_id=str(receipt.get("receipt_signing_key_id") or "").strip()
    signature=str(receipt.get("receipt_signature_ed25519") or "").strip()
    if not key_id or not signature:
        raise HTTPException(400,"Receipt is missing signing key ID or Ed25519 signature")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT public_key_b64url,is_active,retired_at
                           FROM military_receipt_signing_keys WHERE key_id=%s""",(key_id,))
            keyrow=cur.fetchone()
    if not keyrow:
        raise HTTPException(404,"Receipt signing key is not in the VAULT key registry")
    signed=dict(receipt)
    signed.pop("receipt_signature_ed25519",None)
    signed.pop("receipt_public_key_b64url",None)
    signed.pop("receipt_signing_key_id",None)
    import base64
    try:
        pub_raw=base64.urlsafe_b64decode(keyrow["public_key_b64url"] + "=" * (-len(keyrow["public_key_b64url"]) % 4))
        sig_raw=base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        canonical=json.dumps(signed,sort_keys=True,separators=(",",":")).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw,canonical)
        valid=True
    except Exception:
        valid=False
    return {
        "verified":valid,
        "key_id":key_id,
        "key_active":bool(keyrow["is_active"]),
        "key_retired_at":keyrow["retired_at"].isoformat() if keyrow["retired_at"] else None,
        "receipt_sha256":receipt.get("receipt_sha256"),
    }

@app.get("/vault/military/releases/{request_id}/receipt")
def military_release_receipt(request_id: str, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","Military release receipt")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            cur.execute("""SELECT seq,actor,action,detail,created_at
                           FROM vault_audit
                           WHERE object_id=%s
                           ORDER BY seq ASC""",(request_id,))
            events=cur.fetchall()
    receipt_payload={
        "request_id":request_id,
        "status":row["status"],
        "filename":row["file_name"],
        "file_sha256":row["file_sha256"],
        "military_branch":row["military_branch"],
        "redaction_percentage":row["redaction_percentage"],
        "reason":row["reason"],
        "requested_by":row["requested_by"],
        "approved_by":row["approved_by"] or [],
        "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
        "created_at":row["created_at"].isoformat() if hasattr(row["created_at"],"isoformat") else str(row["created_at"]),
        "expires_at":row["expires_at"].isoformat() if hasattr(row["expires_at"],"isoformat") else str(row["expires_at"]),
        "consumed_at":row["consumed_at"].isoformat() if row["consumed_at"] and hasattr(row["consumed_at"],"isoformat") else (str(row["consumed_at"]) if row["consumed_at"] else None),
        "events":[{
            "seq":e["seq"],
            "actor":e["actor"],
            "action":e["action"],
            "detail":e["detail"],
            "created_at":e["created_at"].isoformat() if hasattr(e["created_at"],"isoformat") else str(e["created_at"]),
        } for e in events],
    }
    canonical=json.dumps(receipt_payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    receipt_payload["receipt_sha256"]=hashlib.sha256(canonical).hexdigest()
    receipt_payload["receipt_signature_hmac_sha256"]=_sign_military_receipt(receipt_payload)
    receipt_payload["receipt_signature_ed25519"]=_sign_military_receipt_ed25519(receipt_payload)
    receipt_payload["receipt_public_key_b64url"]=_military_receipt_public_key_b64()
    receipt_payload["receipt_signing_key_id"]=_military_receipt_key_id()
    return receipt_payload

@app.get("/vault/military/releases/{request_id}/receipt/download")
def download_military_release_receipt(request_id: str, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","Military release receipt")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            cur.execute("""SELECT seq,actor,action,detail,created_at
                           FROM vault_audit
                           WHERE object_id=%s
                           ORDER BY seq ASC""",(request_id,))
            events=cur.fetchall()
    receipt={
        "request_id":request_id,
        "status":row["status"],
        "filename":row["file_name"],
        "file_sha256":row["file_sha256"],
        "military_branch":row["military_branch"],
        "redaction_percentage":row["redaction_percentage"],
        "reason":row["reason"],
        "requested_by":row["requested_by"],
        "approved_by":row["approved_by"] or [],
        "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
        "created_at":row["created_at"].isoformat() if hasattr(row["created_at"],"isoformat") else str(row["created_at"]),
        "expires_at":row["expires_at"].isoformat() if hasattr(row["expires_at"],"isoformat") else str(row["expires_at"]),
        "consumed_at":row["consumed_at"].isoformat() if row["consumed_at"] and hasattr(row["consumed_at"],"isoformat") else (str(row["consumed_at"]) if row["consumed_at"] else None),
        "events":[{
            "seq":e["seq"],
            "actor":e["actor"],
            "action":e["action"],
            "detail":e["detail"],
            "created_at":e["created_at"].isoformat() if hasattr(e["created_at"],"isoformat") else str(e["created_at"]),
        } for e in events],
    }
    canonical=json.dumps(receipt,sort_keys=True,separators=(",",":")).encode("utf-8")
    receipt["receipt_sha256"]=hashlib.sha256(canonical).hexdigest()
    receipt["receipt_signature_hmac_sha256"]=_sign_military_receipt(receipt)
    receipt["receipt_signature_ed25519"]=_sign_military_receipt_ed25519(receipt)
    receipt["receipt_public_key_b64url"]=_military_receipt_public_key_b64()
    receipt["receipt_signing_key_id"]=_military_receipt_key_id()
    body=json.dumps(receipt,indent=2,sort_keys=True).encode("utf-8")
    return Response(body,media_type="application/json",headers={
        "Content-Disposition":f"attachment; filename=VAULT-MIL-RECEIPT-{request_id}.json",
        "Cache-Control":"no-store",
        "X-Content-Type-Options":"nosniff",
    })

@app.post("/vault/military/releases/{request_id}/verify-receipt")
def verify_military_release_receipt(request_id: str, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","Military release receipt")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            cur.execute("""SELECT seq,actor,action,detail,created_at
                           FROM vault_audit
                           WHERE object_id=%s
                           ORDER BY seq ASC""",(request_id,))
            events=cur.fetchall()
    receipt_payload={
        "request_id":request_id,
        "status":row["status"],
        "filename":row["file_name"],
        "file_sha256":row["file_sha256"],
        "military_branch":row["military_branch"],
        "redaction_percentage":row["redaction_percentage"],
        "reason":row["reason"],
        "requested_by":row["requested_by"],
        "approved_by":row["approved_by"] or [],
        "approvals_required":PROFILES["VAULT-MIL"].approvals_required,
        "created_at":row["created_at"].isoformat() if hasattr(row["created_at"],"isoformat") else str(row["created_at"]),
        "expires_at":row["expires_at"].isoformat() if hasattr(row["expires_at"],"isoformat") else str(row["expires_at"]),
        "consumed_at":row["consumed_at"].isoformat() if row["consumed_at"] and hasattr(row["consumed_at"],"isoformat") else (str(row["consumed_at"]) if row["consumed_at"] else None),
        "events":[{
            "seq":e["seq"],
            "actor":e["actor"],
            "action":e["action"],
            "detail":e["detail"],
            "created_at":e["created_at"].isoformat() if hasattr(e["created_at"],"isoformat") else str(e["created_at"]),
        } for e in events],
    }
    canonical=json.dumps(receipt_payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    receipt_hash=hashlib.sha256(canonical).hexdigest()
    signed_payload=dict(receipt_payload)
    signed_payload["receipt_sha256"]=receipt_hash
    hmac_signature=_sign_military_receipt(signed_payload)
    ed25519_signature=_sign_military_receipt_ed25519(signed_payload)
    public_key_b64=_military_receipt_public_key_b64()
    try:
        import base64
        sig_raw=base64.urlsafe_b64decode(ed25519_signature + "=" * (-len(ed25519_signature) % 4))
        canonical_signed=json.dumps(signed_payload,sort_keys=True,separators=(",",":")).encode("utf-8")
        _military_receipt_signing_key().public_key().verify(sig_raw,canonical_signed)
        signature_ok=True
    except Exception:
        signature_ok=False
    with connect() as conn:
        with conn.cursor() as cur:
            chain_status=verify_chain(cur)
            chain_ok=bool(chain_status.get("valid"))
            verified=bool(chain_ok and signature_ok)
            append_audit(cur,p.subject,"military_release_receipt_verified",request_id,{
                "receipt_sha256":receipt_hash,
                "receipt_signature_hmac_sha256":hmac_signature,
                "receipt_signature_ed25519":ed25519_signature,
                "signature_valid":signature_ok,
                "audit_chain_valid":chain_ok,
                "broken_at_seq":chain_status.get("broken_at_seq"),
            })
    return {
        "request_id":request_id,
        "receipt_sha256":receipt_hash,
        "receipt_signature_hmac_sha256":hmac_signature,
        "receipt_signature_ed25519":ed25519_signature,
        "receipt_public_key_b64url":public_key_b64,
        "signature_valid":signature_ok,
        "audit_chain_valid":chain_ok,
        "verified":verified,
        "broken_at_seq":chain_status.get("broken_at_seq"),
    }

@app.post("/vault/military/releases/{request_id}/deny")
def deny_military_release(request_id: str, req: MilitaryReleaseDecisionRequest, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:approve","Military release denial",fresh_mfa=True)
    if p.clearance not in {"restricted","top_secret"}:
        raise HTTPException(403,"Restricted clearance or higher is required to deny a military release")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s FOR UPDATE""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            if row["status"] not in {"pending","approved"}:
                raise HTTPException(409,"Military release request is not deniable")
            if row["requested_by"] == p.subject:
                raise HTTPException(403,"Requester cannot deny their own request; use cancel instead")
            cur.execute("""UPDATE military_release_requests SET status='denied' WHERE id=%s""",(request_id,))
            append_audit(cur,p.subject,"military_release_denied",request_id,{
                "requested_by":row["requested_by"],
                "reason":req.reason,
                "approved_by":row["approved_by"] or [],
            })
    sentinel_notified=_notify_sentinel(
        severity="medium",
        title="VAULT-MIL redacted release denied",
        event_type="military_release_denied",
        details=f"Release request {request_id} denied by {p.subject}; reason: {req.reason}",
        object_id=request_id,
        owner=p.subject,
    )
    return {"request_id":request_id,"status":"denied","sentinel_notified":sentinel_notified,"denied_by":p.subject,"reason":req.reason}

@app.post("/vault/military/releases/{request_id}/cancel")
def cancel_military_release(request_id: str, req: MilitaryReleaseDecisionRequest, p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s FOR UPDATE""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            if row["requested_by"] != p.subject:
                raise HTTPException(403,"Only the requester can cancel this military release request")
            if row["status"] not in {"pending","approved"}:
                raise HTTPException(409,"Military release request is not cancellable")
            cur.execute("""UPDATE military_release_requests SET status='cancelled' WHERE id=%s""",(request_id,))
            append_audit(cur,p.subject,"military_release_cancelled",request_id,{
                "reason":req.reason,
                "approved_by":row["approved_by"] or [],
            })
    return {"request_id":request_id,"status":"cancelled","cancelled_by":p.subject,"reason":req.reason}

@app.post("/vault/military/releases/{request_id}/approve")
def approve_military_release(request_id: str, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:approve","Military release approval",fresh_mfa=True)
    if p.clearance not in {"restricted","top_secret"}:
        raise HTTPException(403,"Restricted clearance or higher is required to approve a military release")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT * FROM military_release_requests WHERE id=%s FOR UPDATE""",(request_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"Military release request not found")
            if row["status"] not in {"pending","approved"}:
                raise HTTPException(409,"Military release request is not approvable")
            if row["expires_at"] <= utcnow():
                cur.execute("UPDATE military_release_requests SET status='expired' WHERE id=%s",(request_id,))
                append_audit(cur,p.subject,"military_release_expired",request_id)
                raise HTTPException(409,"Military release request has expired")
            if row["requested_by"] == p.subject:
                raise HTTPException(403,"Requester cannot approve their own military release")
            approved=list(row["approved_by"] or [])
            if p.subject in approved:
                raise HTTPException(409,"You have already approved this release")
            approved.append(p.subject)
            required=PROFILES["VAULT-MIL"].approvals_required
            status="approved" if len(approved)>=required else "pending"
            cur.execute("""UPDATE military_release_requests SET approved_by=%s::jsonb,status=%s WHERE id=%s""",
                        (json.dumps(approved),status,request_id))
            append_audit(cur,p.subject,"military_release_approved",request_id,{
                "approval_number":len(approved),
                "approvals_required":required,
                "status":status,
                "requested_by":row["requested_by"],
            })
    sentinel_notified=False
    if status=="approved":
        sentinel_notified=_notify_sentinel(
            severity="high",
            title="VAULT-MIL redacted release fully approved",
            event_type="military_release_fully_approved",
            details=f"Release request {request_id} reached {len(approved)}/{required} approvals; final approver {p.subject}",
            object_id=request_id,
            owner=p.subject,
        )
    return {"request_id":request_id,"status":status,"sentinel_notified":sentinel_notified,"approvals":len(approved),"approvals_required":required,"approved_by":approved}

@app.post("/vault/military/files/protect")
async def military_file_protect(
    file: UploadFile = File(...),
    mode: str = Form(...),
    percentage: int = Form(95),
    military_branch: str = Form("Joint Headquarters"),
    operation_location: str = Form("not-declared"),
    release_request_id: str = Form(""),
    p: Principal = Depends(require_principal),
):
    _require_military_permission(p,"vault:military:operate","Military file protection")
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
    name = _safe_name(file.filename)
    mode = (mode or "").strip().lower()
    branch = (military_branch or "").strip()
    if branch not in MILITARY_BRANCHES:
        raise HTTPException(400, "Unknown military branch")
    location = (operation_location or "").strip()[:160] or "not-declared"
    event_id = str(uuid.uuid4())
    tracking_number = _mil_tracking("FILE")

    if mode == "encrypt":
        envelope = encrypt_bytes(data, event_id.encode())
        package = {
            "format": "UNG-VAULT-MILITARY-FILE",
            "version": 1,
            "id": event_id,
            "filename": name,
            "profile": "VAULT-MIL",
            "military_branch": branch,
            "tracking_number": tracking_number,
            "operation_location": location,
            "classification_floor": "restricted",
            "envelope": envelope,
        }
        payload = FILE_MAGIC + json.dumps(package, separators=(",", ":")).encode()
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "military_file_fully_encrypted", event_id, {
                    "filename": name, "bytes": len(data), "profile": "VAULT-MIL",
                    "tracking_number": tracking_number, "military_branch": branch,
                    "operation_location": location
                })
        return Response(
            payload,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name + '.mil.ungvault')}",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-UNG-VAULT-Profile": "VAULT-MIL",
                "X-UNG-Military-Handling": "full-encryption",
                "X-UNG-Tracking-Number": tracking_number,
                "X-UNG-Military-Branch": branch,
            },
        )

    if mode == "redact":
        if percentage < MILITARY_MIN_REDACTION or percentage > MILITARY_MAX_REDACTION:
            raise HTTPException(400, f"Military redaction must be between {MILITARY_MIN_REDACTION}% and {MILITARY_MAX_REDACTION}%")
        rid=(release_request_id or "").strip()
        if not rid:
            raise HTTPException(403, "Approved military release request required before creating a redacted release")
        file_hash=hashlib.sha256(data).hexdigest()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT * FROM military_release_requests WHERE id=%s FOR UPDATE""",(rid,))
                release=cur.fetchone()
                if not release:
                    raise HTTPException(404,"Military release request not found")
                if release["status"] != "approved":
                    raise HTTPException(403,"Military release request does not have all required independent approvals")
                if release["expires_at"] <= utcnow():
                    cur.execute("UPDATE military_release_requests SET status='expired' WHERE id=%s",(rid,))
                    append_audit(cur,p.subject,"military_release_expired",rid)
                    raise HTTPException(409,"Military release request has expired")
                if release["consumed_at"] is not None:
                    raise HTTPException(409,"Military release request has already been used")
                if release["file_sha256"] != file_hash or release["file_name"] != name:
                    raise HTTPException(409,"Selected file does not match the approved military release request")
                if release["military_branch"] != branch or int(release["redaction_percentage"]) != int(percentage):
                    raise HTTPException(409,"Branch or redaction percentage does not match the approved release request")
                approved=list(release["approved_by"] or [])
                if len(approved) < PROFILES["VAULT-MIL"].approvals_required:
                    raise HTTPException(403,"Military release request is missing required approvals")
                if p.subject in approved:
                    raise HTTPException(403,"A release approver cannot execute the final redacted release; an independent VAULT-MIL operator is required")
                if release["requested_by"] == p.subject:
                    raise HTTPException(403,"The release requester cannot execute the final redacted release; an independent VAULT-MIL operator is required")
        try:
            result = redact_file(data, percentage, file.content_type or "", name)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""UPDATE military_release_requests SET status='consumed',consumed_at=now()
                               WHERE id=%s AND status='approved' AND consumed_at IS NULL""",(rid,))
                if cur.rowcount != 1:
                    raise HTTPException(409,"Military release authorization is no longer valid")
                append_audit(cur, p.subject, "military_file_redacted_release", event_id, {
                    "filename": name,
                    "bytes": len(data),
                    "percentage": percentage,
                    "profile": "VAULT-MIL",
                    "tracking_number": tracking_number,
                    "military_branch": branch,
                    "operation_location": location,
                    "release_request_id": rid,
                    "approved_by": approved,
                    "irreversible": True,
                })
        sentinel_notified=_notify_sentinel(
            severity="high",
            title="VAULT-MIL redacted military file released",
            event_type="military_file_redacted_release",
            details=f"{name}; tracking {tracking_number}; branch {branch}; redaction {percentage}%; release request {rid}; actor {p.subject}",
            object_id=event_id,
            owner=p.subject,
        )
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur,p.subject,"military_sentinel_delivery",event_id,{
                    "event_type":"military_file_redacted_release",
                    "sentinel_notified":sentinel_notified,
                    "release_request_id":rid,
                    "tracking_number":tracking_number,
                })
        stem = Path(name).stem[:150] or "military-file"
        out = stem + f".mil-redacted-{percentage}" + result.suffix
        return Response(
            result.data,
            media_type=result.media_type,
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(out)}",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-UNG-VAULT-Profile": "VAULT-MIL",
                "X-UNG-Military-Handling": f"redacted-{percentage}",
                "X-UNG-Tracking-Number": tracking_number,
                "X-UNG-Military-Branch": branch,
                "X-UNG-SENTINEL-Notified": "true" if sentinel_notified else "false",
            },
        )

    raise HTTPException(400, "Military handling mode must be 'encrypt' or 'redact'")


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
        if package.get("format") not in {"UNG-VAULT-FILE", "UNG-VAULT-MILITARY-FILE"} or package.get("version") != 1:
            raise ValueError()
        file_id = str(package["id"])
        name = _safe_name(package["filename"])
        if package.get("format") == "UNG-VAULT-MILITARY-FILE":
            with connect() as conn:
                with conn.cursor() as cur:
                    append_audit(cur, p.subject, "military_plaintext_export_blocked", file_id, {
                        "filename": name,
                        "tracking_number": package.get("tracking_number"),
                        "military_branch": package.get("military_branch"),
                        "reason": "military files must remain encrypted or use an approved redacted release",
                    })
            raise HTTPException(403, "Military files cannot be exported as plaintext. Keep the file encrypted or create an approved redacted release.")
        data = decrypt_bytes(package["envelope"], file_id.encode())
    except Exception:
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "file_decryption_failed")
        raise HTTPException(409, "Encrypted file integrity verification failed")
    with connect() as conn:
        with conn.cursor() as cur:
            military = package.get("format") == "UNG-VAULT-MILITARY-FILE"
            append_audit(cur, p.subject, "military_file_decrypted" if military else "file_decrypted", file_id, {"filename":name,"bytes":len(data),"profile":package.get("profile") if military else None})
    return Response(data, media_type="application/octet-stream", headers={"Content-Disposition":f"attachment; filename*=UTF-8''{quote(name)}","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

@app.post("/vault/files/redact")
async def redact_shared_copy(
    file: UploadFile = File(...),
    percentage: int = Form(...),
    p: Principal = Depends(require_principal),
):
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
    name = _safe_name(file.filename)
    try:
        result = redact_file(data, percentage, file.content_type or "", name)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    event_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "file_redacted", event_id, {
                "filename": name,
                "bytes": len(data),
                "percentage": percentage,
                "irreversible": True,
            })
    stem = Path(name).stem[:150] or "file"
    out = stem + result.suffix
    return Response(
        result.data,
        media_type=result.media_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(out)}",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-UNG-VAULT-Redaction": str(percentage),
        },
    )

@app.post("/vault/files/share-package")
async def create_share_package(
    file: UploadFile = File(...),
    percentage: int = Form(...),
    access_code: str = Form(...),
    p: Principal = Depends(require_principal),
):
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
    name = _safe_name(file.filename)
    try:
        payload = build_share_package(data, name, file.content_type or "application/octet-stream", percentage, access_code)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    event_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "share_package_created", event_id, {
                "filename": name,
                "bytes": len(data),
                "percentage": percentage,
                "full_access_code": True,
            })
    out = (Path(name).stem[:150] or "file") + ".ungshare"
    return Response(payload, media_type="application/vnd.ung.vault-share+zip", headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(out)}",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })

@app.post("/vault/files/share-unlock")
async def unlock_share(
    file: UploadFile = File(...),
    access_code: str = Form(...),
    p: Principal = Depends(require_principal),
):
    raw = await file.read(MAX_FILE_BYTES + MAX_FILE_BYTES + 2 * 1024 * 1024)
    try:
        data, name, media_type = unlock_share_package(raw, access_code)
    except ValueError as exc:
        with connect() as conn:
            with conn.cursor() as cur:
                append_audit(cur, p.subject, "share_unlock_denied", detail={"reason": str(exc)})
        raise HTTPException(403, str(exc)) from None
    event_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            append_audit(cur, p.subject, "share_unlocked", event_id, {"filename": name, "bytes": len(data)})
    return Response(data, media_type=media_type or "application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(_safe_name(name))}",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })


@app.get("/vault/military/branches")
def military_branches(p: Principal = Depends(require_principal)):
    return {"branches": list(MILITARY_BRANCHES)}

@app.get("/vault/military/records")
def military_records(
    include_deleted: bool = False,
    limit: int = 200,
    branch: str | None = None,
    q: str | None = None,
    p: Principal = Depends(require_principal),
):
    _require_military_read(p,"Military record ledger")
    limit = max(1, min(500, int(limit)))
    params = []
    with connect() as conn:
        with conn.cursor() as cur:
            sql = """SELECT id,name,classification,compartment,created_by,created_at,military_branch,tracking_number,
                            operation_location,deleted_at,deleted_by,delete_tracking_number
                     FROM vault_objects
                     WHERE protection_profile='VAULT-MIL'"""
            if not include_deleted:
                sql += " AND deleted_at IS NULL"
            if branch:
                if branch not in MILITARY_BRANCHES:
                    raise HTTPException(400, "Unknown military branch")
                sql += " AND COALESCE(military_branch,'Joint Headquarters')=%s"
                params.append(branch)
            if q and q.strip():
                term = "%" + q.strip()[:120] + "%"
                sql += """ AND (name ILIKE %s OR COALESCE(tracking_number,'') ILIKE %s
                               OR COALESCE(operation_location,'') ILIKE %s OR created_by ILIKE %s)"""
                params.extend([term, term, term, term])
            sql += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
    return {"records":[{
        "id": str(r["id"]), "tracking_number": r["tracking_number"], "name": r["name"],
        "classification": r["classification"], "compartment": r["compartment"],
        "branch": r["military_branch"] or "Joint Headquarters",
        "created_by": r["created_by"],
        "created_at": r["created_at"].isoformat() if hasattr(r["created_at"],"isoformat") else str(r["created_at"]),
        "operation_location": r["operation_location"],
        "deleted_at": r["deleted_at"].isoformat() if r["deleted_at"] and hasattr(r["deleted_at"],"isoformat") else (str(r["deleted_at"]) if r["deleted_at"] else None),
        "deleted_by": r["deleted_by"], "delete_tracking_number": r["delete_tracking_number"],
    } for r in rows]}

@app.get("/vault/military/records/{object_id}/history")
def military_record_history(object_id: str, p: Principal = Depends(require_principal)):
    perms=_military_permissions(p)
    if not perms.intersection({"vault:military:audit","vault:military:records-admin"}):
        raise HTTPException(403,"Military chain of custody requires auditor or records-admin permission")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,name,military_branch,tracking_number,created_by,created_at,operation_location,
                                  deleted_at,deleted_by,delete_tracking_number
                           FROM vault_objects
                           WHERE id=%s AND protection_profile='VAULT-MIL'""", (object_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Military record not found")
            cur.execute("""SELECT seq,actor,action,object_id,detail,created_at
                           FROM vault_audit
                           WHERE object_id=%s
                           ORDER BY seq ASC""", (object_id,))
            events = cur.fetchall()
    return {
        "record": {
            "id": str(row["id"]),
            "tracking_number": row["tracking_number"],
            "name": row["name"],
            "branch": row["military_branch"] or "Joint Headquarters",
            "created_by": row["created_by"],
            "created_at": row["created_at"].isoformat() if hasattr(row["created_at"],"isoformat") else str(row["created_at"]),
            "operation_location": row["operation_location"],
            "deleted_at": row["deleted_at"].isoformat() if row["deleted_at"] and hasattr(row["deleted_at"],"isoformat") else (str(row["deleted_at"]) if row["deleted_at"] else None),
            "deleted_by": row["deleted_by"],
            "delete_tracking_number": row["delete_tracking_number"],
        },
        "events": [{
            "seq": e["seq"],
            "actor": e["actor"],
            "action": e["action"],
            "detail": e["detail"],
            "created_at": e["created_at"].isoformat() if hasattr(e["created_at"],"isoformat") else str(e["created_at"]),
        } for e in events],
    }

@app.post("/vault/military/records/{object_id}/transfer")
def transfer_military_record(object_id: str, req: MilitaryTransferRequest, request: Request, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:records-admin","Military record transfer",fresh_mfa=True)
    if req.to_branch not in MILITARY_BRANCHES:
        raise HTTPException(400, "Unknown destination military branch")
    transfer_tracking = _mil_tracking("XFER")
    origin = _request_origin(request, req.operation_location)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,name,military_branch,tracking_number,deleted_at
                           FROM vault_objects
                           WHERE id=%s AND protection_profile='VAULT-MIL'""", (object_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Military record not found")
            if row["deleted_at"] is not None:
                raise HTTPException(409, "Deleted military records cannot be transferred")
            from_branch = row["military_branch"] or "Joint Headquarters"
            if from_branch == req.to_branch:
                raise HTTPException(409, "Record is already assigned to that branch")
            cur.execute("""UPDATE vault_objects
                           SET military_branch=%s,operation_location=%s
                           WHERE id=%s""", (req.to_branch, origin["location"], object_id))
            append_audit(cur, p.subject, "military_record_transferred", object_id, {
                "record_tracking_number": row["tracking_number"],
                "transfer_tracking_number": transfer_tracking,
                "from_branch": from_branch,
                "to_branch": req.to_branch,
                "reason": req.reason,
                "where": origin,
            })
    sentinel_notified=_notify_sentinel(
        severity="medium",
        title="VAULT-MIL military record transferred",
        event_type="military_record_transferred",
        details=f"{row['tracking_number']} transferred {from_branch} -> {req.to_branch}; transfer {transfer_tracking}; actor {p.subject}",
        object_id=object_id,
        owner=p.subject,
    )
    return {
        "transferred": True,
        "sentinel_notified": sentinel_notified,
        "id": object_id,
        "record_tracking_number": row["tracking_number"],
        "transfer_tracking_number": transfer_tracking,
        "from_branch": from_branch,
        "to_branch": req.to_branch,
        "reason": req.reason,
        "where": origin,
    }

@app.delete("/vault/military/records/{object_id}")
def delete_military_record(object_id: str, request: Request, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:records-admin","Military record deletion",fresh_mfa=True)
    deletion_tracking = _mil_tracking("DEL")
    origin = _request_origin(request)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,name,military_branch,tracking_number,deleted_at
                           FROM vault_objects WHERE id=%s AND protection_profile='VAULT-MIL'""", (object_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Military record not found")
            if row["deleted_at"] is not None:
                raise HTTPException(409, "Military record is already deleted")
            cur.execute("""UPDATE vault_objects
                           SET deleted_at=now(),deleted_by=%s,delete_tracking_number=%s
                           WHERE id=%s""", (p.subject,deletion_tracking,object_id))
            append_audit(cur,p.subject,"military_record_deleted",object_id,{
                "record_tracking_number": row["tracking_number"],
                "delete_tracking_number": deletion_tracking,
                "military_branch": row["military_branch"],
                "record_name": row["name"],
                "where": origin,
            })
    sentinel_notified=_notify_sentinel(
        severity="high",
        title="VAULT-MIL military record deleted",
        event_type="military_record_deleted",
        details=f"{row['tracking_number']} soft-deleted; delete tracking {deletion_tracking}; branch {row['military_branch']}; actor {p.subject}",
        object_id=object_id,
        owner=p.subject,
    )
    return {"deleted": True, "sentinel_notified": sentinel_notified, "id": object_id, "record_tracking_number": row["tracking_number"],
            "delete_tracking_number": deletion_tracking, "deleted_by": p.subject, "where": origin}

@app.get("/vault/sentinel/outbox")
def sentinel_outbox_status(limit: int = 100, p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:audit","SENTINEL delivery status")
    limit=max(1,min(500,int(limit)))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT status,COUNT(*) AS n FROM sentinel_outbox GROUP BY status""")
            counts={row["status"]:int(row["n"]) for row in cur.fetchall()}
            cur.execute("""SELECT event_id,payload,status,attempts,last_attempt_at,next_attempt_at,delivered_at,last_error,
                                  sentinel_alert_id,sentinel_incident_id,created_at
                           FROM sentinel_outbox
                           ORDER BY created_at DESC LIMIT %s""",(limit,))
            rows=cur.fetchall()
    return {
        "counts":counts,
        "events":[{
            "event_id":row["event_id"],
            "event_type":(row["payload"] or {}).get("event_type"),
            "title":(row["payload"] or {}).get("title"),
            "severity":(row["payload"] or {}).get("severity"),
            "object_id":(row["payload"] or {}).get("object_id"),
            "status":row["status"],
            "attempts":row["attempts"],
            "last_attempt_at":row["last_attempt_at"].isoformat() if row["last_attempt_at"] else None,
            "next_attempt_at":row["next_attempt_at"].isoformat() if row["next_attempt_at"] else None,
            "delivered_at":row["delivered_at"].isoformat() if row["delivered_at"] else None,
            "last_error":row["last_error"],
            "sentinel_alert_id":row["sentinel_alert_id"],
            "sentinel_incident_id":row["sentinel_incident_id"],
            "created_at":row["created_at"].isoformat() if row["created_at"] else None,
        } for row in rows],
    }

@app.post("/vault/sentinel/outbox/retry")
def retry_sentinel_outbox(p: Principal = Depends(require_principal)):
    _require_military_permission(p,"vault:military:records-admin","SENTINEL outbox retry",fresh_mfa=True)
    delivered=_flush_sentinel_outbox(100)
    return {"retried":True,"delivered_now":delivered}

@app.get("/vault/military/access")
def military_access(p: Principal = Depends(require_principal)):
    perms=_military_permissions(p)
    return {
        "subject":p.subject,
        "permissions":sorted(perms & MILITARY_PERMISSIONS),
        "can_operate":"vault:military:operate" in perms,
        "can_approve":"vault:military:approve" in perms,
        "can_admin_records":"vault:military:records-admin" in perms,
        "can_audit":"vault:military:audit" in perms,
        "fresh_mfa":bool(p.claims.get("mfa")) and bool(p.claims.get("mfa_time")) and 0 <= (time.time()-float(p.claims.get("mfa_time") or 0)) <= 300,
    }

@app.get("/vault/military/summary")
def military_summary(p: Principal = Depends(require_principal)):
    perms=_military_permissions(p)
    if not perms.intersection({"vault:military:audit","vault:military:records-admin"}):
        raise HTTPException(403,"Military Vault summary requires auditor or records-admin permission")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM vault_objects WHERE protection_profile='VAULT-MIL' AND deleted_at IS NULL")
            protected_objects = int(cur.fetchone()["n"])
            cur.execute("""SELECT COUNT(*) AS n FROM vault_audit
                           WHERE action IN ('military_file_fully_encrypted','military_file_redacted_release','military_file_decrypted')""")
            file_events = int(cur.fetchone()["n"])
            cur.execute("""SELECT COUNT(*) AS n FROM vault_audit
                           WHERE action='military_file_redacted_release'""")
            redacted_releases = int(cur.fetchone()["n"])
            cur.execute("""SELECT COUNT(*) AS n FROM vault_audit
                           WHERE action='military_file_fully_encrypted'""")
            encrypted_files = int(cur.fetchone()["n"])
            cur.execute("""SELECT COALESCE(military_branch,'Joint Headquarters') AS branch,COUNT(*) AS n
                           FROM vault_objects
                           WHERE protection_profile='VAULT-MIL' AND deleted_at IS NULL
                           GROUP BY COALESCE(military_branch,'Joint Headquarters')
                           ORDER BY branch""")
            branch_counts = {row["branch"]: int(row["n"]) for row in cur.fetchall()}
            cur.execute("""UPDATE military_release_requests
                           SET status='expired'
                           WHERE status IN ('pending','approved') AND expires_at<=now()""")
            cur.execute("""SELECT status,COUNT(*) AS n FROM military_release_requests GROUP BY status""")
            release_counts = {row["status"]: int(row["n"]) for row in cur.fetchall()}
            cur.execute("""SELECT seq,actor,action,object_id,detail,created_at
                           FROM vault_audit
                           WHERE action LIKE 'military_%'
                           ORDER BY seq DESC LIMIT 25""")
            activity = cur.fetchall()
    return {
        "profile": "VAULT-MIL",
        "protected_objects": protected_objects,
        "branches": list(MILITARY_BRANCHES),
        "branch_counts": branch_counts,
        "encrypted_files": encrypted_files,
        "redacted_releases": redacted_releases,
        "file_events": file_events,
        "release_requests": {
            "pending": release_counts.get("pending", 0),
            "approved": release_counts.get("approved", 0),
            "consumed": release_counts.get("consumed", 0),
            "denied": release_counts.get("denied", 0),
            "cancelled": release_counts.get("cancelled", 0),
            "expired": release_counts.get("expired", 0),
        },
        "release_policy": {
            "full_encryption": True,
            "plaintext_export_allowed": False,
            "redaction_min_percent": MILITARY_MIN_REDACTION,
            "redaction_max_percent": MILITARY_MAX_REDACTION,
            "classification_floor": "restricted",
            "approvals_required": PROFILES["VAULT-MIL"].approvals_required,
            "minimum_tier": PROFILES["VAULT-MIL"].minimum_tier.name,
        },
        "recent_activity": [{
            "seq": row["seq"],
            "actor": row["actor"],
            "action": row["action"],
            "object_id": row["object_id"],
            "detail": row["detail"],
            "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
        } for row in activity],
    }


@app.get("/vault/profiles")
def vault_profiles(p: Principal = Depends(require_principal)):
    """UI registry for consistent VAULT badges and document markings."""
    return {"profiles": [
        {
            "code": code,
            "label": profile.label,
            "minimum_tier": profile.minimum_tier.name,
            "approvals_required": profile.approvals_required,
            "color": VAULT_DOCUMENT_COLORS[code],
        }
        for code, profile in PROFILES.items()
    ]}

@app.get("/vault/markings/{profile_code}/{document_id}")
def get_document_markings(profile_code: str, document_id: str, p: Principal = Depends(require_principal)):
    if profile_code not in PROFILES:
        raise HTTPException(404, "Unknown VAULT profile")
    return {
        "ui": marking_payload(profile_code, document_id),
        "pdf": pdf_marking(profile_code, document_id),
        "print": print_marking(profile_code, document_id),
    }

def _security_raise(cur, status_code: int, detail: str):
    """Persist security state/audit before returning an HTTP denial."""
    cur.connection.commit()
    raise HTTPException(status_code, detail)


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return __import__("base64").urlsafe_b64decode(text + padding)


def _validate_scif_device_jwk(jwk: dict) -> dict:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise HTTPException(400, "SCIF device key must be an EC P-256 public key")
    if not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
        raise HTTPException(400, "SCIF device public key is incomplete")
    try:
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except Exception as exc:
        raise HTTPException(400, "SCIF device public key is invalid") from exc
    return {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"], "ext": True}


def _verify_scif_device_proof(cur, request: Request, row) -> None:
    try:
        jwk = row.get("device_public_jwk")
        if not jwk:
            raise HTTPException(401, "SCIF session requires cryptographic device re-entry")
        timestamp = request.headers.get("x-ung-scif-time", "")
        signature_text = request.headers.get("x-ung-scif-proof", "")
        try:
            ts = int(timestamp)
        except Exception:
            raise HTTPException(401, "SCIF device proof timestamp required")
        now_s = int(utcnow().timestamp())
        if abs(now_s - ts) > 30:
            raise HTTPException(401, "SCIF device proof is stale")
        canonical = f"{request.method.upper()}\n{request.url.path}\n{timestamp}\n{row['id']}".encode("utf-8")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        raw = _b64url_decode(signature_text)
        if len(raw) != 64:
            raise HTTPException(403, "SCIF cryptographic device proof failed")
        rr = int.from_bytes(raw[:32], "big")
        ss = int.from_bytes(raw[32:], "big")
        pub.verify(encode_dss_signature(rr, ss), canonical, ec.ECDSA(hashes.SHA256()))
    except HTTPException as exc:
        _clear_scif_sensitive_state(
            cur, str(row["id"]), state="revoked", reason="cryptographic_device_proof_failed", close=True
        )
        append_audit(cur, row["owner"], "scif_crypto_device_proof_revoked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "reason": str(exc.detail),
        })
        _notify_sentinel(
            severity="critical",
            title="Digital SCIF cryptographic device proof failed",
            event_type="scif_crypto_device_proof_failed",
            details=str(exc.detail),
            session_id=str(row["id"]),
            object_id=str(row["object_id"]),
            owner=row["owner"],
        )
        _security_raise(cur, exc.status_code, str(exc.detail))
    except Exception:
        _clear_scif_sensitive_state(
            cur, str(row["id"]), state="revoked", reason="cryptographic_device_proof_failed", close=True
        )
        append_audit(cur, row["owner"], "scif_crypto_device_proof_revoked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "reason": "signature verification failed",
        })
        _notify_sentinel(
            severity="critical",
            title="Digital SCIF cryptographic device proof failed",
            event_type="scif_crypto_device_proof_failed",
            details="signature verification failed",
            session_id=str(row["id"]),
            object_id=str(row["object_id"]),
            owner=row["owner"],
        )
        _security_raise(cur, 403, "SCIF cryptographic device proof failed")


def _deliver_sentinel_outbox_event(event_id: str) -> bool:
    if not SENTINEL_BASE_URL or not SENTINEL_INGEST_SECRET:
        return False
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT event_id,payload,status,attempts
                           FROM sentinel_outbox
                           WHERE event_id=%s FOR UPDATE""",(event_id,))
            row=cur.fetchone()
            if not row:
                return False
            if row["status"]=="delivered":
                return True
            payload=dict(row["payload"])
    payload["sent_at"]=utcnow().isoformat()
    payload["nonce"]=secrets.token_urlsafe(24)
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    signature=hmac.new(SENTINEL_INGEST_SECRET.encode("utf-8"),raw,hashlib.sha256).hexdigest()
    req=urllib.request.Request(
        SENTINEL_BASE_URL+"/v1/ingest/vault",
        data=raw,
        headers={"Content-Type":"application/json","X-UNG-VAULT-Signature":signature},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req,timeout=3) as resp:
            body=json.loads(resp.read().decode("utf-8") or "{}")
            ok=200 <= resp.status < 300
        if ok:
            alert_id=str(body.get("id") or body.get("alert_id") or "") or None
            incident=body.get("incident")
            incident_id=str((incident or {}).get("id") or "") or None if isinstance(incident,dict) else None
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""UPDATE sentinel_outbox
                                   SET status='delivered',attempts=attempts+1,last_attempt_at=now(),
                                       delivered_at=now(),last_error=NULL,
                                       sentinel_alert_id=%s,sentinel_incident_id=%s
                                   WHERE event_id=%s""",(alert_id,incident_id,event_id))
            return True
    except Exception as exc:
        err=(type(exc).__name__+": "+str(exc))[:500]
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE sentinel_outbox
                           SET status='retrying',attempts=attempts+1,last_attempt_at=now(),
                               next_attempt_at=now() + LEAST(interval '30 seconds' * GREATEST(attempts+1,1), interval '15 minutes'),
                               last_error=%s
                           WHERE event_id=%s""",(err,event_id))
    return False

def _flush_sentinel_outbox(limit: int = 25) -> int:
    if not SENTINEL_BASE_URL or not SENTINEL_INGEST_SECRET:
        return 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT event_id FROM sentinel_outbox
                           WHERE status IN ('pending','retrying') AND next_attempt_at<=now()
                           ORDER BY created_at ASC LIMIT %s""",(max(1,min(100,int(limit))),))
            event_ids=[str(r["event_id"]) for r in cur.fetchall()]
    delivered=0
    for eid in event_ids:
        if _deliver_sentinel_outbox_event(eid):
            delivered+=1
    return delivered

def _sentinel_outbox_worker() -> None:
    while True:
        try:
            _flush_sentinel_outbox()
        except Exception:
            pass
        time.sleep(SENTINEL_OUTBOX_POLL_SECONDS)

def _notify_sentinel(*, severity: str, title: str, event_type: str, details: str = "", session_id: str | None = None, object_id: str | None = None, owner: str | None = None) -> bool:
    stable_basis="|".join([
        event_type or "",
        object_id or "",
        session_id or "",
        owner or "",
        title or "",
        details or "",
    ]).encode("utf-8")
    event_id="vault-"+hashlib.sha256(stable_basis).hexdigest()[:40]
    payload={
        "source":"UNG-VAULT",
        "severity":severity,
        "title":title,
        "details":details,
        "event_type":event_type,
        "session_id":session_id,
        "object_id":object_id,
        "owner":owner,
        "event_id":event_id,
    }
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO sentinel_outbox(event_id,payload,status,next_attempt_at)
                               VALUES(%s,%s::jsonb,'pending',now())
                               ON CONFLICT (event_id) DO NOTHING""",(event_id,json.dumps(payload)))
    except Exception:
        return False
    return _deliver_sentinel_outbox_event(event_id)


def _sentinel_signed_probe() -> bool:
    if not SENTINEL_BASE_URL or not SENTINEL_INGEST_SECRET:
        return False
    payload = {
        "source": "UNG-VAULT",
        "severity": "low",
        "title": "VAULT-SENTINEL signed channel probe",
        "details": "",
        "event_type": "integration_probe",
        "session_id": None,
        "object_id": None,
        "owner": None,
        "sent_at": utcnow().isoformat(),
        "nonce": secrets.token_urlsafe(24),
        "event_id": "probe-" + secrets.token_urlsafe(18),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(SENTINEL_INGEST_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        SENTINEL_BASE_URL + "/v1/ingest/vault/probe",
        data=raw,
        headers={"Content-Type": "application/json", "X-UNG-VAULT-Signature": signature},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _clear_scif_sensitive_state(cur, session_id: str, *, state: str | None = None, reason: str | None = None, close: bool = False):
    fields = [
        "auth_envelope=NULL",
        "cookie_hash=NULL",
        "device_binding_hash=NULL",
        "device_claim=NULL",
        "approved_by='[]'::jsonb",
        "approved_at='{}'::jsonb",
        "failed_entry_attempts=0",
        "failed_cookie_attempts=0",
        "device_public_jwk=NULL",
    ]
    params = []
    if state is not None:
        fields.append("state=%s")
        params.append(state)
    if reason is not None:
        fields.append("revoked_reason=%s")
        params.append(reason)
    if close:
        fields.append("closed_at=COALESCE(closed_at,now())")
    params.append(session_id)
    cur.execute(f"UPDATE vault_scif_sessions SET {','.join(fields)} WHERE id=%s", tuple(params))


def _record_scif_auth_failure(cur, row, *, kind: str, actor: str, action: str):
    if kind == "entry":
        column = "failed_entry_attempts"
        limit = SCIF_MAX_ENTRY_FAILURES
    elif kind == "cookie":
        column = "failed_cookie_attempts"
        limit = SCIF_MAX_COOKIE_FAILURES
    else:
        raise ValueError("invalid SCIF failure counter")

    cur.execute(
        f"UPDATE vault_scif_sessions SET {column}={column}+1 WHERE id=%s RETURNING {column}",
        (str(row["id"]),),
    )
    attempts = int(cur.fetchone()[column])
    append_audit(cur, actor, action, str(row["object_id"]), {
        "session_id": str(row["id"]),
        "attempt": attempts,
        "limit": limit,
    })
    if attempts >= limit:
        cur.execute(
            """UPDATE vault_scif_sessions
               SET state='revoked',
                   closed_at=COALESCE(closed_at,now()),
                   revoked_reason='authentication_failure_limit',
                   auth_envelope=NULL,
                   cookie_hash=NULL,
                   device_binding_hash=NULL,
                   device_claim=NULL,
                   device_public_jwk=NULL,
                   approved_by='[]'::jsonb,
                   approved_at='{}'::jsonb
               WHERE id=%s""",
            (str(row["id"]),),
        )
        append_audit(cur, actor, "scif_auth_failure_limit_reached", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "kind": kind,
            "attempts": attempts,
        })
        _notify_sentinel(
            severity="critical",
            title="Digital SCIF authentication failure limit reached",
            event_type="scif_auth_failure_limit",
            details=f"{kind} failures reached {attempts}",
            session_id=str(row["id"]),
            object_id=str(row["object_id"]),
            owner=row["owner"],
        )
        _security_raise(cur, 423, "SCIF session revoked after repeated authentication failures")
    return attempts


def _require_scif_revoke_authority(p: Principal, system_wide: bool) -> None:
    roles = {str(x) for x in p.claims.get("roles", [])}
    permissions = {str(x) for x in p.claims.get("permissions", [])}
    if system_wide:
        if "platform-admin" not in roles and "vault:scif:revoke-all" not in permissions:
            raise HTTPException(403, "System-wide SCIF revocation requires platform-admin authority")
    elif (
        "platform-admin" not in roles
        and "security-admin" not in roles
        and "vault:scif:revoke" not in permissions
        and "vault:scif:revoke-all" not in permissions
    ):
        raise HTTPException(403, "SCIF revocation authority required")


def _janus_device_claim(p: Principal) -> str:
    for key in ("device_id", "device", "device_uuid", "trusted_device_id"):
        value = p.claims.get(key)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    return ""


def _request_device_binding(request: Request, janus_device: str) -> str:
    # Bind to the trusted JANUS device identity when available and to stable
    # browser/device signals. Deliberately exclude IP so roaming/VPN changes
    # do not terminate a legitimate SCIF session.
    pieces = [
        janus_device,
        request.headers.get("user-agent", ""),
        request.headers.get("sec-ch-ua", ""),
        request.headers.get("sec-ch-ua-platform", ""),
        request.headers.get("accept-language", ""),
    ]
    return hashlib.sha256("\n".join(pieces).encode("utf-8")).hexdigest()


def _enforce_device_binding(cur, row, request: Request, current: Principal | None = None):
    expected = row.get("device_binding_hash")
    if not expected:
        raise HTTPException(401, "SCIF session requires device-bound re-entry")
    principal = current
    if principal is None:
        envelope = row.get("auth_envelope")
        if not envelope:
            raise HTTPException(401, "SCIF session requires re-entry")
        authorization = decrypt_bytes(envelope, str(row["id"]).encode()).decode("utf-8")
        principal = principal_from_authorization(authorization)
    current_claim = _janus_device_claim(principal)
    stored_claim = row.get("device_claim") or ""
    if stored_claim and current_claim and not secrets.compare_digest(stored_claim, current_claim):
        _clear_scif_sensitive_state(
            cur, str(row["id"]), state="revoked", reason="device_identity_changed", close=True
        )
        append_audit(cur, row["owner"], "scif_device_binding_revoked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "reason": "JANUS device identity changed",
        })
        _notify_sentinel(
            severity="critical",
            title="Digital SCIF device identity changed",
            event_type="scif_device_identity_changed",
            details="JANUS device identity changed during an active SCIF session",
            session_id=str(row["id"]),
            object_id=str(row["object_id"]),
            owner=row["owner"],
        )
        _security_raise(cur, 403, "SCIF device identity changed")
    actual = _request_device_binding(request, current_claim or stored_claim)
    if not secrets.compare_digest(expected, actual):
        _clear_scif_sensitive_state(
            cur, str(row["id"]), state="revoked", reason="device_binding_mismatch", close=True
        )
        append_audit(cur, row["owner"], "scif_device_binding_revoked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "reason": "request device binding mismatch",
        })
        _notify_sentinel(
            severity="high",
            title="Digital SCIF browser/device binding mismatch",
            event_type="scif_device_binding_mismatch",
            details="Active SCIF request no longer matched the bound browser/device context",
            session_id=str(row["id"]),
            object_id=str(row["object_id"]),
            owner=row["owner"],
        )
        _security_raise(cur, 403, "SCIF session is bound to a different device/browser")


def _fresh_scif_approvals(row):
    approved = list(row.get("approved_by") or [])
    approved_at = dict(row.get("approved_at") or {})
    fresh = []
    now = utcnow()
    for subject in approved:
        raw = approved_at.get(subject)
        if not raw:
            continue
        try:
            ts = __import__("datetime").datetime.fromisoformat(str(raw))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=__import__("datetime").timezone.utc)
        except Exception:
            continue
        if (now - ts).total_seconds() <= SCIF_APPROVAL_TTL_SECONDS:
            fresh.append(subject)
    return fresh


def _supersede_other_scif_sessions(cur, owner: str, keep_session_id: str):
    """Allow only one live SCIF session per identity at a time."""
    cur.execute(
        """UPDATE vault_scif_sessions
           SET state='revoked',
               closed_at=COALESCE(closed_at,now()),
               revoked_reason='superseded_by_new_scif_session',
               auth_envelope=NULL,
               cookie_hash=NULL,
               device_binding_hash=NULL,
               device_claim=NULL,
               device_public_jwk=NULL
           WHERE owner=%s
             AND id<>%s
             AND state IN ('active','locked')
           RETURNING id,object_id""",
        (owner, keep_session_id),
    )
    rows = cur.fetchall()
    for old in rows:
        append_audit(cur, owner, "scif_session_superseded", str(old["object_id"]), {
            "old_session_id": str(old["id"]),
            "replacement_session_id": keep_session_id,
        })
    return [str(x["id"]) for x in rows]


def _enforce_scif_idle(cur, row):
    last = row.get("last_verified_at") or row.get("opened_at")
    if not last:
        return
    idle_seconds = (utcnow() - last).total_seconds()
    if idle_seconds > SCIF_IDLE_SECONDS:
        if row.get("mode") == "scif_two_person":
            cur.execute(
                "UPDATE vault_scif_sessions SET state='pending',approved_by='[]'::jsonb,approved_at='{}'::jsonb,auth_envelope=NULL,device_binding_hash=NULL,device_claim=NULL,revoked_reason='idle_timeout',cookie_hash=NULL,device_public_jwk=NULL WHERE id=%s",
                (str(row["id"]),),
            )
        else:
            cur.execute(
                "UPDATE vault_scif_sessions SET state='locked',auth_envelope=NULL,device_binding_hash=NULL,device_claim=NULL,revoked_reason='idle_timeout',cookie_hash=NULL,device_public_jwk=NULL WHERE id=%s",
                (str(row["id"]),),
            )
        append_audit(cur, row["owner"], "scif_idle_locked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "idle_seconds": int(idle_seconds),
            "idle_limit_seconds": SCIF_IDLE_SECONDS,
        })
        if row.get("mode") == "scif_two_person":
            _security_raise(cur, 423, "SCIF session locked after inactivity; fresh independent approvals required")
        _security_raise(cur, 423, "SCIF session locked after inactivity; re-entry required")


def _continuous_scif_check(cur, row):
    """Re-validate the viewer against JANUS before exposing SCIF plaintext."""
    envelope = row.get("auth_envelope")
    if not envelope:
        raise HTTPException(401, "SCIF session requires re-entry")
    try:
        authorization = decrypt_bytes(envelope, str(row["id"]).encode()).decode("utf-8")
        current = principal_from_authorization(authorization)
        if current.subject != row["owner"]:
            raise HTTPException(403, "SCIF identity changed")
        require_scif_entitlement(current)
        require_trusted_device(current)
        require_fresh_mfa(current)
        authorize(current, row["classification"], row["compartment"])
    except HTTPException as exc:
        # Identity/authorization failures revoke the active SCIF. Temporary JANUS
        # availability failures fail closed without permanently revoking the session.
        if exc.status_code != 503:
            _clear_scif_sensitive_state(
                cur, str(row["id"]), state="revoked", reason=str(exc.detail), close=True
            )
            append_audit(cur, row["owner"], "scif_continuous_auth_revoked", str(row["object_id"]), {
                "session_id": str(row["id"]),
                "reason": str(exc.detail),
            })
            _notify_sentinel(
                severity="high",
                title="Digital SCIF continuous authorization revoked",
                event_type="scif_continuous_auth_revoked",
                details=str(exc.detail),
                session_id=str(row["id"]),
                object_id=str(row["object_id"]),
                owner=row["owner"],
            )
            cur.connection.commit()
        raise
    cur.execute("UPDATE vault_scif_sessions SET last_verified_at=now() WHERE id=%s", (str(row["id"]),))
    return current

@app.post("/vault/scif/sessions")
def create_scif_session(req: ScifSessionRequest, p: Principal = Depends(require_principal)):
    require_scif_entitlement(p)
    require_trusted_device(p)
    require_fresh_mfa(p)
    if req.mode not in SCIF_MODES:
        raise HTTPException(400, "Invalid SCIF mode")
    minutes = session_minutes(req.duration_minutes)
    try:
        object_uuid = str(uuid.UUID(req.object_id))
    except Exception:
        raise HTTPException(400, "Invalid object ID") from None

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,compartment,classification FROM vault_objects WHERE id=%s", (object_uuid,))
            obj = cur.fetchone()
            if not obj:
                raise HTTPException(404, "Object not found")
            authorize(p, obj["classification"], obj["compartment"])
            if obj["classification"] not in SCIF_REQUIRED_CLASSIFICATIONS:
                raise HTTPException(400, "SCIF mode is reserved for restricted or top-secret objects")

            session_id = str(uuid.uuid4())
            token = new_session_token()
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            approvals_required = int(SCIF_MODES[req.mode]["approvals_required"])
            state = "active" if approvals_required == 0 else "pending"
            expires_at = utcnow() + __import__("datetime").timedelta(minutes=minutes)
            cur.execute(
                """INSERT INTO vault_scif_sessions
                   (id,object_id,owner,mode,state,approvals_required,approved_by,token_hash,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,'[]'::jsonb,%s,%s)""",
                (session_id, object_uuid, p.subject, req.mode, state, approvals_required, token_hash, expires_at),
            )
            append_audit(cur, p.subject, "scif_session_created", object_uuid, {
                "session_id": session_id,
                "mode": req.mode,
                "approvals_required": approvals_required,
                "duration_minutes": minutes,
                "state": state,
            })
    return {
        "session_id": session_id,
        "session_token": token,
        "state": state,
        "mode": req.mode,
        "approvals_required": approvals_required,
        "expires_at": expires_at.isoformat(),
        "notice": "Session token is shown once. Keep it inside the authenticated VAULT workflow.",
    }

@app.post("/vault/scif/sessions/{session_id}/approve")
def approve_scif_session(session_id: str, p: Principal = Depends(require_principal)):
    require_scif_entitlement(p)
    require_trusted_device(p)
    require_fresh_mfa(p)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM vault_scif_sessions WHERE id=%s FOR UPDATE", (session_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if row["expires_at"] <= utcnow() or row["state"] in {"closed", "revoked", "expired"}:
                raise HTTPException(409, "SCIF session is no longer approvable")
            if p.subject == row["owner"]:
                raise HTTPException(403, "Session owner cannot approve their own SCIF request")
            cur.execute("SELECT compartment,classification FROM vault_objects WHERE id=%s", (row["object_id"],))
            obj = cur.fetchone()
            authorize(p, obj["classification"], obj["compartment"])
            approved = list(row["approved_by"] or [])
            approved_at = dict(row.get("approved_at") or {})
            if p.subject not in approved:
                approved.append(p.subject)
            approved_at[p.subject] = utcnow().isoformat()
            temp = dict(row)
            temp["approved_by"] = approved
            temp["approved_at"] = approved_at
            fresh = _fresh_scif_approvals(temp)
            state = "active" if approval_count(fresh) >= int(row["approvals_required"]) else "pending"
            cur.execute("UPDATE vault_scif_sessions SET approved_by=%s::jsonb,approved_at=%s::jsonb,state=%s WHERE id=%s",
                        (json.dumps(approved), json.dumps(approved_at), state, session_id))
            append_audit(cur, p.subject, "scif_session_approved", str(row["object_id"]), {
                "session_id": session_id,
                "approvals": len(fresh),
                "approvals_required": int(row["approvals_required"]),
                "approval_ttl_seconds": SCIF_APPROVAL_TTL_SECONDS,
                "state": state,
            })
            return {"session_id": session_id, "state": state, "approvals": len(fresh), "approvals_required": int(row["approvals_required"]), "approval_ttl_seconds": SCIF_APPROVAL_TTL_SECONDS}

@app.get("/vault/scif/sessions/{session_id}")
def scif_session_status(session_id: str, p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,object_id,owner,mode,state,approvals_required,approved_by,approved_at,expires_at,created_at,opened_at,closed_at FROM vault_scif_sessions WHERE id=%s", (session_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if p.subject != row["owner"]:
                require_scif_entitlement(p)
            state = row["state"]
            if row["expires_at"] <= utcnow() and state not in {"closed","revoked","expired"}:
                state = "expired"
                _clear_scif_sensitive_state(cur, session_id, state="expired", reason="expired", close=True)
            return {
                "session_id": str(row["id"]),
                "object_id": str(row["object_id"]),
                "owner": row["owner"],
                "mode": row["mode"],
                "state": state,
                "approvals": approval_count(_fresh_scif_approvals(row)),
                "approvals_required": int(row["approvals_required"]),
                "expires_at": row["expires_at"].isoformat(),
                "opened_at": row["opened_at"].isoformat() if row["opened_at"] else None,
                "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
            }

@app.post("/vault/scif/sessions/{session_id}/enter")
def enter_scif_session(
    req: ScifEnterRequest,
    session_id: str,
    request: Request,
    p: Principal = Depends(require_principal),
    authorization: str = Header(None),
):
    require_scif_entitlement(p)
    require_trusted_device(p)
    require_fresh_mfa(p)
    token_hash = hashlib.sha256(req.session_token.encode()).hexdigest()
    device_jwk = _validate_scif_device_jwk(req.device_public_jwk)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM vault_scif_sessions WHERE id=%s FOR UPDATE", (session_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if p.subject != row["owner"]:
                raise HTTPException(403, "Only the session owner may enter this SCIF session")
            if row["expires_at"] <= utcnow():
                _clear_scif_sensitive_state(cur, session_id, state="expired", reason="expired", close=True)
                _security_raise(cur, 410, "SCIF session expired")
            if row["mode"] == "scif_two_person":
                fresh = _fresh_scif_approvals(row)
                if approval_count(fresh) < int(row["approvals_required"]):
                    cur.execute("UPDATE vault_scif_sessions SET state='pending' WHERE id=%s", (session_id,))
                    _security_raise(cur, 409, "Fresh two-person approvals required before SCIF entry")
            if row["state"] not in {"active", "locked"}:
                raise HTTPException(409, "SCIF session is not enterable")
            if not secrets.compare_digest(token_hash, row["token_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="entry", actor=p.subject, action="scif_enter_denied"
                )
                _security_raise(cur, 403, "Invalid SCIF session token")
            superseded = _supersede_other_scif_sessions(cur, p.subject, session_id)
            scif_authorization = exchange_scif_handle(authorization)
            auth_envelope = encrypt_bytes(scif_authorization.encode("utf-8"), session_id.encode())
            device_claim = _janus_device_claim(p)
            device_binding_hash = _request_device_binding(request, device_claim)
            cookie_secret = new_session_token()
            cookie_hash = hashlib.sha256(cookie_secret.encode()).hexdigest()
            cur.execute(
                "UPDATE vault_scif_sessions SET state='active',opened_at=COALESCE(opened_at,now()),auth_envelope=%s::jsonb,last_verified_at=now(),revoked_reason=NULL,device_binding_hash=%s,device_claim=%s,cookie_hash=%s,failed_entry_attempts=0,failed_cookie_attempts=0,device_public_jwk=%s::jsonb WHERE id=%s",
                (json.dumps(auth_envelope), device_binding_hash, device_claim, cookie_hash, json.dumps(device_jwk), session_id),
            )
            append_audit(cur, p.subject, "scif_entered", str(row["object_id"]), {
                "session_id": session_id,
                "mode": row["mode"],
                "continuous_authorization": True,
                "janus_scoped_handle": True,
                "cryptographic_device_binding": True,
                "device_bound": True,
                "janus_device_claim": bool(device_claim),
                "browser_secret_rotated": True,
                "superseded_session_count": len(superseded),
            })
    remaining_seconds = max(1, int((row["expires_at"] - utcnow()).total_seconds()))
    resp = Response(status_code=204)
    resp.set_cookie(
        "UNG_SCIF_SESSION",
        f"{session_id}:{cookie_secret}",
        max_age=remaining_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/vault/scif/",
    )
    return resp

@app.get("/vault/scif/view/{session_id}", response_class=Response)
def view_scif_session(
    session_id: str,
    request: Request,
    ung_scif_session: str | None = Cookie(default=None, alias="UNG_SCIF_SESSION"),
):
    if not ung_scif_session or ":" not in ung_scif_session:
        raise HTTPException(401, "SCIF session cookie required")
    cookie_session, token = ung_scif_session.split(":", 1)
    if cookie_session != session_id:
        raise HTTPException(403, "SCIF session mismatch")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT s.*,o.name,o.compartment,o.classification,o.envelope
                   FROM vault_scif_sessions s JOIN vault_objects o ON o.id=s.object_id
                   WHERE s.id=%s FOR UPDATE""",
                (session_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if row["expires_at"] <= utcnow():
                _clear_scif_sensitive_state(cur, session_id, state="expired", reason="expired", close=True)
                _security_raise(cur, 410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_view_denied"
                )
                _security_raise(cur, 403, "Invalid SCIF session")
            if row.get("failed_cookie_attempts"):
                cur.execute("UPDATE vault_scif_sessions SET failed_cookie_attempts=0 WHERE id=%s", (session_id,))
            current = _continuous_scif_check(cur, row)
            _enforce_device_binding(cur, row, request, current)
            append_audit(cur, row["owner"], "scif_view_shell_opened", str(row["object_id"]), {"session_id": session_id})
            return render_scif_view(
                session_id=session_id,
                viewer=row["owner"],
                classification=row["classification"],
                compartment=row["compartment"],
                name=row["name"],
                expires_at=row["expires_at"],
            )

@app.get("/vault/scif/render/{session_id}.png")
def render_scif_document(
    session_id: str,
    request: Request,
    ung_scif_session: str | None = Cookie(default=None, alias="UNG_SCIF_SESSION"),
):
    if not ung_scif_session or ":" not in ung_scif_session:
        raise HTTPException(401, "SCIF session cookie required")
    cookie_session, token = ung_scif_session.split(":", 1)
    if cookie_session != session_id:
        raise HTTPException(403, "SCIF session mismatch")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT s.*,o.name,o.compartment,o.classification,o.envelope
                   FROM vault_scif_sessions s JOIN vault_objects o ON o.id=s.object_id
                   WHERE s.id=%s FOR UPDATE""",
                (session_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if row["expires_at"] <= utcnow():
                _clear_scif_sensitive_state(cur, session_id, state="expired", reason="expired", close=True)
                _security_raise(cur, 410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_render_denied"
                )
                _security_raise(cur, 403, "Invalid SCIF session")
            if row.get("failed_cookie_attempts"):
                cur.execute("UPDATE vault_scif_sessions SET failed_cookie_attempts=0 WHERE id=%s", (session_id,))
            current = _continuous_scif_check(cur, row)
            _enforce_device_binding(cur, row, request, current)
            _verify_scif_device_proof(cur, request, row)
            try:
                value = decrypt_bytes(row["envelope"], str(row["object_id"]).encode()).decode()
                pixels = render_scif_image(
                    value=value,
                    viewer=row["owner"],
                    session_id=session_id,
                    classification=row["classification"],
                    compartment=row["compartment"],
                )
            except HTTPException:
                raise
            except Exception:
                append_audit(cur, row["owner"], "scif_render_failed", str(row["object_id"]), {"session_id": session_id})
                _security_raise(cur, 409, "SCIF document render failed")
            append_audit(cur, row["owner"], "scif_document_rasterized", str(row["object_id"]), {"session_id": session_id})
            return Response(
                pixels,
                media_type="image/png",
                headers={
                    "Cache-Control": "no-store, max-age=0",
                    "Pragma": "no-cache",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Disposition": "inline",
                    "X-UNG-VAULT-SCIF": session_id,
                },
            )


@app.get("/vault/scif/heartbeat/{session_id}")
def scif_heartbeat(
    session_id: str,
    request: Request,
    ung_scif_session: str | None = Cookie(default=None, alias="UNG_SCIF_SESSION"),
):
    if not ung_scif_session or ":" not in ung_scif_session:
        raise HTTPException(401, "SCIF session cookie required")
    cookie_session, token = ung_scif_session.split(":", 1)
    if cookie_session != session_id:
        raise HTTPException(403, "SCIF session mismatch")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT s.*,o.compartment,o.classification
                   FROM vault_scif_sessions s JOIN vault_objects o ON o.id=s.object_id
                   WHERE s.id=%s FOR UPDATE""",
                (session_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            if row["expires_at"] <= utcnow():
                _clear_scif_sensitive_state(cur, session_id, state="expired", reason="expired", close=True)
                _security_raise(cur, 410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_heartbeat_denied"
                )
                _security_raise(cur, 403, "Invalid SCIF session")
            if row.get("failed_cookie_attempts"):
                cur.execute("UPDATE vault_scif_sessions SET failed_cookie_attempts=0 WHERE id=%s", (session_id,))
            current = _continuous_scif_check(cur, row)
            _enforce_device_binding(cur, row, request, current)
            _verify_scif_device_proof(cur, request, row)
            return Response(
                content=json.dumps({"active": True, "verified_at": utcnow().isoformat()}),
                media_type="application/json",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

@app.post("/vault/scif/emergency-revoke")
def emergency_revoke_scif(
    req: ScifEmergencyRevokeRequest,
    p: Principal = Depends(require_principal),
):
    require_trusted_device(p)
    require_fresh_mfa(p)
    system_wide = not bool(req.owner)
    _require_scif_revoke_authority(p, system_wide)

    with connect() as conn:
        with conn.cursor() as cur:
            if req.owner:
                cur.execute(
                    """UPDATE vault_scif_sessions
                       SET state='revoked',
                           closed_at=COALESCE(closed_at,now()),
                           revoked_reason=%s,
                           auth_envelope=NULL,
                           cookie_hash=NULL,
                           device_binding_hash=NULL,
                           device_claim=NULL,
                           approved_by='[]'::jsonb,
                           approved_at='{}'::jsonb
                       WHERE owner=%s
                         AND state IN ('pending','active','locked')
                       RETURNING id,object_id,owner""",
                    (f"emergency:{req.reason}", req.owner),
                )
            else:
                cur.execute(
                    """UPDATE vault_scif_sessions
                       SET state='revoked',
                           closed_at=COALESCE(closed_at,now()),
                           revoked_reason=%s,
                           auth_envelope=NULL,
                           cookie_hash=NULL,
                           device_binding_hash=NULL,
                           device_claim=NULL,
                           approved_by='[]'::jsonb,
                           approved_at='{}'::jsonb
                       WHERE state IN ('pending','active','locked')
                       RETURNING id,object_id,owner""",
                    (f"emergency:{req.reason}",),
                )
            rows = cur.fetchall()
            for row in rows:
                append_audit(cur, p.subject, "scif_emergency_revoked", str(row["object_id"]), {
                    "session_id": str(row["id"]),
                    "owner": row["owner"],
                    "scope": "owner" if req.owner else "system",
                    "reason": req.reason,
                })
            append_audit(cur, p.subject, "scif_emergency_revoke_executed", detail={
                "scope": "owner" if req.owner else "system",
                "owner": req.owner,
                "revoked_sessions": len(rows),
                "reason": req.reason,
            })
            _notify_sentinel(
                severity="critical",
                title="Digital SCIF emergency revocation executed",
                event_type="scif_emergency_revoke",
                details=f"scope={'owner' if req.owner else 'system'}; revoked={len(rows)}; reason={req.reason}",
                owner=req.owner,
            )
            return {
                "revoked_sessions": len(rows),
                "scope": "owner" if req.owner else "system",
                "owner": req.owner,
                "reason": req.reason,
            }


@app.post("/vault/scif/sessions/{session_id}/close")
def close_scif_session(session_id: str, p: Principal = Depends(require_principal)):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM vault_scif_sessions WHERE id=%s FOR UPDATE", (session_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SCIF session not found")
            roles = {str(x) for x in p.claims.get("roles", [])}
            if p.subject != row["owner"] and "platform-admin" not in roles and "security-admin" not in roles:
                raise HTTPException(403, "Not authorized to close this SCIF session")
            state = "revoked" if p.subject != row["owner"] else "closed"
            _clear_scif_sensitive_state(cur, session_id, state=state, reason=("administrative_revoke" if state == "revoked" else "closed"), close=True)
            append_audit(cur, p.subject, "scif_session_" + state, str(row["object_id"]), {"session_id": session_id})
    resp = Response(status_code=204)
    resp.delete_cookie("UNG_SCIF_SESSION", path="/vault/scif/")
    return resp

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
