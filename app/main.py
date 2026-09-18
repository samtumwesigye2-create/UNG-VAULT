import json, uuid, os, hashlib, secrets
from pathlib import Path
from urllib.parse import urlsplit, quote
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, Cookie, Header, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
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

class ScifSessionRequest(BaseModel):
    object_id: str
    mode: str = "scif"
    duration_minutes: int = 30

class ScifEnterRequest(BaseModel):
    session_token: str = Field(min_length=20, max_length=256)

class ScifEmergencyRevokeRequest(BaseModel):
    owner: str | None = Field(default=None, max_length=256)
    reason: str = Field(min_length=3, max_length=500)

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
    return {"status":"ok","service":"UNG-VAULT","version":"1.1.0"}

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
    return {"id":object_id,"name":req.name,"marking": marking_payload(req.classification, object_id) if req.classification in PROFILES else None}

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
            return {"id":str(row["id"]),"name":row["name"],"compartment":row["compartment"],"classification":row["classification"],"value":value,"marking": marking_payload(row["classification"], str(row["id"])) if row["classification"] in PROFILES else None}

MAX_FILE_BYTES = int(os.getenv("VAULT_MAX_FILE_BYTES", str(25 * 1024 * 1024)))
FILE_MAGIC = b"UNGVAULT1\n"
SCIF_IDLE_SECONDS = max(30, min(900, int(os.getenv("VAULT_SCIF_IDLE_SECONDS", "90"))))
SCIF_APPROVAL_TTL_SECONDS = max(60, min(900, int(os.getenv("VAULT_SCIF_APPROVAL_TTL_SECONDS", "300"))))
SCIF_MAX_ENTRY_FAILURES = max(3, min(10, int(os.getenv("VAULT_SCIF_MAX_ENTRY_FAILURES", "5"))))
SCIF_MAX_COOKIE_FAILURES = max(2, min(10, int(os.getenv("VAULT_SCIF_MAX_COOKIE_FAILURES", "3"))))

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
        raise HTTPException(423, "SCIF session revoked after repeated authentication failures")
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
        raise HTTPException(403, "SCIF device identity changed")
    actual = _request_device_binding(request, current_claim or stored_claim)
    if not secrets.compare_digest(expected, actual):
        _clear_scif_sensitive_state(
            cur, str(row["id"]), state="revoked", reason="device_binding_mismatch", close=True
        )
        append_audit(cur, row["owner"], "scif_device_binding_revoked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "reason": "request device binding mismatch",
        })
        raise HTTPException(403, "SCIF session is bound to a different device/browser")


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
               device_claim=NULL
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
                "UPDATE vault_scif_sessions SET state='pending',approved_by='[]'::jsonb,approved_at='{}'::jsonb,auth_envelope=NULL,device_binding_hash=NULL,device_claim=NULL,revoked_reason='idle_timeout',cookie_hash=NULL WHERE id=%s",
                (str(row["id"]),),
            )
        else:
            cur.execute(
                "UPDATE vault_scif_sessions SET state='locked',auth_envelope=NULL,device_binding_hash=NULL,device_claim=NULL,revoked_reason='idle_timeout',cookie_hash=NULL WHERE id=%s",
                (str(row["id"]),),
            )
        append_audit(cur, row["owner"], "scif_idle_locked", str(row["object_id"]), {
            "session_id": str(row["id"]),
            "idle_seconds": int(idle_seconds),
            "idle_limit_seconds": SCIF_IDLE_SECONDS,
        })
        if row.get("mode") == "scif_two_person":
            raise HTTPException(423, "SCIF session locked after inactivity; fresh independent approvals required")
        raise HTTPException(423, "SCIF session locked after inactivity; re-entry required")


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
            if obj["classification"] not in {"restricted", "top_secret"}:
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
                raise HTTPException(410, "SCIF session expired")
            if row["mode"] == "scif_two_person":
                fresh = _fresh_scif_approvals(row)
                if approval_count(fresh) < int(row["approvals_required"]):
                    cur.execute("UPDATE vault_scif_sessions SET state='pending' WHERE id=%s", (session_id,))
                    raise HTTPException(409, "Fresh two-person approvals required before SCIF entry")
            if row["state"] not in {"active", "locked"}:
                raise HTTPException(409, "SCIF session is not enterable")
            if not secrets.compare_digest(token_hash, row["token_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="entry", actor=p.subject, action="scif_enter_denied"
                )
                raise HTTPException(403, "Invalid SCIF session token")
            superseded = _supersede_other_scif_sessions(cur, p.subject, session_id)
            scif_authorization = exchange_scif_handle(authorization)
            auth_envelope = encrypt_bytes(scif_authorization.encode("utf-8"), session_id.encode())
            device_claim = _janus_device_claim(p)
            device_binding_hash = _request_device_binding(request, device_claim)
            cookie_secret = new_session_token()
            cookie_hash = hashlib.sha256(cookie_secret.encode()).hexdigest()
            cur.execute(
                "UPDATE vault_scif_sessions SET state='active',opened_at=COALESCE(opened_at,now()),auth_envelope=%s::jsonb,last_verified_at=now(),revoked_reason=NULL,device_binding_hash=%s,device_claim=%s,cookie_hash=%s,failed_entry_attempts=0,failed_cookie_attempts=0 WHERE id=%s",
                (json.dumps(auth_envelope), device_binding_hash, device_claim, cookie_hash, session_id),
            )
            append_audit(cur, p.subject, "scif_entered", str(row["object_id"]), {
                "session_id": session_id,
                "mode": row["mode"],
                "continuous_authorization": True,
                "janus_scoped_handle": True,
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
                raise HTTPException(410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_view_denied"
                )
                raise HTTPException(403, "Invalid SCIF session")
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
                raise HTTPException(410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_render_denied"
                )
                raise HTTPException(403, "Invalid SCIF session")
            if row.get("failed_cookie_attempts"):
                cur.execute("UPDATE vault_scif_sessions SET failed_cookie_attempts=0 WHERE id=%s", (session_id,))
            current = _continuous_scif_check(cur, row)
            _enforce_device_binding(cur, row, request, current)
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
                raise HTTPException(409, "SCIF document render failed")
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
                raise HTTPException(410, "SCIF session expired")
            _enforce_scif_idle(cur, row)
            if row["state"] != "active":
                raise HTTPException(403, "SCIF session is not active")
            if not row.get("cookie_hash") or not secrets.compare_digest(token_hash, row["cookie_hash"]):
                _record_scif_auth_failure(
                    cur, row, kind="cookie", actor=row["owner"], action="scif_heartbeat_denied"
                )
                raise HTTPException(403, "Invalid SCIF session")
            if row.get("failed_cookie_attempts"):
                cur.execute("UPDATE vault_scif_sessions SET failed_cookie_attempts=0 WHERE id=%s", (session_id,))
            current = _continuous_scif_check(cur, row)
            _enforce_device_binding(cur, row, request, current)
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
