from dataclasses import dataclass
import json
from urllib import request, error
from fastapi import Header, HTTPException
from .config import load_settings

CLEARANCE = {"public":0,"internal":1,"confidential":2,"restricted":3,"top_secret":4}
ROLE_CLEARANCE = {
    "platform-admin": "top_secret",
    "security-admin": "restricted",
    "corporate-user": "confidential",
    "service": "restricted",
    "vendor": "internal",
    "contractor": "internal",
}

@dataclass(frozen=True)
class Principal:
    subject: str
    clearance: str
    compartments: frozenset[str]
    claims: dict


def _introspect(authorization: str) -> dict:
    s = load_settings()
    req = request.Request(
        s.janus_introspect_url,
        method="POST",
        headers={"Authorization": authorization, "Accept": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=s.janus_timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        if e.code in (401, 403):
            raise HTTPException(401, "Invalid or expired JANUS token") from e
        raise HTTPException(503, "JANUS authorization service unavailable") from e
    except Exception as e:
        raise HTTPException(503, "JANUS authorization service unavailable") from e
    if not body.get("active") or not isinstance(body.get("principal"), dict):
        raise HTTPException(401, "Invalid or expired JANUS token")
    return body["principal"]


def require_principal(authorization: str = Header(None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing JANUS bearer token")
    claims = _introspect(authorization)
    roles = set(map(str, claims.get("roles", [])))
    permissions = set(map(str, claims.get("permissions", [])))

    clearance = "public"
    for role, level in ROLE_CLEARANCE.items():
        if role in roles and CLEARANCE[level] > CLEARANCE[clearance]:
            clearance = level

    compartments = {p.split(":", 2)[2] for p in permissions if p.startswith("vault:compartment:") and p.count(":") >= 2}
    if "platform-admin" in roles:
        compartments.add("*")

    return Principal(str(claims.get("id", "")), clearance, frozenset(compartments), claims)


def authorize(p: Principal, classification: str, compartment: str) -> None:
    if classification not in CLEARANCE:
        raise HTTPException(400, "Invalid classification")
    if CLEARANCE[p.clearance] < CLEARANCE[classification]:
        raise HTTPException(403, "Insufficient clearance")
    if "*" not in p.compartments and compartment not in p.compartments:
        raise HTTPException(403, "Compartment access denied")
