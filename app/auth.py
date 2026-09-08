from dataclasses import dataclass
from fastapi import Header, HTTPException
import jwt
from .config import load_settings

CLEARANCE = {"public":0,"internal":1,"confidential":2,"restricted":3,"top_secret":4}

@dataclass(frozen=True)
class Principal:
    subject: str
    clearance: str
    compartments: frozenset[str]
    claims: dict


def require_principal(authorization: str = Header(None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing JANUS bearer token")
    token = authorization.split(" ", 1)[1]
    s = load_settings()
    try:
        options = {"require": ["sub", "exp"]}
        kwargs = {"algorithms": list(s.janus_algorithms), "options": options}
        if s.janus_audience:
            kwargs["audience"] = s.janus_audience
        else:
            kwargs["options"] = {**options, "verify_aud": False}
        claims = jwt.decode(token, s.janus_public_key, **kwargs)
    except Exception as e:
        raise HTTPException(401, "Invalid JANUS access claim") from e
    clearance = str(claims.get("clearance", "public"))
    if clearance not in CLEARANCE:
        raise HTTPException(403, "Invalid clearance claim")
    compartments = claims.get("compartments", [])
    if not isinstance(compartments, list):
        raise HTTPException(403, "Invalid compartment claim")
    return Principal(str(claims["sub"]), clearance, frozenset(map(str, compartments)), claims)


def authorize(p: Principal, classification: str, compartment: str) -> None:
    if classification not in CLEARANCE:
        raise HTTPException(500, "Invalid stored classification")
    if CLEARANCE[p.clearance] < CLEARANCE[classification]:
        raise HTTPException(403, "Insufficient clearance")
    if compartment not in p.compartments:
        raise HTTPException(403, "Compartment access denied")
