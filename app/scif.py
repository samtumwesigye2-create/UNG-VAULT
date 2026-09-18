from __future__ import annotations

import html
import json
import os
import secrets
import textwrap
from io import BytesIO
from datetime import datetime, timedelta, timezone
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont

from fastapi import HTTPException
from fastapi.responses import HTMLResponse

from .auth import Principal

SCIF_MODES = {
    "scif": {"label": "SCIF", "approvals_required": 0},
    "scif_two_person": {"label": "SCIF + TWO-PERSON CONTROL", "approvals_required": 2},
}

DEFAULT_MINUTES = 30
MAX_MINUTES = 120
SCIF_MFA_MAX_AGE_SECONDS = max(
    60,
    min(1800, int(os.getenv("VAULT_SCIF_MFA_MAX_AGE_SECONDS", "300"))),
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def require_scif_entitlement(p: Principal) -> None:
    roles = {str(x) for x in p.claims.get("roles", [])}
    permissions = {str(x) for x in p.claims.get("permissions", [])}
    allowed = (
        p.clearance == "top_secret"
        and (
            "platform-admin" in roles
            or "security-admin" in roles
            or "vault:scif" in permissions
            or "vault:scif:enter" in permissions
        )
    )
    if not allowed:
        raise HTTPException(403, "SCIF access requires top-secret clearance and SCIF entitlement")


def require_trusted_device(p: Principal) -> None:
    permissions = {str(x) for x in p.claims.get("permissions", [])}
    # JANUS deployments can assert trust either as a boolean posture claim or a permission.
    posture = p.claims.get("device_trusted", p.claims.get("trusted_device"))
    if posture is True or "vault:trusted-device" in permissions or "device:trusted" in permissions:
        return
    raise HTTPException(403, "SCIF access requires a JANUS-trusted device")


def require_recent_mfa(p: Principal) -> None:
    amr = {str(x).lower() for x in p.claims.get("amr", [])}
    acr = str(p.claims.get("acr", "")).lower()
    mfa = p.claims.get("mfa")
    if mfa is True or "mfa" in amr or "otp" in amr or "webauthn" in amr or "phishing-resistant" in acr:
        return
    raise HTTPException(403, "SCIF access requires MFA-authenticated JANUS session")


def _claim_time(value) -> datetime | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def require_fresh_mfa(p: Principal, max_age_seconds: int | None = None) -> int:
    require_recent_mfa(p)
    max_age = max_age_seconds or SCIF_MFA_MAX_AGE_SECONDS

    # Prefer an explicit MFA timestamp. OIDC auth_time is accepted as the
    # fallback only when the same JANUS principal also proves MFA via AMR/ACR.
    ts = (
        _claim_time(p.claims.get("mfa_time"))
        or _claim_time(p.claims.get("mfa_at"))
        or _claim_time(p.claims.get("auth_time"))
    )
    if ts is None:
        raise HTTPException(401, "SCIF requires fresh MFA; JANUS must provide mfa_time or auth_time")

    age = int((utcnow() - ts).total_seconds())
    if age < 0:
        raise HTTPException(401, "Invalid JANUS MFA timestamp")
    if age > max_age:
        raise HTTPException(401, "SCIF MFA is stale; step-up authentication required")
    return age


def session_minutes(value: int) -> int:
    if value < 5 or value > MAX_MINUTES:
        raise HTTPException(400, f"SCIF session duration must be between 5 and {MAX_MINUTES} minutes")
    return value


def approval_count(values: Iterable[str] | None) -> int:
    return len({str(x) for x in (values or []) if str(x)})


def scif_headers(session_id: str) -> dict[str, str]:
    return {
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), clipboard-read=(), clipboard-write=()",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
        "X-Frame-Options": "DENY",
        "X-UNG-VAULT-SCIF": session_id,
    }


def render_scif_image(
    *,
    value: str,
    viewer: str,
    session_id: str,
    classification: str,
    compartment: str,
) -> bytes:
    """Rasterize SCIF plaintext server-side so the browser receives pixels, not text."""
    font = ImageFont.load_default()
    margin = 48
    line_gap = 6
    wrap_width = 110
    lines: list[str] = []
    for paragraph in value.splitlines() or [""]:
        wrapped = textwrap.wrap(
            paragraph,
            width=wrap_width,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        lines.extend(wrapped or [""])
    lines = lines[:4000]

    probe = Image.new("RGB", (10, 10), "white")
    pd = ImageDraw.Draw(probe)
    bbox = pd.textbbox((0, 0), "Ag", font=font)
    line_h = max(16, bbox[3] - bbox[1] + line_gap)
    width = 1400
    height = min(50000, max(500, margin * 2 + line_h * max(1, len(lines)) + 90))

    image = Image.new("RGB", (width, height), (10, 16, 24))
    draw = ImageDraw.Draw(image)
    y = margin
    for line in lines:
        if y + line_h > height - margin:
            break
        draw.text((margin, y), line, font=font, fill=(238, 242, 247))
        y += line_h

    stamp = f"{viewer} | {session_id[:12]} | {classification.upper()} | {compartment}"
    stamp_w = max(220, min(width - 40, len(stamp) * 7))
    for yy in range(70, height, 180):
        for xx in range(-80, width, stamp_w + 90):
            draw.text((xx, yy), stamp, font=font, fill=(52, 64, 80))

    out = BytesIO()
    image.save(out, format="PNG", optimize=True)
    return out.getvalue()


def render_scif_view(
    *,
    session_id: str,
    viewer: str,
    classification: str,
    compartment: str,
    name: str,
    expires_at: datetime,
) -> HTMLResponse:
    stamp = f"{viewer} • {session_id[:12]} • {utcnow().isoformat(timespec='seconds')}"
    watermark = html.escape(stamp)
    title = html.escape(name)
    cls = html.escape(classification.upper())
    comp = html.escape(compartment)
    expires = html.escape(expires_at.isoformat(timespec="seconds"))

    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UNG-VAULT SCIF — {title}</title>
<style>
*{{box-sizing:border-box}} html,body{{margin:0;background:#05080d;color:#edf2f7;font:16px system-ui,-apple-system,sans-serif}}
body{{min-height:100vh;user-select:none;-webkit-user-select:none}} header{{position:sticky;top:0;background:#090f18;border-bottom:1px solid #293343;padding:16px 24px;z-index:3}}
.badge{{display:inline-block;background:#6d0013;color:#fff;padding:7px 10px;border-radius:6px;font-weight:800;letter-spacing:.08em}}
.meta{{color:#aab6c4;margin-top:8px;font-size:13px}} main{{max-width:1000px;margin:0 auto;padding:34px 28px 100px;position:relative}}
article{{background:#0b121c;border:1px solid #263343;border-radius:12px;padding:18px;min-height:50vh;overflow:auto}} article img{{display:block;width:100%;height:auto;border-radius:8px;pointer-events:none}}
.watermark{{position:fixed;inset:0;pointer-events:none;z-index:10;display:grid;grid-template-columns:repeat(3,1fr);grid-auto-rows:150px;overflow:hidden;opacity:.13;transform:rotate(-18deg);font-size:18px;font-weight:800}}
.watermark span{{display:flex;align-items:center;justify-content:center;white-space:nowrap}}
.notice{{margin-top:18px;color:#f7c873;font-size:13px}} @media print{{body{{display:none!important}}}}
</style></head>
<body oncontextmenu="return false" ondragstart="return false">
<header><span class="badge">SCIF MODE</span><div class="meta">{cls} • {comp} • expires {expires}</div></header>
<main><h1>{title}</h1><article><img src="/vault/scif/render/{session_id}.png" alt="Controlled SCIF document"></article><div class="notice">Controlled viewing session. Plaintext is rasterized server-side and is not delivered as selectable HTML text. Download, print, clipboard and local caching are disabled by policy. Screen capture cannot be guaranteed by a browser; viewer/session watermarking remains active.</div></main>
<div class="watermark">{''.join(f'<span>{watermark}</span>' for _ in range(42))}</div>
<script>
document.addEventListener('copy',e=>e.preventDefault());
document.addEventListener('cut',e=>e.preventDefault());
document.addEventListener('paste',e=>e.preventDefault());
document.addEventListener('keydown',e=>{{if((e.ctrlKey||e.metaKey)&&['p','s','c','u'].includes(e.key.toLowerCase()))e.preventDefault();}});
const heartbeat=async()=>{{try{{const r=await fetch('/vault/scif/heartbeat/{session_id}',{{credentials:'same-origin',cache:'no-store'}});if(!r.ok)throw new Error('SCIF authorization lost')}}catch(e){{document.body.innerHTML='<main><h1>SCIF SESSION LOCKED</h1><p>Continuous authorization failed or the session was revoked.</p></main>';setTimeout(()=>location.replace('/ui'),1500)}}}};setInterval(heartbeat,15000);heartbeat();
setTimeout(()=>location.replace('/ui'), Math.max(1000, new Date('{expires_at.isoformat()}').getTime()-Date.now()));
</script></body></html>"""
    return HTMLResponse(page, headers=scif_headers(session_id))
