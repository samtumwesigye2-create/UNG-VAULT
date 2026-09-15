from __future__ import annotations

from .auth import Principal


class SecurityPolicyError(Exception):
    pass


def _has_mfa(claims: dict) -> bool:
    amr = claims.get("amr", [])
    if isinstance(amr, str):
        amr = [amr]
    normalized = {str(v).lower() for v in amr}
    if normalized & {"mfa", "otp", "totp", "webauthn", "hwk", "fido", "fido2"}:
        return True
    acr = str(claims.get("acr", "")).lower()
    return any(marker in acr for marker in ("mfa", "aal2", "aal3"))


def require_top_secret_access(
    principal: Principal,
    classification: str,
    compartment: str,
    recipient_subject: str,
) -> None:
    """Require all identity-bound Level 3 gates; fail closed on any missing evidence."""
    if not principal.subject or principal.subject != recipient_subject:
        raise SecurityPolicyError("TOP SECRET access denied")
    if str(classification).strip().lower() != "top_secret":
        raise SecurityPolicyError("TOP SECRET access denied")
    if str(principal.clearance).strip().lower() != "top_secret":
        raise SecurityPolicyError("TOP SECRET access denied")
    normalized_compartments = {str(v).strip().lower() for v in principal.compartments}
    if str(compartment).strip().lower() not in normalized_compartments:
        raise SecurityPolicyError("TOP SECRET access denied")
    if not _has_mfa(principal.claims):
        raise SecurityPolicyError("TOP SECRET access denied")
