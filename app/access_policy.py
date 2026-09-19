"""UNG-VAULT need-to-know authorization and multi-party approval policy.

All VAULT-* cryptographic profiles remain capabilities of UNG-VAULT.
This module is policy metadata and fail-closed authorization logic; JANUS remains
the identity authority and cryptographic operations remain in app.crypto/key_management.
"""
from dataclasses import dataclass
from enum import IntEnum
from typing import FrozenSet

class AccessTier(IntEnum):
    JUNIOR_STAFF = 10
    STAFF = 20
    SENIOR_STAFF = 30
    EXECUTIVE_STAFF = 40
    CABINET = 90
    PRESIDENT = 100

@dataclass(frozen=True)
class VaultProfile:
    code: str
    label: str
    minimum_tier: AccessTier
    approvals_required: int
    compartments: FrozenSet[str] = frozenset()

PROFILES = {
    "VAULT-ONE": VaultProfile("VAULT-ONE", "One-Time Vault", AccessTier.SENIOR_STAFF, 2),
    "VAULT-ENVELOPE": VaultProfile("VAULT-ENVELOPE", "Ephemeral Envelope Encryption", AccessTier.STAFF, 1),
    "VAULT-SPLIT": VaultProfile("VAULT-SPLIT", "Split-Key Vault", AccessTier.EXECUTIVE_STAFF, 3),
    "VAULT-DUAL": VaultProfile("VAULT-DUAL", "Dual-Control Encryption", AccessTier.SENIOR_STAFF, 2),
    "VAULT-TIME": VaultProfile("VAULT-TIME", "Time-Locked Vaults", AccessTier.SENIOR_STAFF, 2),
    "VAULT-FORWARD": VaultProfile("VAULT-FORWARD", "Forward-Secure Sessions", AccessTier.STAFF, 1),
    "VAULT-FIELD": VaultProfile("VAULT-FIELD", "Per-Record / Per-Field Encryption", AccessTier.STAFF, 1),
    "VAULT-STREAM": VaultProfile("VAULT-STREAM", "Streaming / Chunk Encryption", AccessTier.STAFF, 1),
    "VAULT-MULTI": VaultProfile("VAULT-MULTI", "Multi-Recipient Encryption", AccessTier.SENIOR_STAFF, 2),
    "VAULT-COURIER": VaultProfile("VAULT-COURIER", "Offline Courier Mode", AccessTier.EXECUTIVE_STAFF, 3),
    "VAULT-ERASE": VaultProfile("VAULT-ERASE", "Crypto-Erasure", AccessTier.EXECUTIVE_STAFF, 3),
    "VAULT-CANARY": VaultProfile("VAULT-CANARY", "Honey / Canary Containers", AccessTier.SENIOR_STAFF, 2),
    "VAULT-PQ": VaultProfile("VAULT-PQ", "Post-Quantum Hybrid Mode", AccessTier.SENIOR_STAFF, 2),
    "VAULT-LEGACY": VaultProfile("VAULT-LEGACY", "Legacy Interoperability Mode", AccessTier.EXECUTIVE_STAFF, 3),
    "VAULT-CASCADE": VaultProfile("VAULT-CASCADE", "Multi-Domain Cascade Protection", AccessTier.EXECUTIVE_STAFF, 3),
    "VAULT-TRANSIT": VaultProfile("VAULT-TRANSIT", "Signed Encrypted Transit Packages", AccessTier.SENIOR_STAFF, 2),
    "VAULT-MIL": VaultProfile("VAULT-MIL", "Military / Defence Protected Vault", AccessTier.EXECUTIVE_STAFF, 3),
}

FULL_VAULT_TIERS = frozenset({AccessTier.PRESIDENT, AccessTier.CABINET})

@dataclass(frozen=True)
class AccessContext:
    subject_id: str
    tier: AccessTier
    clearance: int
    compartments: FrozenSet[str]
    purpose: str
    approved_by: FrozenSet[str]

def authorize(ctx: AccessContext, profile_code: str, resource_clearance: int,
              resource_compartments: FrozenSet[str], owner_id: str | None = None) -> bool:
    """Fail closed. Rank alone never bypasses clearance, compartment, purpose, or approvals."""
    profile = PROFILES.get(profile_code)
    if not profile or not ctx.purpose.strip():
        return False
    if ctx.clearance < resource_clearance:
        return False
    if not resource_compartments.issubset(ctx.compartments):
        return False
    if ctx.tier not in FULL_VAULT_TIERS and ctx.tier < profile.minimum_tier:
        return False
    # Approvers must be distinct and cannot self-approve.
    independent = set(ctx.approved_by)
    independent.discard(ctx.subject_id)
    if len(independent) < profile.approvals_required:
        return False
    return True


# Stable document visual classification. Color identifies the VAULT protection
# profile only; access is always determined by authorize(), never by color.
VAULT_DOCUMENT_COLORS = {
    "VAULT-ONE": {"name": "Black", "hex": "#111111"},
    "VAULT-ENVELOPE": {"name": "Slate", "hex": "#475569"},
    "VAULT-SPLIT": {"name": "Burgundy", "hex": "#7F1D1D"},
    "VAULT-DUAL": {"name": "Crimson", "hex": "#B91C1C"},
    "VAULT-TIME": {"name": "Amber", "hex": "#B45309"},
    "VAULT-FORWARD": {"name": "Teal", "hex": "#0F766E"},
    "VAULT-FIELD": {"name": "Emerald", "hex": "#047857"},
    "VAULT-STREAM": {"name": "Cyan", "hex": "#0E7490"},
    "VAULT-MULTI": {"name": "Violet", "hex": "#6D28D9"},
    "VAULT-COURIER": {"name": "Orange", "hex": "#C2410C"},
    "VAULT-ERASE": {"name": "Graphite", "hex": "#374151"},
    "VAULT-CANARY": {"name": "Yellow", "hex": "#A16207"},
    "VAULT-PQ": {"name": "Indigo", "hex": "#4338CA"},
    "VAULT-LEGACY": {"name": "Blue", "hex": "#1D4ED8"},
    "VAULT-CASCADE": {"name": "Purple", "hex": "#7E22CE"},
    "VAULT-TRANSIT": {"name": "Green", "hex": "#15803D"},
    "VAULT-MIL": {"name": "Olive", "hex": "#3F6212"},
}

def document_marking(profile_code: str) -> dict:
    profile = PROFILES[profile_code]
    color = VAULT_DOCUMENT_COLORS[profile_code]
    return {
        "profile": profile.code,
        "label": profile.label,
        "color_name": color["name"],
        "color_hex": color["hex"],
        # Text remains authoritative for printing, accessibility and monochrome copies.
        "banner": f"{profile.code} | {profile.label}",
    }
