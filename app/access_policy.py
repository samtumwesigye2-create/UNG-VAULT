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
