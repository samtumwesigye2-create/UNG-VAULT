import pytest
from app.auth import Principal
from app.security_policy import SecurityPolicyError, require_top_secret_access


def principal(subject="recipient-1", clearance="top_secret", compartments=frozenset({"alpha"}), claims=None):
    return Principal(subject, clearance, compartments, claims or {"amr": ["pwd", "mfa"]})


def test_top_secret_requires_identity_mfa_clearance_compartment_and_recipient():
    require_top_secret_access(principal(), "top_secret", "alpha", "recipient-1")


def test_top_secret_rejects_wrong_recipient():
    with pytest.raises(SecurityPolicyError):
        require_top_secret_access(principal(), "top_secret", "alpha", "recipient-2")


def test_top_secret_rejects_missing_mfa():
    with pytest.raises(SecurityPolicyError):
        require_top_secret_access(principal(claims={"amr": ["pwd"]}), "top_secret", "alpha", "recipient-1")


def test_top_secret_rejects_insufficient_clearance_or_compartment():
    with pytest.raises(SecurityPolicyError):
        require_top_secret_access(principal(clearance="restricted"), "top_secret", "alpha", "recipient-1")
    with pytest.raises(SecurityPolicyError):
        require_top_secret_access(principal(compartments=frozenset({"beta"})), "top_secret", "alpha", "recipient-1")
