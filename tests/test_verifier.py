"""
Tests for verify_credential(), is_expired(), and has_permission().
"""

from datetime import datetime, timezone

import pytest

from cordprotocol import (
    AgentCredential,
    VerificationResult,
    generate_keypair,
    has_permission,
    is_expired,
    issue_credential,
    verify_credential,
)
from cordprotocol.crypto.signatures import default_backend


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _issue(**overrides):
    """Issue a valid test credential and return (credential, keypair)."""
    kp = generate_keypair()
    cred = issue_credential(
        agent_id=overrides.pop("agent_id", "test-agent"),
        issued_to=overrides.pop("issued_to", "alice"),
        permissions=overrides.pop("permissions", ["read:data", "write:data"]),
        expires_in=overrides.pop("expires_in", "24h"),
        private_key=kp.private_key,
        **overrides,
    )
    return cred, kp


def _re_sign(cred: AgentCredential, private_key: str) -> AgentCredential:
    """Re-sign a (possibly tampered) credential and return a new instance."""
    payload = cred.to_signing_payload()
    sig = default_backend.sign(payload, private_key)
    return cred.model_copy(update={"signature": sig})


# ------------------------------------------------------------------ #
# verify_credential — happy path                                       #
# ------------------------------------------------------------------ #


class TestVerifyCredentialValid:
    def test_valid_credential_passes(self):
        cred, _ = _issue()
        assert verify_credential(cred).valid is True

    def test_returns_verification_result(self):
        cred, _ = _issue()
        assert isinstance(verify_credential(cred), VerificationResult)

    def test_credential_embedded_in_result(self):
        cred, _ = _issue()
        result = verify_credential(cred)
        assert result.credential is not None
        assert result.credential.id == cred.id

    def test_no_error_on_valid(self):
        cred, _ = _issue()
        assert verify_credential(cred).error is None

    def test_all_scopes_credential_valid(self):
        cred, _ = _issue(permissions=["read:data", "write:data", "execute:actions",
                                       "communicate:agents", "spend:budget"])
        assert verify_credential(cred).valid is True

    def test_empty_permissions_credential_valid(self):
        cred, _ = _issue(permissions=[])
        assert verify_credential(cred).valid is True


# ------------------------------------------------------------------ #
# verify_credential — tamper detection                                 #
# ------------------------------------------------------------------ #


class TestVerifyCredentialTamper:
    def test_tampered_permissions_fails(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"permissions": ["spend:budget"]})
        assert verify_credential(tampered).valid is False

    def test_tampered_agent_id_fails(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"agent_id": "evil-agent"})
        assert verify_credential(tampered).valid is False

    def test_tampered_issued_to_fails(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"issued_to": "mallory"})
        assert verify_credential(tampered).valid is False

    def test_tampered_signature_fails(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"signature": "dGFtcGVyZWQ="})
        assert verify_credential(tampered).valid is False

    def test_wrong_public_key_fails(self):
        cred, _ = _issue()
        other_kp = generate_keypair()
        tampered = cred.model_copy(update={"issuer_public_key": other_kp.public_key})
        assert verify_credential(tampered).valid is False

    def test_empty_signature_fails(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"signature": ""})
        result = verify_credential(tampered)
        assert result.valid is False
        assert result.error == "Credential has no signature."

    def test_error_message_is_set_on_invalid(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"signature": "dGFtcGVyZWQ="})
        result = verify_credential(tampered)
        assert result.error is not None and isinstance(result.error, str)

    def test_credential_absent_on_invalid(self):
        cred, _ = _issue()
        tampered = cred.model_copy(update={"signature": "dGFtcGVyZWQ="})
        assert verify_credential(tampered).credential is None


# ------------------------------------------------------------------ #
# verify_credential — expiry                                           #
# ------------------------------------------------------------------ #


class TestVerifyCredentialExpiry:
    def test_expired_credential_fails(self):
        """Credential with expires_at in the past must fail, even if signature is valid."""
        cred, kp = _issue()
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        # Move expiry into the past and re-sign so the signature is still valid.
        expired = _re_sign(cred.model_copy(update={"expires_at": past}), kp.private_key)
        result = verify_credential(expired)
        assert result.valid is False
        assert "expired" in result.error.lower()

    def test_expiry_error_message_contains_expired(self):
        cred, kp = _issue()
        past = datetime(2020, 6, 1, tzinfo=timezone.utc)
        expired = _re_sign(cred.model_copy(update={"expires_at": past}), kp.private_key)
        assert "expired" in verify_credential(expired).error.lower()


# ------------------------------------------------------------------ #
# is_expired                                                           #
# ------------------------------------------------------------------ #


class TestIsExpired:
    def test_future_credential_not_expired(self):
        cred, _ = _issue(expires_in="24h")
        assert is_expired(cred) is False

    def test_past_credential_is_expired(self):
        cred, _ = _issue()
        past = cred.model_copy(update={"expires_at": datetime(2020, 1, 1, tzinfo=timezone.utc)})
        assert is_expired(past) is True

    def test_is_expired_returns_bool(self):
        cred, _ = _issue()
        result = is_expired(cred)
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
# has_permission                                                       #
# ------------------------------------------------------------------ #


class TestHasPermission:
    def test_granted_scope_returns_true(self):
        cred, _ = _issue(permissions=["read:data", "write:data"])
        assert has_permission(cred, "read:data") is True

    def test_missing_scope_returns_false(self):
        cred, _ = _issue(permissions=["read:data"])
        assert has_permission(cred, "spend:budget") is False

    def test_empty_permissions_returns_false(self):
        cred, _ = _issue(permissions=[])
        assert has_permission(cred, "read:data") is False

    def test_partial_scope_not_matched(self):
        cred, _ = _issue(permissions=["read:data"])
        assert has_permission(cred, "read") is False
        assert has_permission(cred, "data") is False

    def test_all_scopes_granted(self):
        scopes = ["read:data", "write:data", "execute:actions", "communicate:agents", "spend:budget"]
        cred, _ = _issue(permissions=scopes)
        for scope in scopes:
            assert has_permission(cred, scope) is True

    def test_has_permission_returns_bool(self):
        cred, _ = _issue(permissions=["read:data"])
        assert isinstance(has_permission(cred, "read:data"), bool)

    def test_unknown_scope_returns_false(self):
        cred, _ = _issue(permissions=["read:data"])
        assert has_permission(cred, "delete:everything") is False
