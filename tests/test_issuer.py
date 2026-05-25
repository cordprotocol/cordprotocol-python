"""
Tests for generate_keypair() and issue_credential().
"""

import base64
import uuid
from datetime import datetime, timezone

import pytest

from cordprotocol import AgentCredential, KeyPair, generate_keypair, issue_credential
from cordprotocol.crypto.signatures import Ed25519Backend


# ------------------------------------------------------------------ #
# generate_keypair                                                     #
# ------------------------------------------------------------------ #


class TestGenerateKeypair:
    def test_returns_keypair(self):
        assert isinstance(generate_keypair(), KeyPair)

    def test_has_private_key(self):
        kp = generate_keypair()
        assert kp.private_key and isinstance(kp.private_key, str)

    def test_has_public_key(self):
        kp = generate_keypair()
        assert kp.public_key and isinstance(kp.public_key, str)

    def test_algorithm_is_ed25519(self):
        assert generate_keypair().algorithm == "Ed25519"

    def test_keypairs_are_unique(self):
        kp1, kp2 = generate_keypair(), generate_keypair()
        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key

    def test_keys_are_valid_base64(self):
        kp = generate_keypair()
        base64.b64decode(kp.private_key)
        base64.b64decode(kp.public_key)

    def test_ed25519_raw_key_lengths(self):
        kp = generate_keypair()
        assert len(base64.b64decode(kp.private_key)) == 32
        assert len(base64.b64decode(kp.public_key)) == 32

    def test_custom_backend_respected(self):
        backend = Ed25519Backend()
        kp = generate_keypair(backend=backend)
        assert kp.algorithm == "Ed25519"

    def test_public_key_derivable_from_private(self):
        """Public key in KeyPair must equal the key derived from its private key."""
        backend = Ed25519Backend()
        kp = generate_keypair()
        derived = backend.get_public_key(kp.private_key)
        assert derived == kp.public_key


# ------------------------------------------------------------------ #
# issue_credential                                                     #
# ------------------------------------------------------------------ #


@pytest.fixture
def kp() -> KeyPair:
    return generate_keypair()


class TestIssueCredential:
    def test_returns_agent_credential(self, kp):
        cred = issue_credential("agent", "alice", ["read:data"], "24h", kp.private_key)
        assert isinstance(cred, AgentCredential)

    def test_agent_id_is_preserved(self, kp):
        cred = issue_credential("my-agent", "alice", ["read:data"], "24h", kp.private_key)
        assert cred.agent_id == "my-agent"

    def test_issued_to_is_preserved(self, kp):
        cred = issue_credential("agent", "carol", ["read:data"], "24h", kp.private_key)
        assert cred.issued_to == "carol"

    def test_permissions_are_preserved(self, kp):
        perms = ["read:data", "write:data"]
        cred = issue_credential("agent", "dave", perms, "24h", kp.private_key)
        assert set(cred.permissions) == set(perms)

    def test_id_is_valid_uuid(self, kp):
        cred = issue_credential("agent", "eve", ["read:data"], "24h", kp.private_key)
        uuid.UUID(cred.id)  # raises ValueError if not a valid UUID

    def test_signature_is_non_empty_string(self, kp):
        cred = issue_credential("agent", "frank", ["read:data"], "24h", kp.private_key)
        assert cred.signature and isinstance(cred.signature, str)

    def test_issuer_public_key_matches_keypair(self, kp):
        cred = issue_credential("agent", "grace", ["read:data"], "24h", kp.private_key)
        assert cred.issuer_public_key == kp.public_key

    def test_issued_at_is_recent(self, kp):
        before = datetime.now(tz=timezone.utc)
        cred = issue_credential("agent", "henry", ["read:data"], "24h", kp.private_key)
        after = datetime.now(tz=timezone.utc)
        assert before <= cred.issued_at <= after

    def test_issued_at_is_utc(self, kp):
        cred = issue_credential("agent", "iris", ["read:data"], "24h", kp.private_key)
        assert cred.issued_at.tzinfo is not None

    def test_expires_in_hours(self, kp):
        cred = issue_credential("agent", "jack", ["read:data"], "24h", kp.private_key)
        delta = (cred.expires_at - cred.issued_at).total_seconds()
        assert abs(delta - 86_400) < 2

    def test_expires_in_days(self, kp):
        cred = issue_credential("agent", "kate", ["read:data"], "7d", kp.private_key)
        delta = (cred.expires_at - cred.issued_at).total_seconds()
        assert abs(delta - 7 * 86_400) < 2

    def test_expires_in_minutes(self, kp):
        cred = issue_credential("agent", "leo", ["read:data"], "30m", kp.private_key)
        delta = (cred.expires_at - cred.issued_at).total_seconds()
        assert abs(delta - 1_800) < 2

    def test_attestation_hash_none_by_default(self, kp):
        cred = issue_credential("agent", "mia", ["read:data"], "24h", kp.private_key)
        assert cred.attestation_hash is None

    def test_attestation_hash_set_when_provided(self, kp):
        cred = issue_credential(
            "agent", "nina", ["read:data"], "24h", kp.private_key,
            attestation_hash="abc123",
        )
        assert cred.attestation_hash == "abc123"

    def test_empty_permissions_allowed(self, kp):
        cred = issue_credential("agent", "oscar", [], "24h", kp.private_key)
        assert cred.permissions == []

    def test_multiple_permissions(self, kp):
        perms = ["read:data", "write:data", "execute:actions"]
        cred = issue_credential("agent", "petra", perms, "24h", kp.private_key)
        assert set(cred.permissions) == set(perms)

    def test_signature_is_valid_base64(self, kp):
        cred = issue_credential("agent", "quinn", ["read:data"], "24h", kp.private_key)
        base64.b64decode(cred.signature)

    def test_two_credentials_have_different_ids(self, kp):
        c1 = issue_credential("agent", "rosa", ["read:data"], "24h", kp.private_key)
        c2 = issue_credential("agent", "rosa", ["read:data"], "24h", kp.private_key)
        assert c1.id != c2.id


# ------------------------------------------------------------------ #
# Validation / error cases                                             #
# ------------------------------------------------------------------ #


class TestIssueCredentialValidation:
    def test_invalid_expires_in_unit_raises(self, kp):
        with pytest.raises(ValueError, match="Unknown duration unit"):
            issue_credential("agent", "user", ["read:data"], "1x", kp.private_key)

    def test_invalid_expires_in_format_raises(self, kp):
        with pytest.raises(ValueError):
            issue_credential("agent", "user", ["read:data"], "invalid", kp.private_key)

    def test_negative_expires_in_raises(self, kp):
        with pytest.raises(ValueError):
            issue_credential("agent", "user", ["read:data"], "-1h", kp.private_key)

    def test_zero_expires_in_raises(self, kp):
        with pytest.raises(ValueError):
            issue_credential("agent", "user", ["read:data"], "0d", kp.private_key)

    def test_empty_expires_in_raises(self, kp):
        with pytest.raises(ValueError):
            issue_credential("agent", "user", ["read:data"], "", kp.private_key)

    def test_empty_agent_id_raises(self, kp):
        with pytest.raises(ValueError, match="agent_id"):
            issue_credential("", "user", ["read:data"], "24h", kp.private_key)

    def test_empty_issued_to_raises(self, kp):
        with pytest.raises(ValueError, match="issued_to"):
            issue_credential("agent", "", ["read:data"], "24h", kp.private_key)

    def test_empty_private_key_raises(self):
        with pytest.raises(ValueError, match="private_key"):
            issue_credential("agent", "user", ["read:data"], "24h", "")
