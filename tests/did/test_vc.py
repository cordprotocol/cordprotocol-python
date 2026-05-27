"""
Tests for cordprotocol.did.vc — issue_verifiable_credential, verify_verifiable_credential,
agent_credential_to_vc, and vc_to_agent_credential_dict.
"""

import dataclasses
import uuid
from datetime import datetime, timezone

import pytest

from cordprotocol import generate_keypair, issue_credential
from cordprotocol.did.document import _base58_encode, _base58_decode
from cordprotocol.did.vc import (
    _vc_signing_payload,
    agent_credential_to_vc,
    issue_verifiable_credential,
    vc_to_agent_credential_dict,
    verify_verifiable_credential,
)
from cordprotocol.did.types import VerifiableCredential, VCProof


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _issue_vc(**overrides):
    kp = generate_keypair()
    vc = issue_verifiable_credential(
        agent_id=overrides.pop("agent_id", "test-agent"),
        issued_to=overrides.pop("issued_to", "alice"),
        permissions=overrides.pop("permissions", ["read:data", "write:data"]),
        expires_in=overrides.pop("expires_in", "24h"),
        private_key=kp.private_key,
        issuer_did=overrides.pop("issuer_did", "did:web:cordprotocol.dev"),
        **overrides,
    )
    return vc, kp


# ------------------------------------------------------------------ #
# issue_verifiable_credential — structure                              #
# ------------------------------------------------------------------ #


class TestIssueVerifiableCredential:
    def test_returns_verifiable_credential(self):
        vc, _ = _issue_vc()
        assert isinstance(vc, VerifiableCredential)

    def test_context_includes_w3c_credentials(self):
        vc, _ = _issue_vc()
        assert "https://www.w3.org/2018/credentials/v1" in vc.context

    def test_context_includes_ed25519_suite(self):
        vc, _ = _issue_vc()
        assert any("ed25519" in c.lower() for c in vc.context)

    def test_type_includes_verifiable_credential(self):
        vc, _ = _issue_vc()
        assert "VerifiableCredential" in vc.type

    def test_type_includes_agent_identity(self):
        vc, _ = _issue_vc()
        assert "AgentIdentityCredential" in vc.type

    def test_id_has_urn_uuid_prefix(self):
        vc, _ = _issue_vc()
        assert vc.id.startswith("urn:uuid:")

    def test_id_contains_valid_uuid(self):
        vc, _ = _issue_vc()
        raw = vc.id[len("urn:uuid:"):]
        uuid.UUID(raw)  # raises if invalid

    def test_issuer_preserved(self):
        vc, _ = _issue_vc(issuer_did="did:web:mycompany.io")
        assert vc.issuer == "did:web:mycompany.io"

    def test_issuance_date_is_set(self):
        vc, _ = _issue_vc()
        assert vc.issuance_date != ""

    def test_expiration_date_is_set(self):
        vc, _ = _issue_vc()
        assert vc.expiration_date is not None and vc.expiration_date != ""

    def test_credential_subject_agent_id(self):
        vc, _ = _issue_vc(agent_id="trading-bot")
        assert vc.credential_subject.agent_id == "trading-bot"

    def test_credential_subject_issued_to(self):
        vc, _ = _issue_vc(issued_to="paul@example.com")
        assert vc.credential_subject.issued_to == "paul@example.com"

    def test_credential_subject_permissions(self):
        perms = ["read:data", "execute:actions"]
        vc, _ = _issue_vc(permissions=perms)
        assert set(vc.credential_subject.permissions) == set(perms)

    def test_credential_subject_id_is_did(self):
        vc, _ = _issue_vc(agent_id="my-agent")
        assert vc.credential_subject.id.startswith("did:web:")
        assert "my-agent" in vc.credential_subject.id

    def test_proof_type(self):
        vc, _ = _issue_vc()
        assert vc.proof.type == "Ed25519Signature2020"

    def test_proof_purpose(self):
        vc, _ = _issue_vc()
        assert vc.proof.proof_purpose == "assertionMethod"

    def test_proof_value_starts_with_z(self):
        vc, _ = _issue_vc()
        assert vc.proof.proof_value.startswith("z")

    def test_verification_method_is_did_key(self):
        vc, _ = _issue_vc()
        assert vc.proof.verification_method.startswith("did:key:z")

    def test_attestation_hash_preserved(self):
        vc, _ = _issue_vc(attestation_hash="abc123")
        assert vc.credential_subject.attestation_hash == "abc123"

    def test_attestation_hash_none_by_default(self):
        vc, _ = _issue_vc()
        assert vc.credential_subject.attestation_hash is None

    def test_two_vcs_have_different_ids(self):
        vc1, _ = _issue_vc()
        vc2, _ = _issue_vc()
        assert vc1.id != vc2.id


# ------------------------------------------------------------------ #
# verify_verifiable_credential — valid                                 #
# ------------------------------------------------------------------ #


class TestVerifyVerifiableCredential:
    def test_valid_vc_passes(self):
        vc, _ = _issue_vc()
        result = verify_verifiable_credential(vc)
        assert result["valid"] is True

    def test_returns_agent_id_on_success(self):
        vc, _ = _issue_vc(agent_id="analyzer-bot")
        result = verify_verifiable_credential(vc)
        assert result["agent_id"] == "analyzer-bot"

    def test_returns_permissions_on_success(self):
        perms = ["read:data", "execute:actions"]
        vc, _ = _issue_vc(permissions=perms)
        result = verify_verifiable_credential(vc)
        assert set(result["permissions"]) == set(perms)

    def test_reason_none_on_success(self):
        vc, _ = _issue_vc()
        assert verify_verifiable_credential(vc)["reason"] is None


# ------------------------------------------------------------------ #
# verify_verifiable_credential — failures                              #
# ------------------------------------------------------------------ #


class TestVerifyVerifiableCredentialFailures:
    def test_expired_vc_fails(self):
        vc, _ = _issue_vc()
        expired = dataclasses.replace(vc, expiration_date="2020-01-01T00:00:00+00:00")
        result = verify_verifiable_credential(expired)
        assert result["valid"] is False
        assert "expired" in result["reason"].lower()

    def test_tampered_permissions_fails(self):
        vc, _ = _issue_vc()
        new_subject = dataclasses.replace(
            vc.credential_subject, permissions=["spend:budget"]
        )
        tampered = dataclasses.replace(vc, credential_subject=new_subject)
        assert verify_verifiable_credential(tampered)["valid"] is False

    def test_tampered_agent_id_fails(self):
        vc, _ = _issue_vc()
        new_subject = dataclasses.replace(vc.credential_subject, agent_id="evil-agent")
        tampered = dataclasses.replace(vc, credential_subject=new_subject)
        assert verify_verifiable_credential(tampered)["valid"] is False

    def test_tampered_proof_value_fails(self):
        vc, _ = _issue_vc()
        new_proof = dataclasses.replace(vc.proof, proof_value="zFakeSignatureValue")
        tampered = dataclasses.replace(vc, proof=new_proof)
        result = verify_verifiable_credential(tampered)
        assert result["valid"] is False

    def test_non_did_key_verification_method_fails(self):
        vc, _ = _issue_vc()
        new_proof = dataclasses.replace(
            vc.proof, verification_method="did:web:example.com#key-1"
        )
        tampered = dataclasses.replace(vc, proof=new_proof)
        result = verify_verifiable_credential(tampered)
        assert result["valid"] is False
        assert "did:key" in result["reason"]

    def test_proof_value_without_z_prefix_fails(self):
        vc, _ = _issue_vc()
        # Strip the 'z' multibase prefix.
        new_proof = dataclasses.replace(vc.proof, proof_value=vc.proof.proof_value[1:])
        tampered = dataclasses.replace(vc, proof=new_proof)
        result = verify_verifiable_credential(tampered)
        assert result["valid"] is False

    def test_agent_id_none_on_failure(self):
        vc, _ = _issue_vc()
        expired = dataclasses.replace(vc, expiration_date="2020-01-01T00:00:00+00:00")
        result = verify_verifiable_credential(expired)
        assert result["agent_id"] is None

    def test_permissions_none_on_failure(self):
        vc, _ = _issue_vc()
        expired = dataclasses.replace(vc, expiration_date="2020-01-01T00:00:00+00:00")
        result = verify_verifiable_credential(expired)
        assert result["permissions"] is None


# ------------------------------------------------------------------ #
# agent_credential_to_vc                                               #
# ------------------------------------------------------------------ #


class TestAgentCredentialToVC:
    def _cred(self):
        kp = generate_keypair()
        return issue_credential(
            agent_id="service-agent",
            issued_to="ops-team",
            permissions=["read:data", "write:data"],
            expires_in="1h",
            private_key=kp.private_key,
        ), kp

    def test_returns_verifiable_credential(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert isinstance(vc, VerifiableCredential)

    def test_agent_id_preserved(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert vc.credential_subject.agent_id == "service-agent"

    def test_issued_to_preserved(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert vc.credential_subject.issued_to == "ops-team"

    def test_permissions_preserved(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert set(vc.credential_subject.permissions) == {"read:data", "write:data"}

    def test_issuer_preserved(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:mycompany.io")
        assert vc.issuer == "did:web:mycompany.io"

    def test_id_includes_original_uuid(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert cred.id in vc.id

    def test_proof_type_is_ed25519(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert vc.proof.type == "Ed25519Signature2020"

    def test_proof_value_starts_with_z(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert vc.proof.proof_value.startswith("z")

    def test_verification_method_is_did_key(self):
        cred, _ = self._cred()
        vc = agent_credential_to_vc(cred, "did:web:cordprotocol.dev")
        assert vc.proof.verification_method.startswith("did:key:z")


# ------------------------------------------------------------------ #
# vc_to_agent_credential_dict                                          #
# ------------------------------------------------------------------ #


class TestVCToAgentCredentialDict:
    def test_agent_id_extracted(self):
        vc, _ = _issue_vc(agent_id="my-agent")
        d = vc_to_agent_credential_dict(vc)
        assert d["agent_id"] == "my-agent"

    def test_issued_to_extracted(self):
        vc, _ = _issue_vc(issued_to="corp@example.com")
        d = vc_to_agent_credential_dict(vc)
        assert d["issued_to"] == "corp@example.com"

    def test_permissions_extracted(self):
        vc, _ = _issue_vc(permissions=["execute:actions"])
        d = vc_to_agent_credential_dict(vc)
        assert d["permissions"] == ["execute:actions"]

    def test_id_strips_urn_uuid_prefix(self):
        vc, _ = _issue_vc()
        d = vc_to_agent_credential_dict(vc)
        assert not d["id"].startswith("urn:uuid:")

    def test_issuer_public_key_recovered(self):
        kp = generate_keypair()
        vc = issue_verifiable_credential(
            agent_id="a",
            issued_to="b",
            permissions=[],
            expires_in="1h",
            private_key=kp.private_key,
            issuer_did="did:web:example.com",
        )
        d = vc_to_agent_credential_dict(vc)
        assert d["issuer_public_key"] == kp.public_key

    def test_signature_is_non_empty(self):
        vc, _ = _issue_vc()
        d = vc_to_agent_credential_dict(vc)
        assert d["signature"] != ""

    def test_round_trip_via_agent_credential_to_vc(self):
        orig_cred = issue_credential(
            agent_id="round-trip-agent",
            issued_to="tester",
            permissions=["read:data"],
            expires_in="24h",
            private_key=generate_keypair().private_key,
        )
        vc = agent_credential_to_vc(orig_cred, "did:web:cordprotocol.dev")
        d = vc_to_agent_credential_dict(vc)
        assert d["agent_id"] == orig_cred.agent_id
        assert d["issued_to"] == orig_cred.issued_to
        assert d["permissions"] == orig_cred.permissions
        assert d["issuer_public_key"] == orig_cred.issuer_public_key
