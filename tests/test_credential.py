"""
Tests for AgentCredential serialisation, deserialisation, and signing payload.
"""

import json
from datetime import datetime, timezone

import pytest

from cordprotocol import AgentCredential


_SAMPLE: dict = {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_id": "test-agent",
    "issued_to": "alice",
    "issued_at": "2024-01-01T00:00:00+00:00",
    "expires_at": "2024-01-02T00:00:00+00:00",
    "permissions": ["read:data", "write:data"],
    "attestation_hash": None,
    "issuer_public_key": "dGVzdHB1YmxpY2tleQ==",
    "signature": "dGVzdHNpZ25hdHVyZQ==",
}


def _make(**overrides) -> AgentCredential:
    return AgentCredential.from_dict({**_SAMPLE, **overrides})


# ------------------------------------------------------------------ #
# Serialisation                                                        #
# ------------------------------------------------------------------ #


class TestSerialization:
    def test_from_dict_roundtrip(self):
        cred = AgentCredential.from_dict(_SAMPLE)
        assert cred.to_dict() == _SAMPLE

    def test_from_json_roundtrip(self):
        cred = AgentCredential.from_json(json.dumps(_SAMPLE))
        assert json.loads(cred.to_json()) == _SAMPLE

    def test_to_dict_contains_all_fields(self):
        cred = _make()
        keys = set(cred.to_dict().keys())
        expected = {
            "id", "agent_id", "issued_to", "issued_at", "expires_at",
            "permissions", "attestation_hash", "issuer_public_key", "signature",
        }
        assert keys == expected

    def test_to_dict_datetimes_are_iso_strings(self):
        cred = _make()
        d = cred.to_dict()
        datetime.fromisoformat(d["issued_at"])
        datetime.fromisoformat(d["expires_at"])

    def test_permissions_list_preserved(self):
        cred = _make(permissions=["read:data", "execute:actions"])
        assert cred.permissions == ["read:data", "execute:actions"]

    def test_attestation_hash_none_by_default(self):
        cred = _make()
        assert cred.attestation_hash is None

    def test_attestation_hash_preserved_when_set(self):
        cred = _make(attestation_hash="abc123hash")
        assert cred.attestation_hash == "abc123hash"

    def test_attestation_hash_roundtrip(self):
        cred = _make(attestation_hash="deadbeef0123")
        restored = AgentCredential.from_dict(cred.to_dict())
        assert restored.attestation_hash == "deadbeef0123"

    def test_from_json_parses_datetimes(self):
        cred = _make()
        assert isinstance(cred.issued_at, datetime)
        assert isinstance(cred.expires_at, datetime)

    def test_issued_at_is_timezone_aware(self):
        cred = _make()
        assert cred.issued_at.tzinfo is not None


# ------------------------------------------------------------------ #
# Signing payload                                                      #
# ------------------------------------------------------------------ #


class TestSigningPayload:
    def test_payload_is_bytes(self):
        assert isinstance(_make().to_signing_payload(), bytes)

    def test_payload_is_deterministic(self):
        cred = _make()
        assert cred.to_signing_payload() == cred.to_signing_payload()

    def test_payload_excludes_signature(self):
        data = json.loads(_make().to_signing_payload())
        assert "signature" not in data

    def test_payload_keys_are_sorted(self):
        data = json.loads(_make().to_signing_payload())
        keys = list(data.keys())
        assert keys == sorted(keys)

    def test_payload_includes_required_fields(self):
        data = json.loads(_make().to_signing_payload())
        for field in ("agent_id", "id", "issued_to", "permissions", "issuer_public_key"):
            assert field in data

    def test_payload_permissions_are_sorted(self):
        cred = _make(permissions=["write:data", "read:data", "execute:actions"])
        data = json.loads(cred.to_signing_payload())
        assert data["permissions"] == sorted(["write:data", "read:data", "execute:actions"])

    def test_payload_changes_on_agent_id_change(self):
        p1 = _make(agent_id="agent-a").to_signing_payload()
        p2 = _make(agent_id="agent-b").to_signing_payload()
        assert p1 != p2

    def test_payload_changes_on_permission_change(self):
        p1 = _make(permissions=["read:data"]).to_signing_payload()
        p2 = _make(permissions=["write:data"]).to_signing_payload()
        assert p1 != p2

    def test_payload_changes_on_issued_to_change(self):
        p1 = _make(issued_to="alice").to_signing_payload()
        p2 = _make(issued_to="bob").to_signing_payload()
        assert p1 != p2

    def test_payload_same_permissions_different_order(self):
        """Permission order must not affect the payload (set semantics)."""
        p1 = _make(permissions=["read:data", "write:data"]).to_signing_payload()
        p2 = _make(permissions=["write:data", "read:data"]).to_signing_payload()
        assert p1 == p2

    def test_payload_is_valid_utf8_json(self):
        raw = _make().to_signing_payload()
        parsed = json.loads(raw.decode("utf-8"))
        assert isinstance(parsed, dict)

    def test_payload_attestation_hash_included(self):
        cred = _make(attestation_hash="hashvalue")
        data = json.loads(cred.to_signing_payload())
        assert data["attestation_hash"] == "hashvalue"
