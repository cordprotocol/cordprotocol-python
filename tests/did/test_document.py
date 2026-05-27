"""
Tests for cordprotocol.did.document — key format conversion and DID document creation.
"""

import base64

import pytest

from cordprotocol import generate_keypair
from cordprotocol.did.document import (
    _base58_decode,
    _base58_encode,
    _ED25519_MULTICODEC_PREFIX,
    create_did_document,
    multibase_to_public_key,
    public_key_to_multibase,
)


# ------------------------------------------------------------------ #
# base58 encode / decode                                               #
# ------------------------------------------------------------------ #


class TestBase58:
    def test_encode_single_byte(self):
        assert _base58_encode(bytes([1])) == "2"

    def test_encode_leading_zero_byte(self):
        # Each leading zero byte maps to a leading '1' in base58.
        result = _base58_encode(bytes([0, 1]))
        assert result == "12"

    def test_decode_single_byte(self):
        assert _base58_decode("2") == bytes([1])

    def test_decode_leading_one(self):
        assert _base58_decode("12") == bytes([0, 1])

    def test_round_trip_arbitrary_bytes(self):
        raw = bytes(range(32))
        assert _base58_decode(_base58_encode(raw)) == raw

    def test_round_trip_32_zero_bytes(self):
        raw = bytes(32)
        assert _base58_decode(_base58_encode(raw)) == raw


# ------------------------------------------------------------------ #
# public_key_to_multibase                                              #
# ------------------------------------------------------------------ #


class TestPublicKeyToMultibase:
    def test_starts_with_z(self):
        kp = generate_keypair()
        result = public_key_to_multibase(kp.public_key)
        assert result.startswith("z")

    def test_contains_ed25519_multicodec_prefix(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        decoded = _base58_decode(multibase[1:])
        assert decoded[:2] == _ED25519_MULTICODEC_PREFIX

    def test_raw_key_bytes_preserved(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        decoded = _base58_decode(multibase[1:])
        raw = decoded[len(_ED25519_MULTICODEC_PREFIX):]
        assert raw == base64.b64decode(kp.public_key)

    def test_different_keys_produce_different_multibase(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert public_key_to_multibase(kp1.public_key) != public_key_to_multibase(kp2.public_key)

    def test_result_is_string(self):
        kp = generate_keypair()
        assert isinstance(public_key_to_multibase(kp.public_key), str)


# ------------------------------------------------------------------ #
# multibase_to_public_key                                              #
# ------------------------------------------------------------------ #


class TestMultibaseToPublicKey:
    def test_round_trip(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        recovered = multibase_to_public_key(multibase)
        assert recovered == kp.public_key

    def test_wrong_prefix_raises(self):
        with pytest.raises(ValueError, match="base58btc multibase"):
            multibase_to_public_key("mSomeOtherMultibase")

    def test_wrong_multicodec_raises(self):
        # Encode bytes with the wrong multicodec prefix.
        raw = bytes([0x12, 0x20]) + bytes(32)  # SHA-256 multicodec prefix
        bad_multibase = "z" + _base58_encode(raw)
        with pytest.raises(ValueError, match="multicodec"):
            multibase_to_public_key(bad_multibase)


# ------------------------------------------------------------------ #
# create_did_document                                                  #
# ------------------------------------------------------------------ #


class TestCreateDIDDocument:
    def _doc(self, service_endpoint=None):
        kp = generate_keypair()
        did = "did:web:cordprotocol.dev:agents:test-agent"
        return create_did_document(did, kp.public_key, service_endpoint), kp

    def test_id_matches_did(self):
        doc, _ = self._doc()
        assert doc.id == "did:web:cordprotocol.dev:agents:test-agent"

    def test_context_includes_did_v1(self):
        doc, _ = self._doc()
        assert "https://www.w3.org/ns/did/v1" in doc.context

    def test_context_includes_ed25519_suite(self):
        doc, _ = self._doc()
        assert any("ed25519" in c.lower() for c in doc.context)

    def test_single_verification_method(self):
        doc, _ = self._doc()
        assert len(doc.verification_method) == 1

    def test_verification_method_type(self):
        doc, _ = self._doc()
        assert doc.verification_method[0].type == "Ed25519VerificationKey2020"

    def test_verification_method_id(self):
        doc, _ = self._doc()
        vm = doc.verification_method[0]
        assert vm.id == "did:web:cordprotocol.dev:agents:test-agent#key-1"

    def test_verification_method_controller(self):
        doc, _ = self._doc()
        assert doc.verification_method[0].controller == doc.id

    def test_verification_method_public_key_multibase_starts_with_z(self):
        doc, _ = self._doc()
        assert doc.verification_method[0].public_key_multibase.startswith("z")

    def test_authentication_references_key(self):
        doc, _ = self._doc()
        key_id = doc.verification_method[0].id
        assert key_id in doc.authentication

    def test_assertion_method_references_key(self):
        doc, _ = self._doc()
        key_id = doc.verification_method[0].id
        assert key_id in doc.assertion_method

    def test_service_none_by_default(self):
        doc, _ = self._doc()
        assert doc.service is None

    def test_service_set_when_provided(self):
        doc, _ = self._doc(service_endpoint="https://agent.example.com")
        assert doc.service is not None
        assert len(doc.service) == 1
        assert doc.service[0].service_endpoint == "https://agent.example.com"

    def test_service_type_is_agent_service(self):
        doc, _ = self._doc(service_endpoint="https://agent.example.com")
        assert doc.service[0].type == "AgentService"

    def test_public_key_round_trips_through_multibase(self):
        kp = generate_keypair()
        did = "did:web:example.com:agents:my-agent"
        doc = create_did_document(did, kp.public_key)
        recovered = multibase_to_public_key(doc.verification_method[0].public_key_multibase)
        assert recovered == kp.public_key
