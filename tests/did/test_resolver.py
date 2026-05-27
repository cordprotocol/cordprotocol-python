"""
Tests for cordprotocol.did.resolver — agent_id_to_did, did_to_agent_id, resolve_did.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cordprotocol import generate_keypair
from cordprotocol.did.document import multibase_to_public_key, public_key_to_multibase
from cordprotocol.did.resolver import (
    _did_web_to_url,
    agent_id_to_did,
    did_to_agent_id,
    resolve_did,
    resolve_did_sync,
)
from cordprotocol.did.types import DIDResolutionResult


# ------------------------------------------------------------------ #
# agent_id_to_did                                                      #
# ------------------------------------------------------------------ #


class TestAgentIdToDid:
    def test_default_domain(self):
        result = agent_id_to_did("my-agent")
        assert result == "did:web:cordprotocol.dev:agents:my-agent"

    def test_custom_domain(self):
        result = agent_id_to_did("bot-001", domain="example.com")
        assert result == "did:web:example.com:agents:bot-001"

    def test_returns_string(self):
        assert isinstance(agent_id_to_did("x"), str)

    def test_did_method_prefix(self):
        assert agent_id_to_did("a").startswith("did:web:")

    def test_agents_path_segment(self):
        assert ":agents:" in agent_id_to_did("my-agent")


# ------------------------------------------------------------------ #
# did_to_agent_id                                                      #
# ------------------------------------------------------------------ #


class TestDidToAgentId:
    def test_extracts_agent_id(self):
        did = "did:web:cordprotocol.dev:agents:trading-agent"
        assert did_to_agent_id(did) == "trading-agent"

    def test_returns_none_for_non_web_did(self):
        assert did_to_agent_id("did:key:z6Mk...") is None

    def test_returns_none_for_non_agents_path(self):
        assert did_to_agent_id("did:web:example.com:users:alice") is None

    def test_returns_none_for_too_few_parts(self):
        assert did_to_agent_id("did:web:example.com") is None

    def test_returns_none_for_other_protocols(self):
        assert did_to_agent_id("https://example.com/agents/x") is None

    def test_custom_domain_preserved(self):
        did = "did:web:mycompany.io:agents:analyzer"
        assert did_to_agent_id(did) == "analyzer"

    def test_round_trip_with_agent_id_to_did(self):
        agent_id = "research-bot"
        did = agent_id_to_did(agent_id, domain="test.example.com")
        assert did_to_agent_id(did) == agent_id


# ------------------------------------------------------------------ #
# _did_web_to_url (internal helper)                                    #
# ------------------------------------------------------------------ #


class TestDidWebToUrl:
    def test_root_did_uses_well_known(self):
        url = _did_web_to_url("did:web:example.com")
        assert url == "https://example.com/.well-known/did.json"

    def test_path_did_appends_did_json(self):
        url = _did_web_to_url("did:web:example.com:agents:my-agent")
        assert url == "https://example.com/agents/my-agent/did.json"

    def test_cordprotocol_agent_url(self):
        url = _did_web_to_url("did:web:cordprotocol.dev:agents:trading-agent")
        assert url == "https://cordprotocol.dev/agents/trading-agent/did.json"


# ------------------------------------------------------------------ #
# resolve_did — did:key (offline)                                      #
# ------------------------------------------------------------------ #


class TestResolveDIDKey:
    async def test_resolves_successfully(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert result.did_document is not None

    async def test_returns_did_resolution_result(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert isinstance(result, DIDResolutionResult)

    async def test_document_id_matches_did(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert result.did_document.id == did

    async def test_has_verification_method(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert len(result.did_document.verification_method) > 0

    async def test_has_authentication(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert len(result.did_document.authentication) > 0

    async def test_has_assertion_method(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert len(result.did_document.assertion_method) > 0

    async def test_public_key_round_trips(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        vm = result.did_document.verification_method[0]
        recovered = multibase_to_public_key(vm.public_key_multibase)
        assert recovered == kp.public_key

    async def test_content_type_in_metadata(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = await resolve_did(did)
        assert result.did_resolution_metadata.get("contentType") == "application/did+ld+json"

    async def test_invalid_did_key_returns_error(self):
        result = await resolve_did("did:key:invalidmultibase")
        assert result.did_document is None
        assert "error" in result.did_resolution_metadata

    async def test_unsupported_method_returns_error(self):
        result = await resolve_did("did:ethr:0x1234")
        assert result.did_document is None
        assert result.did_resolution_metadata.get("error") == "methodNotSupported"


# ------------------------------------------------------------------ #
# resolve_did — did:web (mocked HTTP)                                  #
# ------------------------------------------------------------------ #


def _mock_web_response(status_code: int, json_data: dict = None):
    """Create a context-manager mock for httpx.AsyncClient.get."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.is_success = status_code < 400
    mock_response.json.return_value = json_data or {}

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client
    return patch("cordprotocol.did.resolver.httpx.AsyncClient", return_value=mock_cm)


class TestResolveDIDWeb:
    async def test_success_returns_document(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did_doc_json = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": multibase,
                }
            ],
            "authentication": ["did:web:example.com#key-1"],
            "assertionMethod": ["did:web:example.com#key-1"],
        }
        with _mock_web_response(200, did_doc_json):
            result = await resolve_did("did:web:example.com")
        assert result.did_document is not None

    async def test_http_404_returns_error(self):
        with _mock_web_response(404):
            result = await resolve_did("did:web:example.com:agents:unknown")
        assert result.did_document is None
        assert "error" in result.did_resolution_metadata


# ------------------------------------------------------------------ #
# resolve_did_sync                                                      #
# ------------------------------------------------------------------ #


class TestResolveDIDSync:
    def test_resolves_did_key_offline(self):
        kp = generate_keypair()
        multibase = public_key_to_multibase(kp.public_key)
        did = f"did:key:{multibase}"
        result = resolve_did_sync(did)
        assert isinstance(result, DIDResolutionResult)
        assert result.did_document is not None
