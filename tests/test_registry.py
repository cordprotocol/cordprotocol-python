"""
Tests for cordprotocol.registry — register_agent, lookup_agent,
check_revocation_status, revoke_credential, and their sync wrappers.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cordprotocol.registry import (
    AgentRegistration,
    RegistryError,
    RevocationError,
    check_revocation_status,
    check_revocation_status_sync,
    lookup_agent,
    lookup_agent_sync,
    register_agent,
    register_agent_sync,
    revoke_credential,
    revoke_credential_sync,
)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

_REGISTRATION_DATA = {
    "id": "reg-001",
    "agent_id": "test-agent",
    "public_key": "dGVzdHB1YmxpY2tleQ==",
    "issued_to": "alice",
    "registered_at": "2024-01-01T00:00:00+00:00",
    "credential_count": 1,
    "active": True,
    "domain": None,
    "last_seen": None,
}


def _mock_httpx(method: str, status_code: int, json_data: dict = None, text: str = "error"):
    """Create a context-manager patch for httpx.AsyncClient."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.is_success = status_code < 400
    mock_response.json.return_value = json_data or {}
    mock_response.text = text

    mock_client = AsyncMock()
    getattr(mock_client, method).return_value = mock_response

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client

    return patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm)


# ------------------------------------------------------------------ #
# register_agent                                                       #
# ------------------------------------------------------------------ #


class TestRegisterAgent:
    async def test_success_returns_registration(self):
        with _mock_httpx("post", 201, _REGISTRATION_DATA):
            result = await register_agent("test-agent", "pubkey==", "alice")
        assert isinstance(result, AgentRegistration)

    async def test_success_fields_populated(self):
        with _mock_httpx("post", 201, _REGISTRATION_DATA):
            result = await register_agent("test-agent", "pubkey==", "alice")
        assert result.id == "reg-001"
        assert result.agent_id == "test-agent"
        assert result.issued_to == "alice"
        assert result.credential_count == 1
        assert result.active is True

    async def test_domain_included_when_provided(self):
        data = {**_REGISTRATION_DATA, "domain": "example.com"}
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.is_success = True
        mock_response.json.return_value = data

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            result = await register_agent("test-agent", "pubkey==", "alice", domain="example.com")

        assert result.domain == "example.com"
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["domain"] == "example.com"

    async def test_domain_omitted_when_none(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.is_success = True
        mock_response.json.return_value = _REGISTRATION_DATA
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await register_agent("test-agent", "pubkey==", "alice")

        _, kwargs = mock_client.post.call_args
        assert "domain" not in kwargs["json"]

    async def test_http_error_raises_registry_error(self):
        with _mock_httpx("post", 500, text="Internal Server Error"):
            with pytest.raises(RegistryError, match="Registration failed"):
                await register_agent("test-agent", "pubkey==", "alice")

    async def test_network_error_raises_registry_error(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("connection refused")
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(RegistryError, match="Network error"):
                await register_agent("test-agent", "pubkey==", "alice")

    async def test_posts_to_correct_endpoint(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.is_success = True
        mock_response.json.return_value = _REGISTRATION_DATA
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await register_agent("test-agent", "pubkey==", "alice", api_url="https://test.example.com")

        url = mock_client.post.call_args[0][0]
        assert url == "https://test.example.com/v1/registry/agents"


# ------------------------------------------------------------------ #
# lookup_agent                                                         #
# ------------------------------------------------------------------ #


class TestLookupAgent:
    async def test_found_returns_registration(self):
        with _mock_httpx("get", 200, _REGISTRATION_DATA):
            result = await lookup_agent("test-agent")
        assert isinstance(result, AgentRegistration)

    async def test_found_fields_populated(self):
        with _mock_httpx("get", 200, _REGISTRATION_DATA):
            result = await lookup_agent("test-agent")
        assert result.agent_id == "test-agent"
        assert result.public_key == "dGVzdHB1YmxpY2tleQ=="

    async def test_not_found_returns_none(self):
        with _mock_httpx("get", 404):
            result = await lookup_agent("unknown-agent")
        assert result is None

    async def test_http_error_raises_registry_error(self):
        with _mock_httpx("get", 503, text="Service Unavailable"):
            with pytest.raises(RegistryError, match="Agent lookup failed"):
                await lookup_agent("test-agent")

    async def test_network_error_raises_registry_error(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("no route to host")
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(RegistryError, match="Network error"):
                await lookup_agent("test-agent")

    async def test_gets_correct_url(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_response.json.return_value = _REGISTRATION_DATA
        mock_client.get.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await lookup_agent("my-agent", api_url="https://test.example.com")

        url = mock_client.get.call_args[0][0]
        assert url == "https://test.example.com/v1/registry/agents/my-agent"


# ------------------------------------------------------------------ #
# check_revocation_status                                              #
# ------------------------------------------------------------------ #


class TestCheckRevocationStatus:
    async def test_not_revoked(self):
        data = {"revoked": False, "revoked_at": None, "reason": None}
        with _mock_httpx("get", 200, data):
            result = await check_revocation_status("cred-uuid")
        assert result["revoked"] is False
        assert result["revoked_at"] is None
        assert result["reason"] is None

    async def test_revoked_with_reason(self):
        data = {"revoked": True, "revoked_at": "2024-06-01T00:00:00+00:00", "reason": "compromised"}
        with _mock_httpx("get", 200, data):
            result = await check_revocation_status("cred-uuid")
        assert result["revoked"] is True
        assert result["revoked_at"] == "2024-06-01T00:00:00+00:00"
        assert result["reason"] == "compromised"

    async def test_returns_dict(self):
        with _mock_httpx("get", 200, {"revoked": False}):
            result = await check_revocation_status("cred-uuid")
        assert isinstance(result, dict)

    async def test_http_error_raises_registry_error(self):
        with _mock_httpx("get", 404, text="Not Found"):
            with pytest.raises(RegistryError, match="Revocation check failed"):
                await check_revocation_status("cred-uuid")

    async def test_network_error_raises_registry_error(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("timeout")
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(RegistryError, match="Network error"):
                await check_revocation_status("cred-uuid")


# ------------------------------------------------------------------ #
# revoke_credential                                                    #
# ------------------------------------------------------------------ #


class TestRevokeCredential:
    async def test_success_no_exception(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await revoke_credential("cred-uuid", "agent-1", "secret-key")

        mock_client.post.assert_called_once()

    async def test_bearer_token_sent(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await revoke_credential("cred-uuid", "agent-1", "my-api-key")

        _, kwargs = mock_client.post.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer my-api-key"

    async def test_reason_included_when_provided(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            await revoke_credential("cred-uuid", "agent-1", "key", reason="compromised")

        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["reason"] == "compromised"

    async def test_http_error_raises_revocation_error(self):
        with _mock_httpx("post", 401, text="Unauthorized"):
            with pytest.raises(RevocationError, match="Revocation failed"):
                await revoke_credential("cred-uuid", "agent-1", "bad-key")

    async def test_network_error_raises_revocation_error(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("refused")
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(RevocationError, match="Network error"):
                await revoke_credential("cred-uuid", "agent-1", "key")


# ------------------------------------------------------------------ #
# Sync wrappers                                                        #
# ------------------------------------------------------------------ #


class TestSyncWrappers:
    def test_register_agent_sync_returns_registration(self):
        with _mock_httpx("post", 201, _REGISTRATION_DATA):
            result = register_agent_sync("test-agent", "pubkey==", "alice")
        assert isinstance(result, AgentRegistration)
        assert result.agent_id == "test-agent"

    def test_lookup_agent_sync_found(self):
        with _mock_httpx("get", 200, _REGISTRATION_DATA):
            result = lookup_agent_sync("test-agent")
        assert isinstance(result, AgentRegistration)

    def test_lookup_agent_sync_not_found(self):
        with _mock_httpx("get", 404):
            result = lookup_agent_sync("unknown-agent")
        assert result is None

    def test_check_revocation_status_sync_returns_dict(self):
        data = {"revoked": False, "revoked_at": None, "reason": None}
        with _mock_httpx("get", 200, data):
            result = check_revocation_status_sync("cred-uuid")
        assert isinstance(result, dict)
        assert result["revoked"] is False

    def test_revoke_credential_sync_succeeds(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_client.post.return_value = mock_response
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_client

        with patch("cordprotocol.registry.httpx.AsyncClient", return_value=mock_cm):
            result = revoke_credential_sync("cred-uuid", "agent-1", "key")

        assert result is None
