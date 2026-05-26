"""
Tests for CordProtocol client — issue_credential, verify_credential,
revoke_credential, and lookup_agent.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cordprotocol import (
    AgentCredential,
    VerificationResult,
    generate_keypair,
    issue_credential,
)
from cordprotocol.client import CordProtocol, CordProtocolConfig
from cordprotocol.registry import AgentRegistration, RegistryError, RevocationError


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #


@pytest.fixture
def kp():
    return generate_keypair()


@pytest.fixture
def valid_credential(kp):
    return issue_credential(
        agent_id="test-agent",
        issued_to="alice",
        permissions=["read:data"],
        expires_in="24h",
        private_key=kp.private_key,
    )


_SAMPLE_REGISTRATION = AgentRegistration(
    id="reg-001",
    agent_id="test-agent",
    public_key="dGVzdHB1YmxpY2tleQ==",
    issued_to="alice",
    registered_at="2024-01-01T00:00:00+00:00",
    credential_count=1,
    active=True,
)


# ------------------------------------------------------------------ #
# CordProtocolConfig defaults                                          #
# ------------------------------------------------------------------ #


class TestCordProtocolConfig:
    def test_default_registry_false(self):
        config = CordProtocolConfig()
        assert config.registry is False

    def test_default_api_key_none(self):
        config = CordProtocolConfig()
        assert config.api_key is None

    def test_default_api_url(self):
        config = CordProtocolConfig()
        assert config.api_url == "https://api.cordprotocol.dev"

    def test_cord_protocol_uses_default_config_when_none(self):
        cord = CordProtocol()
        assert cord._config.registry is False
        assert cord._config.api_key is None


# ------------------------------------------------------------------ #
# issue_credential                                                     #
# ------------------------------------------------------------------ #


class TestIssueCredential:
    def test_returns_agent_credential(self, kp):
        cord = CordProtocol()
        cred = cord.issue_credential(
            agent_id="agent-1",
            issued_to="alice",
            permissions=["read:data"],
            expires_in="24h",
            private_key=kp.private_key,
        )
        assert isinstance(cred, AgentCredential)

    def test_no_registry_call_when_registry_false(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=False))
        with patch("cordprotocol.client.register_agent", new_callable=AsyncMock) as mock_reg:
            cord.issue_credential(
                agent_id="agent-1",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        mock_reg.assert_not_called()

    def test_registry_called_when_registry_true(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=True))
        with patch(
            "cordprotocol.client.register_agent",
            new_callable=AsyncMock,
            return_value=_SAMPLE_REGISTRATION,
        ) as mock_reg:
            cord.issue_credential(
                agent_id="agent-1",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        mock_reg.assert_called_once()

    def test_registry_receives_correct_agent_id(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=True))
        with patch(
            "cordprotocol.client.register_agent",
            new_callable=AsyncMock,
            return_value=_SAMPLE_REGISTRATION,
        ) as mock_reg:
            cord.issue_credential(
                agent_id="my-special-agent",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        _, kwargs = mock_reg.call_args
        assert kwargs["agent_id"] == "my-special-agent"

    def test_registry_failure_does_not_raise(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=True))
        with patch(
            "cordprotocol.client.register_agent",
            new_callable=AsyncMock,
            side_effect=RegistryError("network error"),
        ):
            cred = cord.issue_credential(
                agent_id="agent-1",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        assert isinstance(cred, AgentCredential)

    def test_registry_exception_does_not_raise(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=True))
        with patch(
            "cordprotocol.client.register_agent",
            new_callable=AsyncMock,
            side_effect=Exception("unexpected error"),
        ):
            cred = cord.issue_credential(
                agent_id="agent-1",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        assert isinstance(cred, AgentCredential)

    def test_custom_api_url_passed_to_registry(self, kp):
        cord = CordProtocol(CordProtocolConfig(registry=True, api_url="https://staging.example.com"))
        with patch(
            "cordprotocol.client.register_agent",
            new_callable=AsyncMock,
            return_value=_SAMPLE_REGISTRATION,
        ) as mock_reg:
            cord.issue_credential(
                agent_id="agent-1",
                issued_to="alice",
                permissions=["read:data"],
                expires_in="24h",
                private_key=kp.private_key,
            )
        _, kwargs = mock_reg.call_args
        assert kwargs["api_url"] == "https://staging.example.com"


# ------------------------------------------------------------------ #
# verify_credential                                                    #
# ------------------------------------------------------------------ #


class TestVerifyCredential:
    def test_valid_credential_passes(self, valid_credential):
        cord = CordProtocol()
        result = cord.verify_credential(valid_credential)
        assert result.valid is True

    def test_returns_verification_result(self, valid_credential):
        cord = CordProtocol()
        assert isinstance(cord.verify_credential(valid_credential), VerificationResult)

    def test_no_revocation_check_without_api_key(self, valid_credential):
        cord = CordProtocol(CordProtocolConfig(api_key=None))
        with patch(
            "cordprotocol.client.check_revocation_status", new_callable=AsyncMock
        ) as mock_check:
            cord.verify_credential(valid_credential)
        mock_check.assert_not_called()

    def test_revocation_check_called_with_api_key(self, valid_credential):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        not_revoked = {"revoked": False, "revoked_at": None, "reason": None}
        with patch(
            "cordprotocol.client.check_revocation_status",
            new_callable=AsyncMock,
            return_value=not_revoked,
        ) as mock_check:
            cord.verify_credential(valid_credential)
        mock_check.assert_called_once()

    def test_not_revoked_returns_valid(self, valid_credential):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        not_revoked = {"revoked": False, "revoked_at": None, "reason": None}
        with patch(
            "cordprotocol.client.check_revocation_status",
            new_callable=AsyncMock,
            return_value=not_revoked,
        ):
            result = cord.verify_credential(valid_credential)
        assert result.valid is True

    def test_revoked_credential_returns_invalid(self, valid_credential):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        revoked = {"revoked": True, "revoked_at": "2024-06-01T00:00:00+00:00", "reason": "compromised"}
        with patch(
            "cordprotocol.client.check_revocation_status",
            new_callable=AsyncMock,
            return_value=revoked,
        ):
            result = cord.verify_credential(valid_credential)
        assert result.valid is False
        assert "revoked" in result.error.lower()

    def test_revocation_check_error_is_silent(self, valid_credential):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        with patch(
            "cordprotocol.client.check_revocation_status",
            new_callable=AsyncMock,
            side_effect=Exception("network error"),
        ):
            result = cord.verify_credential(valid_credential)
        assert result.valid is True

    def test_already_invalid_credential_skips_revocation(self, kp):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        tampered = issue_credential(
            "agent-1", "alice", ["read:data"], "24h", kp.private_key
        ).model_copy(update={"signature": "dGFtcGVyZWQ="})
        with patch(
            "cordprotocol.client.check_revocation_status", new_callable=AsyncMock
        ) as mock_check:
            result = cord.verify_credential(tampered)
        mock_check.assert_not_called()
        assert result.valid is False


# ------------------------------------------------------------------ #
# revoke_credential                                                    #
# ------------------------------------------------------------------ #


class TestRevokeCredential:
    def test_raises_without_api_key(self):
        cord = CordProtocol(CordProtocolConfig(api_key=None))
        with pytest.raises(ValueError, match="api_key"):
            cord.revoke_credential("cred-uuid", "agent-1")

    def test_success_with_api_key(self):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        with patch(
            "cordprotocol.client._revoke_credential",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_revoke:
            cord.revoke_credential("cred-uuid", "agent-1")
        mock_revoke.assert_called_once()

    def test_reason_forwarded(self):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        with patch(
            "cordprotocol.client._revoke_credential",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_revoke:
            cord.revoke_credential("cred-uuid", "agent-1", reason="decommissioned")
        _, kwargs = mock_revoke.call_args
        assert kwargs["reason"] == "decommissioned"

    def test_revocation_error_propagates(self):
        cord = CordProtocol(CordProtocolConfig(api_key="my-key"))
        with patch(
            "cordprotocol.client._revoke_credential",
            new_callable=AsyncMock,
            side_effect=RevocationError("forbidden"),
        ):
            with pytest.raises(RevocationError):
                cord.revoke_credential("cred-uuid", "agent-1")


# ------------------------------------------------------------------ #
# lookup_agent                                                         #
# ------------------------------------------------------------------ #


class TestLookupAgent:
    def test_found_returns_registration(self):
        cord = CordProtocol()
        with patch(
            "cordprotocol.client.lookup_agent",
            new_callable=AsyncMock,
            return_value=_SAMPLE_REGISTRATION,
        ):
            result = cord.lookup_agent("test-agent")
        assert isinstance(result, AgentRegistration)
        assert result.agent_id == "test-agent"

    def test_not_found_returns_none(self):
        cord = CordProtocol()
        with patch(
            "cordprotocol.client.lookup_agent",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = cord.lookup_agent("unknown-agent")
        assert result is None

    def test_custom_api_url_respected(self):
        cord = CordProtocol(CordProtocolConfig(api_url="https://staging.example.com"))
        with patch(
            "cordprotocol.client.lookup_agent",
            new_callable=AsyncMock,
            return_value=_SAMPLE_REGISTRATION,
        ) as mock_lookup:
            cord.lookup_agent("test-agent")
        _, kwargs = mock_lookup.call_args
        assert kwargs["api_url"] == "https://staging.example.com"
