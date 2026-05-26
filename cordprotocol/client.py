"""
High-level CordProtocol client with optional registry and revocation integration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from cordprotocol.credential import AgentCredential, VerificationResult
from cordprotocol.issuer import issue_credential as _issue_credential
from cordprotocol.registry import (
    AgentRegistration,
    RevocationError,
    check_revocation_status,
    lookup_agent,
    register_agent,
    revoke_credential as _revoke_credential,
)
from cordprotocol.verifier import verify_credential as _verify_credential


@dataclass
class CordProtocolConfig:
    """Configuration for the CordProtocol client.

    Attributes:
        registry: If True, ``issue_credential`` auto-posts the agent's
                  public key to the Cord Protocol registry.
        api_key: API key for authenticated operations (revocation).
                 Also enables revocation checking in ``verify_credential``.
        api_url: Base URL of the Cord Protocol API.
    """

    registry: bool = False
    api_key: Optional[str] = None
    api_url: str = "https://api.cordprotocol.dev"


class CordProtocol:
    """High-level client for the Cord Protocol API.

    Wraps the core issuer and verifier with optional registry integration.
    Registry failures are always silent so credential operations are not
    blocked by network issues.
    """

    def __init__(self, config: Optional[CordProtocolConfig] = None) -> None:
        self._config = config or CordProtocolConfig()

    def issue_credential(
        self,
        agent_id: str,
        issued_to: str,
        permissions: List[str],
        expires_in: str,
        private_key: str,
        attestation_hash: Optional[str] = None,
    ) -> AgentCredential:
        """Issue a signed credential.

        When ``registry=True`` in config, the agent's public key is posted to
        the Cord Protocol registry after issuance.  Registry failures are
        silent — the credential is returned regardless.

        Args:
            agent_id: Unique identifier for the agent.
            issued_to: Entity receiving the credential.
            permissions: Permission scopes to grant.
            expires_in: Expiry duration, e.g. ``"24h"``, ``"7d"``.
            private_key: Base64-encoded private key used to sign.
            attestation_hash: Optional SHA-256 of an audit document.

        Returns:
            A fully signed AgentCredential.
        """
        credential = _issue_credential(
            agent_id=agent_id,
            issued_to=issued_to,
            permissions=permissions,
            expires_in=expires_in,
            private_key=private_key,
            attestation_hash=attestation_hash,
        )

        if self._config.registry:
            try:
                asyncio.run(
                    register_agent(
                        agent_id=credential.agent_id,
                        public_key=credential.issuer_public_key,
                        issued_to=issued_to,
                        api_url=self._config.api_url,
                    )
                )
            except Exception:
                pass  # registry failure must never block credential issuance

        return credential

    def verify_credential(
        self,
        credential: AgentCredential,
    ) -> VerificationResult:
        """Verify a credential's signature and expiry.

        When ``api_key`` is set in config, also checks the registry for
        revocation.  A revoked credential returns ``valid=False``.  Network
        errors during the revocation check are silent.

        Args:
            credential: The AgentCredential to verify.

        Returns:
            VerificationResult with ``valid=True`` on success, or
            ``valid=False`` with an ``error`` message on failure.
        """
        result = _verify_credential(credential)
        if not result.valid:
            return result

        if self._config.api_key:
            try:
                status = asyncio.run(
                    check_revocation_status(
                        credential.id,
                        api_url=self._config.api_url,
                    )
                )
                if status.get("revoked"):
                    return VerificationResult(
                        valid=False,
                        error="Credential has been revoked.",
                    )
            except Exception:
                pass  # revocation check failure must never block verification

        return result

    def revoke_credential(
        self,
        credential_id: str,
        agent_id: str,
        reason: Optional[str] = None,
    ) -> None:
        """Revoke a credential via the Cord Protocol API.

        Args:
            credential_id: UUID of the credential to revoke.
            agent_id: ID of the agent that owns the credential.
            reason: Optional human-readable reason for revocation.

        Raises:
            ValueError: If no ``api_key`` is set in config.
            RevocationError: If the revocation request fails.
        """
        if not self._config.api_key:
            raise ValueError(
                "api_key is required in CordProtocolConfig to revoke credentials."
            )

        asyncio.run(
            _revoke_credential(
                credential_id=credential_id,
                agent_id=agent_id,
                api_key=self._config.api_key,
                reason=reason,
                api_url=self._config.api_url,
            )
        )

    def lookup_agent(
        self,
        agent_id: str,
    ) -> Optional[AgentRegistration]:
        """Look up an agent in the Cord Protocol registry.

        Args:
            agent_id: The agent identifier to look up.

        Returns:
            AgentRegistration if found, ``None`` if not registered.
        """
        return asyncio.run(
            lookup_agent(
                agent_id=agent_id,
                api_url=self._config.api_url,
            )
        )
