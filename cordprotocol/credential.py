"""
AgentCredential and VerificationResult models.

The AgentCredential schema is intentionally compatible with the TypeScript
@cordprotocol/sdk so credentials can be reasoned about across ecosystems.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AgentCredential(BaseModel):
    """Cryptographically signed identity credential for an AI agent.

    Schema is compatible with the TypeScript ``@cordprotocol/sdk``
    AgentCredential so credentials serialised by one SDK can be
    inspected by the other.
    """

    id: str = Field(description="UUID v4 credential identifier")
    agent_id: str = Field(description="Identifier for the agent this credential belongs to")
    issued_to: str = Field(description="Entity the credential was issued to (user, org, etc.)")
    issued_at: datetime = Field(description="UTC timestamp when the credential was issued")
    expires_at: datetime = Field(description="UTC timestamp when the credential expires")
    permissions: List[str] = Field(description="Permission scopes granted to this agent")
    attestation_hash: Optional[str] = Field(
        default=None,
        description="Optional SHA-256 hash of an external attestation document",
    )
    issuer_public_key: str = Field(description="Base64-encoded public key of the issuer")
    signature: str = Field(description="Base64-encoded signature over the credential payload")

    # ------------------------------------------------------------------ #
    # Signing                                                              #
    # ------------------------------------------------------------------ #

    def to_signing_payload(self) -> bytes:
        """Return the canonical bytes that are signed or verified.

        The signature field is excluded.  Keys are sorted alphabetically
        and permissions are sorted so the payload is deterministic regardless
        of insertion order — matching the TypeScript SDK's behaviour.
        """
        payload = {
            "agent_id": self.agent_id,
            "attestation_hash": self.attestation_hash,
            "expires_at": self.expires_at.isoformat(),
            "id": self.id,
            "issued_at": self.issued_at.isoformat(),
            "issued_to": self.issued_to,
            "issuer_public_key": self.issuer_public_key,
            "permissions": sorted(self.permissions),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ------------------------------------------------------------------ #
    # Serialisation                                                        #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Serialise to a plain dict with ISO-8601 datetime strings."""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "issued_to": self.issued_to,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "permissions": self.permissions,
            "attestation_hash": self.attestation_hash,
            "issuer_public_key": self.issuer_public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AgentCredential:
        """Deserialise from a plain dict.  Parses ISO-8601 datetime strings."""
        return cls(**data)

    def to_json(self) -> str:
        """Serialise to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> AgentCredential:
        """Deserialise from a JSON string."""
        return cls.from_dict(json.loads(json_str))


class VerificationResult(BaseModel):
    """Result of a credential verification attempt."""

    valid: bool = Field(description="True if the credential passed all verification checks")
    error: Optional[str] = Field(
        default=None,
        description="Human-readable error message when valid=False",
    )
    credential: Optional[AgentCredential] = Field(
        default=None,
        description="The verified credential; present only when valid=True",
    )
