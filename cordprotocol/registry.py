"""
Registry integration: register agents and manage credential revocation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

import httpx


class RegistryError(Exception):
    """Raised when a registry operation fails."""


class RevocationError(Exception):
    """Raised when a revocation operation fails."""


@dataclass
class AgentRegistration:
    """An agent's entry in the Cord Protocol registry."""

    id: str
    agent_id: str
    public_key: str
    issued_to: str
    registered_at: str
    credential_count: int
    active: bool
    domain: Optional[str] = None
    last_seen: Optional[str] = None


# ------------------------------------------------------------------ #
# Async API functions                                                  #
# ------------------------------------------------------------------ #


async def register_agent(
    agent_id: str,
    public_key: str,
    issued_to: str,
    domain: Optional[str] = None,
    api_url: str = "https://api.cordprotocol.dev",
) -> AgentRegistration:
    """Register an agent in the Cord Protocol registry.

    Args:
        agent_id: Unique identifier for the agent.
        public_key: Base64-encoded public key to register.
        issued_to: The entity the credential was issued to.
        domain: Optional domain the agent belongs to.
        api_url: Base URL of the Cord Protocol API.

    Returns:
        AgentRegistration describing the registered agent.

    Raises:
        RegistryError: If the request fails or the server returns an error.
    """
    payload: dict = {
        "agent_id": agent_id,
        "public_key": public_key,
        "issued_to": issued_to,
    }
    if domain is not None:
        payload["domain"] = domain

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{api_url}/v1/registry/agents", json=payload)
        except httpx.RequestError as exc:
            raise RegistryError(f"Network error registering agent: {exc}") from exc

        if not resp.is_success:
            raise RegistryError(
                f"Registration failed: HTTP {resp.status_code} — {resp.text}"
            )

        data = resp.json()
        return AgentRegistration(
            id=data["id"],
            agent_id=data["agent_id"],
            public_key=data["public_key"],
            issued_to=data["issued_to"],
            registered_at=data["registered_at"],
            credential_count=data.get("credential_count", 0),
            active=data.get("active", True),
            domain=data.get("domain"),
            last_seen=data.get("last_seen"),
        )


async def lookup_agent(
    agent_id: str,
    api_url: str = "https://api.cordprotocol.dev",
) -> Optional[AgentRegistration]:
    """Look up an agent in the Cord Protocol registry.

    Args:
        agent_id: The agent identifier to look up.
        api_url: Base URL of the Cord Protocol API.

    Returns:
        AgentRegistration if the agent is registered, ``None`` if not found.

    Raises:
        RegistryError: On non-404 HTTP errors or network failures.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{api_url}/v1/registry/agents/{agent_id}")
        except httpx.RequestError as exc:
            raise RegistryError(f"Network error looking up agent: {exc}") from exc

        if resp.status_code == 404:
            return None

        if not resp.is_success:
            raise RegistryError(
                f"Agent lookup failed: HTTP {resp.status_code} — {resp.text}"
            )

        data = resp.json()
        return AgentRegistration(
            id=data["id"],
            agent_id=data["agent_id"],
            public_key=data["public_key"],
            issued_to=data["issued_to"],
            registered_at=data["registered_at"],
            credential_count=data.get("credential_count", 0),
            active=data.get("active", True),
            domain=data.get("domain"),
            last_seen=data.get("last_seen"),
        )


async def check_revocation_status(
    credential_id: str,
    api_url: str = "https://api.cordprotocol.dev",
) -> dict:
    """Check the revocation status of a credential.

    Args:
        credential_id: UUID of the credential to check.
        api_url: Base URL of the Cord Protocol API.

    Returns:
        Dict with keys: ``revoked`` (bool), ``revoked_at`` (str | None),
        ``reason`` (str | None).

    Raises:
        RegistryError: On request or server failures.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{api_url}/v1/credentials/{credential_id}/status")
        except httpx.RequestError as exc:
            raise RegistryError(f"Network error checking revocation status: {exc}") from exc

        if not resp.is_success:
            raise RegistryError(
                f"Revocation check failed: HTTP {resp.status_code} — {resp.text}"
            )

        data = resp.json()
        return {
            "revoked": bool(data.get("revoked", False)),
            "revoked_at": data.get("revoked_at"),
            "reason": data.get("reason"),
        }


async def revoke_credential(
    credential_id: str,
    agent_id: str,
    api_key: str,
    reason: Optional[str] = None,
    api_url: str = "https://api.cordprotocol.dev",
) -> None:
    """Revoke a credential in the Cord Protocol registry.

    Args:
        credential_id: UUID of the credential to revoke.
        agent_id: ID of the agent that owns the credential.
        api_key: API key for authentication.
        reason: Optional human-readable reason for revocation.
        api_url: Base URL of the Cord Protocol API.

    Raises:
        RevocationError: If the request fails or the server returns an error.
    """
    payload: dict = {
        "credential_id": credential_id,
        "agent_id": agent_id,
    }
    if reason is not None:
        payload["reason"] = reason

    headers = {"Authorization": f"Bearer {api_key}"}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{api_url}/v1/credentials/revoke",
                json=payload,
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise RevocationError(f"Network error revoking credential: {exc}") from exc

        if not resp.is_success:
            raise RevocationError(
                f"Revocation failed: HTTP {resp.status_code} — {resp.text}"
            )


# ------------------------------------------------------------------ #
# Sync wrappers                                                        #
# ------------------------------------------------------------------ #


def register_agent_sync(
    agent_id: str,
    public_key: str,
    issued_to: str,
    domain: Optional[str] = None,
    api_url: str = "https://api.cordprotocol.dev",
) -> AgentRegistration:
    """Synchronous wrapper for :func:`register_agent`."""
    return asyncio.run(register_agent(agent_id, public_key, issued_to, domain, api_url))


def lookup_agent_sync(
    agent_id: str,
    api_url: str = "https://api.cordprotocol.dev",
) -> Optional[AgentRegistration]:
    """Synchronous wrapper for :func:`lookup_agent`."""
    return asyncio.run(lookup_agent(agent_id, api_url))


def check_revocation_status_sync(
    credential_id: str,
    api_url: str = "https://api.cordprotocol.dev",
) -> dict:
    """Synchronous wrapper for :func:`check_revocation_status`."""
    return asyncio.run(check_revocation_status(credential_id, api_url))


def revoke_credential_sync(
    credential_id: str,
    agent_id: str,
    api_key: str,
    reason: Optional[str] = None,
    api_url: str = "https://api.cordprotocol.dev",
) -> None:
    """Synchronous wrapper for :func:`revoke_credential`."""
    asyncio.run(revoke_credential(credential_id, agent_id, api_key, reason, api_url))
