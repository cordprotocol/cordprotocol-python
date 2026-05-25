"""
Credential issuance: generate_keypair() and issue_credential().
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cordprotocol.credential import AgentCredential
from cordprotocol.crypto.keys import KeyPair
from cordprotocol.crypto.keys import generate_keypair as _generate_keypair
from cordprotocol.crypto.signatures import CryptoBackend, default_backend


def generate_keypair(backend: CryptoBackend | None = None) -> KeyPair:
    """Generate a new cryptographic keypair for use as an issuer identity.

    Args:
        backend: Optional CryptoBackend override.  Defaults to Ed25519.
                 [PQ SWAP POINT] Pass ``DilithiumBackend()`` here to
                 produce post-quantum keypairs.

    Returns:
        KeyPair with base64-encoded private and public keys.
    """
    return _generate_keypair(backend)


def _parse_expires_in(expires_in: str) -> timedelta:
    """Parse a duration string into a timedelta.

    Supported units:
        'm'  minutes  e.g. "30m"
        'h'  hours    e.g. "24h"
        'd'  days     e.g. "7d"

    Raises:
        ValueError: If the format is invalid, the value is non-positive,
                    or the unit is unrecognised.
    """
    if not expires_in or len(expires_in) < 2:
        raise ValueError(
            f"Invalid expires_in format: {expires_in!r}. "
            "Expected e.g. '30m', '24h', '7d'."
        )

    unit = expires_in[-1].lower()
    try:
        value = int(expires_in[:-1])
    except ValueError:
        raise ValueError(
            f"Invalid expires_in value: {expires_in!r}. "
            "Numeric prefix required, e.g. '24h'."
        )

    if value <= 0:
        raise ValueError(
            f"expires_in must be positive, got {expires_in!r}."
        )

    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "d":
        return timedelta(days=value)

    raise ValueError(
        f"Unknown duration unit {unit!r} in {expires_in!r}. "
        "Use 'm' (minutes), 'h' (hours), or 'd' (days)."
    )


def issue_credential(
    agent_id: str,
    issued_to: str,
    permissions: List[str],
    expires_in: str,
    private_key: str,
    attestation_hash: Optional[str] = None,
    backend: CryptoBackend | None = None,
) -> AgentCredential:
    """Issue a signed identity credential for an AI agent.

    The issuer public key is derived from ``private_key`` automatically,
    so callers only need to manage a single secret.

    Args:
        agent_id: Unique identifier for the agent (e.g. ``"langchain-agent-1"``).
        issued_to: The entity receiving the credential (username, org, etc.).
        permissions: Permission scopes to grant.  See ``SCOPES`` for
                     the standard set.
        expires_in: How long until the credential expires.
                    Format: ``"<int><unit>"`` where unit is ``m``, ``h``, or ``d``.
                    Examples: ``"30m"``, ``"24h"``, ``"7d"``, ``"30d"``.
        private_key: Base64-encoded private key used to sign the credential.
        attestation_hash: Optional SHA-256 hash of an external attestation
                          document (e.g. a model card or audit report).
        backend: Optional CryptoBackend override.  Defaults to Ed25519.

    Returns:
        A fully signed AgentCredential.

    Raises:
        ValueError: If required fields are empty or ``expires_in`` is malformed.
    """
    if not agent_id:
        raise ValueError("agent_id must not be empty.")
    if not issued_to:
        raise ValueError("issued_to must not be empty.")
    if not private_key:
        raise ValueError("private_key must not be empty.")

    _backend = backend or default_backend
    delta = _parse_expires_in(expires_in)
    public_key = _backend.get_public_key(private_key)

    now = datetime.now(tz=timezone.utc)

    # Build the credential without a signature first so we can compute
    # the canonical payload, then stamp the signature back in.
    unsigned = AgentCredential(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        issued_to=issued_to,
        issued_at=now,
        expires_at=now + delta,
        permissions=list(permissions),
        attestation_hash=attestation_hash,
        issuer_public_key=public_key,
        signature="",
    )

    payload = unsigned.to_signing_payload()
    signature = _backend.sign(payload, private_key)

    return unsigned.model_copy(update={"signature": signature})
