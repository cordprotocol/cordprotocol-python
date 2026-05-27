"""
DID resolution for did:key (offline) and did:web (HTTP fetch).
"""

from __future__ import annotations

import asyncio
import base64
from typing import Optional

import httpx

from cordprotocol.did.document import (
    _ED25519_MULTICODEC_PREFIX,
    _base58_decode,
    create_did_document,
)
from cordprotocol.did.types import (
    DIDDocument,
    DIDResolutionResult,
    ServiceEndpoint,
    VerificationMethod,
)


def agent_id_to_did(agent_id: str, domain: str = "cordprotocol.dev") -> str:
    """Convert an agent ID to a ``did:web`` DID.

    Example::

        agent_id_to_did("trading-agent")
        # → "did:web:cordprotocol.dev:agents:trading-agent"
    """
    return f"did:web:{domain}:agents:{agent_id}"


def did_to_agent_id(did: str) -> Optional[str]:
    """Extract the agent ID from a cordprotocol ``did:web`` DID.

    Returns ``None`` if the DID is not a ``did:web:…:agents:…`` DID.
    """
    parts = did.split(":")
    # did:web:<domain>:agents:<agent_id>
    if len(parts) < 5:
        return None
    if parts[0] != "did" or parts[1] != "web":
        return None
    if parts[3] != "agents":
        return None
    return parts[4]


def _did_web_to_url(did: str) -> str:
    """Derive the DID document URL from a ``did:web`` DID.

    Per the did:web spec:
    - ``did:web:example.com`` → ``https://example.com/.well-known/did.json``
    - ``did:web:example.com:a:b`` → ``https://example.com/a/b/did.json``
    """
    rest = did[len("did:web:"):]
    parts = rest.split(":", 1)
    if len(parts) == 1:
        return f"https://{parts[0]}/.well-known/did.json"
    path = parts[1].replace(":", "/")
    return f"https://{parts[0]}/{path}/did.json"


async def resolve_did(did: str) -> DIDResolutionResult:
    """Resolve a DID to a :class:`~cordprotocol.did.types.DIDDocument`.

    Supports:

    - ``did:key`` — public key is derived offline from the DID string.
    - ``did:web`` — DID document is fetched via HTTP.

    Returns a :class:`~cordprotocol.did.types.DIDResolutionResult` with
    ``did_document=None`` and an ``"error"`` key in
    ``did_resolution_metadata`` on any failure.
    """
    if did.startswith("did:key:"):
        return _resolve_did_key(did)
    if did.startswith("did:web:"):
        return await _resolve_did_web(did)
    return DIDResolutionResult(
        did_document=None,
        did_resolution_metadata={"error": "methodNotSupported"},
        did_document_metadata={},
    )


def _resolve_did_key(did: str) -> DIDResolutionResult:
    """Offline resolution of a ``did:key`` DID."""
    parts = did.split(":")
    if len(parts) < 3 or not parts[2].startswith("z"):
        return DIDResolutionResult(
            did_document=None,
            did_resolution_metadata={"error": "invalidDid"},
            did_document_metadata={},
        )

    try:
        multibase = parts[2]
        decoded = _base58_decode(multibase[1:])
        plen = len(_ED25519_MULTICODEC_PREFIX)
        if decoded[:plen] != _ED25519_MULTICODEC_PREFIX:
            raise ValueError("Not an Ed25519 key multicodec prefix")
        public_key_b64 = base64.b64encode(decoded[plen:]).decode("utf-8")
        doc = create_did_document(did, public_key_b64)
        return DIDResolutionResult(
            did_document=doc,
            did_resolution_metadata={"contentType": "application/did+ld+json"},
            did_document_metadata={},
        )
    except Exception as exc:
        return DIDResolutionResult(
            did_document=None,
            did_resolution_metadata={"error": f"invalidDid: {exc}"},
            did_document_metadata={},
        )


async def _resolve_did_web(did: str) -> DIDResolutionResult:
    """Fetch and parse a ``did:web`` DID document via HTTP."""
    url = _did_web_to_url(did)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, follow_redirects=True)
        except httpx.RequestError as exc:
            return DIDResolutionResult(
                did_document=None,
                did_resolution_metadata={"error": f"networkError: {exc}"},
                did_document_metadata={},
            )

    if not resp.is_success:
        return DIDResolutionResult(
            did_document=None,
            did_resolution_metadata={"error": f"notFound: HTTP {resp.status_code}"},
            did_document_metadata={},
        )

    try:
        data = resp.json()
        vms = [
            VerificationMethod(
                id=vm["id"],
                type=vm.get("type", "Ed25519VerificationKey2020"),
                controller=vm.get("controller", did),
                public_key_multibase=vm.get("publicKeyMultibase", ""),
            )
            for vm in data.get("verificationMethod", [])
        ]

        raw_services = data.get("service", [])
        services = (
            [
                ServiceEndpoint(
                    id=s["id"],
                    type=s.get("type", ""),
                    service_endpoint=s.get("serviceEndpoint", ""),
                )
                for s in raw_services
            ]
            if raw_services
            else None
        )

        doc = DIDDocument(
            context=data.get("@context", ["https://www.w3.org/ns/did/v1"]),
            id=data.get("id", did),
            verification_method=vms,
            authentication=data.get("authentication", []),
            assertion_method=data.get("assertionMethod", []),
            service=services,
        )
        return DIDResolutionResult(
            did_document=doc,
            did_resolution_metadata={"contentType": "application/did+ld+json"},
            did_document_metadata={},
        )
    except Exception as exc:
        return DIDResolutionResult(
            did_document=None,
            did_resolution_metadata={"error": f"parseError: {exc}"},
            did_document_metadata={},
        )


def resolve_did_sync(did: str) -> DIDResolutionResult:
    """Synchronous wrapper for :func:`resolve_did`."""
    return asyncio.run(resolve_did(did))
