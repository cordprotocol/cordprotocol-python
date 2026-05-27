"""
DID Document creation and key format conversion utilities.
"""

from __future__ import annotations

import base64
from typing import Optional

from cordprotocol.did.types import DIDDocument, ServiceEndpoint, VerificationMethod

# Bitcoin Base58 alphabet — omits 0, I, O, l to avoid visual confusion.
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_DECODE_MAP = {chr(c): i for i, c in enumerate(_BASE58_ALPHABET)}

# Multicodec prefix for Ed25519 public key (varint 0xed 0x01).
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


def _base58_encode(data: bytes) -> str:
    """Encode raw bytes to a base58 string."""
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    n = int.from_bytes(data, "big") if data else 0
    digits: list = []
    while n > 0:
        n, rem = divmod(n, 58)
        digits.append(_BASE58_ALPHABET[rem])

    digits.extend([_BASE58_ALPHABET[0]] * leading_zeros)
    digits.reverse()
    return bytes(digits).decode("ascii")


def _base58_decode(s: str) -> bytes:
    """Decode a base58 string to raw bytes."""
    leading_ones = 0
    for c in s:
        if c == "1":
            leading_ones += 1
        else:
            break

    n = 0
    for c in s:
        n = n * 58 + _BASE58_DECODE_MAP[c]

    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * leading_ones + raw


def public_key_to_multibase(public_key_base64: str) -> str:
    """Convert a base64 Ed25519 public key to base58btc multibase format.

    Prepends the Ed25519 multicodec prefix (0xed 0x01) before encoding.
    Returns a string starting with 'z' (multibase indicator for base58btc).
    """
    raw = base64.b64decode(public_key_base64)
    return "z" + _base58_encode(_ED25519_MULTICODEC_PREFIX + raw)


def multibase_to_public_key(multibase: str) -> str:
    """Convert a base58btc multibase string back to a base64 public key.

    Strips the 'z' multibase prefix, base58btc decodes, removes the
    Ed25519 multicodec prefix, and returns the result as base64.
    """
    if not multibase.startswith("z"):
        raise ValueError(
            f"Expected base58btc multibase (starts with 'z'), got: {multibase!r}"
        )

    decoded = _base58_decode(multibase[1:])
    plen = len(_ED25519_MULTICODEC_PREFIX)

    if decoded[:plen] != _ED25519_MULTICODEC_PREFIX:
        raise ValueError(
            f"Unexpected multicodec prefix — expected Ed25519 (0xed 0x01), "
            f"got: {decoded[:plen].hex()}"
        )

    return base64.b64encode(decoded[plen:]).decode("utf-8")


def create_did_document(
    did: str,
    public_key: str,
    service_endpoint: Optional[str] = None,
) -> DIDDocument:
    """Create a W3C DID Document for an agent.

    Args:
        did: The DID string (e.g. ``"did:web:cordprotocol.dev:agents:my-agent"``).
        public_key: Base64-encoded Ed25519 public key.
        service_endpoint: Optional URL for the agent's service endpoint.

    Returns:
        A :class:`DIDDocument` with a single Ed25519VerificationKey2020 method.
    """
    key_id = f"{did}#key-1"
    multibase = public_key_to_multibase(public_key)

    vm = VerificationMethod(
        id=key_id,
        type="Ed25519VerificationKey2020",
        controller=did,
        public_key_multibase=multibase,
    )

    services = None
    if service_endpoint is not None:
        services = [
            ServiceEndpoint(
                id=f"{did}#agent-service",
                type="AgentService",
                service_endpoint=service_endpoint,
            )
        ]

    return DIDDocument(
        context=[
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        id=did,
        verification_method=[vm],
        authentication=[key_id],
        assertion_method=[key_id],
        service=services,
    )
