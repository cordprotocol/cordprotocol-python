"""
KeyPair generation and management.

[PQ SWAP POINT] The KeyPair dataclass and generate_keypair() are
algorithm-agnostic.  Only the backend needs to change when moving
to a post-quantum algorithm.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cordprotocol.crypto.signatures import CryptoBackend, default_backend


@dataclass
class KeyPair:
    """A cryptographic keypair with base64-encoded key strings."""

    private_key: str
    public_key: str
    algorithm: str = field(default="Ed25519")


def generate_keypair(backend: CryptoBackend | None = None) -> KeyPair:
    """Generate a new cryptographic keypair.

    Args:
        backend: CryptoBackend to use.  Defaults to Ed25519.
                 [PQ SWAP POINT] Pass a ``DilithiumBackend()`` instance
                 here to produce post-quantum keypairs without changing
                 any other code.

    Returns:
        KeyPair with base64-encoded private and public keys.
    """
    _backend = backend or default_backend
    private_key, public_key = _backend.generate_keypair()
    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        algorithm=_backend.algorithm_id,
    )
