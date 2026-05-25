"""
Cryptographic backends for cordprotocol.

[PQ SWAP POINT] Import and register a post-quantum backend here to upgrade
all credential operations to CRYSTALS-Dilithium or similar.
"""

from cordprotocol.crypto.keys import KeyPair, generate_keypair
from cordprotocol.crypto.signatures import CryptoBackend, Ed25519Backend, default_backend

__all__ = [
    "CryptoBackend",
    "Ed25519Backend",
    "default_backend",
    "KeyPair",
    "generate_keypair",
]
