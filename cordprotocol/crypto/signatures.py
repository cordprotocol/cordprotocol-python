"""
CryptoBackend ABC and Ed25519 implementation.

[PQ SWAP POINT] Replace Ed25519Backend with DilithiumBackend when
CRYSTALS-Dilithium becomes available via a stable Python package.
The interface is identical — only the backend class and the
``default_backend`` assignment at the bottom change.
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class CryptoBackend(ABC):
    """Abstract base class for cryptographic backends.

    Implement this interface to swap in a post-quantum algorithm such as
    CRYSTALS-Dilithium.  The issuer and verifier depend only on this ABC,
    so swapping backends requires zero changes outside this module.
    """

    @abstractmethod
    def generate_keypair(self) -> tuple[str, str]:
        """Generate a new keypair.

        Returns:
            (private_key_b64, public_key_b64) — both base64-encoded.
        """

    @abstractmethod
    def get_public_key(self, private_key_b64: str) -> str:
        """Derive the public key from a private key.

        Args:
            private_key_b64: Base64-encoded private key.

        Returns:
            Base64-encoded public key.
        """

    @abstractmethod
    def sign(self, message: bytes, private_key_b64: str) -> str:
        """Sign a message.

        Args:
            message: Raw bytes to sign.
            private_key_b64: Base64-encoded private key.

        Returns:
            Base64-encoded signature.
        """

    @abstractmethod
    def verify(self, message: bytes, signature_b64: str, public_key_b64: str) -> bool:
        """Verify a signature.

        Args:
            message: The original signed bytes.
            signature_b64: Base64-encoded signature.
            public_key_b64: Base64-encoded public key.

        Returns:
            True if the signature is valid, False otherwise.
        """

    @property
    @abstractmethod
    def algorithm_id(self) -> str:
        """Human-readable identifier for this algorithm (e.g. "Ed25519")."""


class Ed25519Backend(CryptoBackend):
    """Ed25519 signature backend using the ``cryptography`` library.

    [PQ SWAP POINT] This class will be replaced by ``DilithiumBackend``
    when CRYSTALS-Dilithium support is stable in Python.  The
    ``CryptoBackend`` interface guarantees that issuer.py and verifier.py
    need no changes.
    """

    def generate_keypair(self) -> tuple[str, str]:
        private_key = Ed25519PrivateKey.generate()
        return (
            self._encode_private(private_key),
            self._encode_public(private_key.public_key()),
        )

    def get_public_key(self, private_key_b64: str) -> str:
        private_key = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(private_key_b64)
        )
        return self._encode_public(private_key.public_key())

    def sign(self, message: bytes, private_key_b64: str) -> str:
        private_key = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(private_key_b64)
        )
        return base64.b64encode(private_key.sign(message)).decode("utf-8")

    def verify(self, message: bytes, signature_b64: str, public_key_b64: str) -> bool:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64)
            )
            public_key.verify(base64.b64decode(signature_b64), message)
            return True
        except (InvalidSignature, Exception):
            return False

    @property
    def algorithm_id(self) -> str:
        return "Ed25519"

    @staticmethod
    def _encode_private(key: Ed25519PrivateKey) -> str:
        return base64.b64encode(
            key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode("utf-8")

    @staticmethod
    def _encode_public(key: Ed25519PublicKey) -> str:
        return base64.b64encode(
            key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("utf-8")


# Default backend used throughout the SDK.
# [PQ SWAP POINT] Change this single line to upgrade all operations:
#   default_backend: CryptoBackend = DilithiumBackend()
default_backend: CryptoBackend = Ed25519Backend()
