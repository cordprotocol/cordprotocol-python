"""
Credential verification: verify_credential(), is_expired(), has_permission().
"""

from __future__ import annotations

from datetime import datetime, timezone

from cordprotocol.credential import AgentCredential, VerificationResult
from cordprotocol.crypto.signatures import CryptoBackend, default_backend


def is_expired(credential: AgentCredential) -> bool:
    """Return True if the credential's expiry time has passed."""
    return datetime.now(tz=timezone.utc) >= credential.expires_at


def has_permission(credential: AgentCredential, scope: str) -> bool:
    """Return True if the credential grants the given permission scope."""
    return scope in credential.permissions


def verify_credential(
    credential: AgentCredential,
    backend: CryptoBackend | None = None,
) -> VerificationResult:
    """Verify a credential's signature and expiry.

    Checks performed in order:

    1. The credential has a non-empty signature.
    2. The signature is cryptographically valid against ``issuer_public_key``.
    3. The credential has not expired.

    Args:
        credential: The AgentCredential to verify.
        backend: Optional CryptoBackend override.  Must match the algorithm
                 used when issuing the credential.  Defaults to Ed25519.

    Returns:
        VerificationResult with ``valid=True`` and the credential on success,
        or ``valid=False`` with a human-readable ``error`` on failure.
    """
    _backend = backend or default_backend

    if not credential.signature:
        return VerificationResult(valid=False, error="Credential has no signature.")

    try:
        payload = credential.to_signing_payload()
        signature_valid = _backend.verify(
            payload,
            credential.signature,
            credential.issuer_public_key,
        )
    except Exception as exc:
        return VerificationResult(
            valid=False,
            error=f"Signature verification error: {exc}",
        )

    if not signature_valid:
        return VerificationResult(valid=False, error="Signature verification failed.")

    if is_expired(credential):
        return VerificationResult(valid=False, error="Credential has expired.")

    return VerificationResult(valid=True, credential=credential)
