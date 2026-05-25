"""
cordprotocol — Post-quantum cryptographic identity for AI agents.

Compatible with @cordprotocol/sdk (TypeScript) at the credential schema
level, so credentials issued by either SDK are mutually inspectable.

Quick start::

    from cordprotocol import generate_keypair, issue_credential, verify_credential, SCOPES

    kp = generate_keypair()

    cred = issue_credential(
        agent_id="my-agent-001",
        issued_to="acme-corp",
        permissions=[SCOPES.READ, SCOPES.EXECUTE],
        expires_in="24h",
        private_key=kp.private_key,
    )

    result = verify_credential(cred)
    assert result.valid
"""

from cordprotocol.credential import AgentCredential, VerificationResult
from cordprotocol.crypto.keys import KeyPair
from cordprotocol.issuer import generate_keypair, issue_credential
from cordprotocol.permissions import SCOPES, validate_scopes
from cordprotocol.verifier import has_permission, is_expired, verify_credential

__version__ = "0.1.0"

__all__ = [
    # Models
    "AgentCredential",
    "VerificationResult",
    "KeyPair",
    # Issuance
    "generate_keypair",
    "issue_credential",
    # Verification
    "verify_credential",
    "is_expired",
    "has_permission",
    # Permissions
    "SCOPES",
    "validate_scopes",
]
