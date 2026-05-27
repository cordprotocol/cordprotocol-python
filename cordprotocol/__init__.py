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

With hosted registry and revocation::

    from cordprotocol import CordProtocol, CordProtocolConfig

    cord = CordProtocol(CordProtocolConfig(
        registry=True,
        api_key="your-api-key",
    ))

    cred = cord.issue_credential(
        agent_id="my-agent-001",
        issued_to="acme-corp",
        permissions=[SCOPES.READ, SCOPES.EXECUTE],
        expires_in="24h",
        private_key=kp.private_key,
    )

    result = cord.verify_credential(cred)  # also checks revocation
"""

from cordprotocol.client import CordProtocol, CordProtocolConfig
from cordprotocol.credential import AgentCredential, VerificationResult
from cordprotocol.crypto.keys import KeyPair
from cordprotocol.did.document import (
    create_did_document,
    multibase_to_public_key,
    public_key_to_multibase,
)
from cordprotocol.did.resolver import (
    agent_id_to_did,
    did_to_agent_id,
    resolve_did,
    resolve_did_sync,
)
from cordprotocol.did.types import (
    DIDDocument,
    DIDResolutionResult,
    ServiceEndpoint,
    VCCredentialSubject,
    VCProof,
    VerifiableCredential,
    VerificationMethod,
)
from cordprotocol.did.vc import (
    agent_credential_to_vc,
    issue_verifiable_credential,
    vc_to_agent_credential_dict,
    verify_verifiable_credential,
)
from cordprotocol.issuer import generate_keypair, issue_credential
from cordprotocol.permissions import SCOPES, validate_scopes
from cordprotocol.registry import (
    AgentRegistration,
    RegistryError,
    RevocationError,
    check_revocation_status,
    check_revocation_status_sync,
    lookup_agent,
    lookup_agent_sync,
    register_agent,
    register_agent_sync,
    revoke_credential,
    revoke_credential_sync,
)
from cordprotocol.verifier import has_permission, is_expired, verify_credential

__version__ = "0.3.0"

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
    # Client
    "CordProtocol",
    "CordProtocolConfig",
    # Registry
    "AgentRegistration",
    "RegistryError",
    "RevocationError",
    "register_agent",
    "register_agent_sync",
    "lookup_agent",
    "lookup_agent_sync",
    "check_revocation_status",
    "check_revocation_status_sync",
    "revoke_credential",
    "revoke_credential_sync",
    # DID types
    "DIDDocument",
    "DIDResolutionResult",
    "ServiceEndpoint",
    "VCCredentialSubject",
    "VCProof",
    "VerifiableCredential",
    "VerificationMethod",
    # DID document
    "create_did_document",
    "public_key_to_multibase",
    "multibase_to_public_key",
    # DID resolver
    "agent_id_to_did",
    "did_to_agent_id",
    "resolve_did",
    "resolve_did_sync",
    # Verifiable Credentials
    "issue_verifiable_credential",
    "verify_verifiable_credential",
    "agent_credential_to_vc",
    "vc_to_agent_credential_dict",
]
