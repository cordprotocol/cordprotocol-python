"""
W3C DID and Verifiable Credential support for cordprotocol.
"""

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

__all__ = [
    # Types
    "DIDDocument",
    "DIDResolutionResult",
    "ServiceEndpoint",
    "VCCredentialSubject",
    "VCProof",
    "VerifiableCredential",
    "VerificationMethod",
    # Document
    "create_did_document",
    "public_key_to_multibase",
    "multibase_to_public_key",
    # Resolver
    "agent_id_to_did",
    "did_to_agent_id",
    "resolve_did",
    "resolve_did_sync",
    # VC
    "issue_verifiable_credential",
    "verify_verifiable_credential",
    "agent_credential_to_vc",
    "vc_to_agent_credential_dict",
]
