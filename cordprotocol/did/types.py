"""
W3C DID and Verifiable Credential type definitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VerificationMethod:
    id: str
    type: str  # "Ed25519VerificationKey2020"
    controller: str
    public_key_multibase: str  # base58btc encoded, starts with 'z'


@dataclass
class ServiceEndpoint:
    id: str
    type: str
    service_endpoint: str


@dataclass
class DIDDocument:
    context: List[str]
    id: str
    verification_method: List[VerificationMethod]
    authentication: List[str]
    assertion_method: List[str]
    service: Optional[List[ServiceEndpoint]] = None


@dataclass
class VCCredentialSubject:
    id: str  # DID of the agent
    agent_id: str
    issued_to: str
    permissions: List[str]
    attestation_hash: Optional[str] = None


@dataclass
class VCProof:
    type: str  # "Ed25519Signature2020"
    created: str
    verification_method: str
    proof_purpose: str  # "assertionMethod"
    proof_value: str  # base58btc encoded signature, starts with 'z'


@dataclass
class VerifiableCredential:
    context: List[str]
    id: str
    type: List[str]
    issuer: str  # DID
    issuance_date: str
    credential_subject: VCCredentialSubject
    proof: VCProof
    expiration_date: Optional[str] = None


@dataclass
class DIDResolutionResult:
    did_document: Optional[DIDDocument]
    did_resolution_metadata: dict
    did_document_metadata: dict
