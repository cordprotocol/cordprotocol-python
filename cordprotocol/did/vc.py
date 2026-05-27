"""
W3C Verifiable Credential issuance and verification.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from cordprotocol.credential import AgentCredential
from cordprotocol.crypto.signatures import default_backend
from cordprotocol.did.document import (
    _ED25519_MULTICODEC_PREFIX,
    _base58_decode,
    _base58_encode,
    public_key_to_multibase,
)
from cordprotocol.did.types import VCCredentialSubject, VCProof, VerifiableCredential
from cordprotocol.issuer import _parse_expires_in

_VC_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]

_VC_TYPE = ["VerifiableCredential", "AgentIdentityCredential"]


def _vc_signing_payload(vc: VerifiableCredential) -> bytes:
    """Build deterministic signing bytes from a VC, excluding the proof.

    Keys are sorted alphabetically (``sort_keys=True``) and permissions are
    sorted so the payload is deterministic regardless of insertion order.
    """
    subject: dict = {
        "agentId": vc.credential_subject.agent_id,
        "id": vc.credential_subject.id,
        "issuedTo": vc.credential_subject.issued_to,
        "permissions": sorted(vc.credential_subject.permissions),
    }
    if vc.credential_subject.attestation_hash is not None:
        subject["attestationHash"] = vc.credential_subject.attestation_hash

    data: dict = {
        "@context": vc.context,
        "credentialSubject": subject,
        "id": vc.id,
        "issuanceDate": vc.issuance_date,
        "issuer": vc.issuer,
        "type": vc.type,
    }
    if vc.expiration_date is not None:
        data["expirationDate"] = vc.expiration_date

    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_verifiable_credential(
    agent_id: str,
    issued_to: str,
    permissions: List[str],
    expires_in: str,
    private_key: str,
    issuer_did: str,
    domain: str = "cordprotocol.dev",
    attestation_hash: Optional[str] = None,
) -> VerifiableCredential:
    """Issue a W3C Verifiable Credential for an AI agent.

    Uses the same Ed25519 backend as the core SDK.  The proof type is
    ``Ed25519Signature2020``; ``proof_value`` is base58btc multibase encoded.
    The ``proof.verification_method`` is a ``did:key`` DID so the public key
    can be recovered offline without any network lookup.

    Args:
        agent_id: Unique identifier for the agent.
        issued_to: Entity receiving the credential (user, org, etc.).
        permissions: Permission scopes to grant.
        expires_in: Duration string — ``"30m"``, ``"24h"``, ``"7d"``, etc.
        private_key: Base64-encoded Ed25519 private key.
        issuer_did: DID of the issuer (e.g. ``"did:web:cordprotocol.dev"``).
        domain: Domain used to construct the agent's DID.
        attestation_hash: Optional SHA-256 hash of an external attestation.

    Returns:
        A signed :class:`~cordprotocol.did.types.VerifiableCredential`.
    """
    from cordprotocol.did.resolver import agent_id_to_did

    public_key_b64 = default_backend.get_public_key(private_key)
    multibase = public_key_to_multibase(public_key_b64)
    key_did = f"did:key:{multibase}"

    now = datetime.now(tz=timezone.utc)
    delta = _parse_expires_in(expires_in)
    expiry = now + delta

    agent_did = agent_id_to_did(agent_id, domain)
    cred_id = f"urn:uuid:{uuid.uuid4()}"

    subject = VCCredentialSubject(
        id=agent_did,
        agent_id=agent_id,
        issued_to=issued_to,
        permissions=list(permissions),
        attestation_hash=attestation_hash,
    )

    # Build unsigned VC to compute the canonical payload.
    unsigned = VerifiableCredential(
        context=_VC_CONTEXT,
        id=cred_id,
        type=_VC_TYPE,
        issuer=issuer_did,
        issuance_date=now.isoformat(),
        expiration_date=expiry.isoformat(),
        credential_subject=subject,
        proof=VCProof(
            type="Ed25519Signature2020",
            created=now.isoformat(),
            verification_method=f"{key_did}#key-1",
            proof_purpose="assertionMethod",
            proof_value="",
        ),
    )

    payload = _vc_signing_payload(unsigned)
    sig_b64 = default_backend.sign(payload, private_key)
    sig_bytes = base64.b64decode(sig_b64)
    proof_value = "z" + _base58_encode(sig_bytes)

    return VerifiableCredential(
        context=_VC_CONTEXT,
        id=cred_id,
        type=_VC_TYPE,
        issuer=issuer_did,
        issuance_date=now.isoformat(),
        expiration_date=expiry.isoformat(),
        credential_subject=subject,
        proof=VCProof(
            type="Ed25519Signature2020",
            created=now.isoformat(),
            verification_method=f"{key_did}#key-1",
            proof_purpose="assertionMethod",
            proof_value=proof_value,
        ),
    )


def verify_verifiable_credential(vc: VerifiableCredential) -> dict:
    """Verify a Verifiable Credential's proof signature and expiration.

    Extracts the issuer's Ed25519 public key directly from the ``did:key``
    embedded in ``proof.verification_method`` — no network lookup required.

    Returns:
        A dict with keys:

        - ``valid`` (bool)
        - ``reason`` (str | None) — human-readable failure reason
        - ``agent_id`` (str | None) — present when valid
        - ``permissions`` (list | None) — present when valid
    """
    # Expiry check first (fast path).
    if vc.expiration_date is not None:
        try:
            exp_str = vc.expiration_date
            if exp_str.endswith("Z"):
                exp_str = exp_str[:-1] + "+00:00"
            expiry = datetime.fromisoformat(exp_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if datetime.now(tz=timezone.utc) >= expiry:
                return {
                    "valid": False,
                    "reason": "Credential has expired.",
                    "agent_id": None,
                    "permissions": None,
                }
        except ValueError as exc:
            return {
                "valid": False,
                "reason": f"Invalid expiration_date: {exc}",
                "agent_id": None,
                "permissions": None,
            }

    # Extract public key from the did:key in verification_method.
    vm = vc.proof.verification_method.split("#")[0]
    if not vm.startswith("did:key:z"):
        return {
            "valid": False,
            "reason": (
                "Cannot extract public key: verification_method must be a did:key DID."
            ),
            "agent_id": None,
            "permissions": None,
        }

    try:
        multibase = vm[len("did:key:"):]
        decoded = _base58_decode(multibase[1:])
        plen = len(_ED25519_MULTICODEC_PREFIX)
        if decoded[:plen] != _ED25519_MULTICODEC_PREFIX:
            raise ValueError("Not an Ed25519 multicodec key")
        public_key_b64 = base64.b64encode(decoded[plen:]).decode("utf-8")
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Cannot decode public key from did:key: {exc}",
            "agent_id": None,
            "permissions": None,
        }

    # Decode proof_value (base58btc → raw bytes → base64).
    proof_value = vc.proof.proof_value
    if not proof_value.startswith("z"):
        return {
            "valid": False,
            "reason": "proof_value must be base58btc multibase (starts with 'z').",
            "agent_id": None,
            "permissions": None,
        }

    try:
        sig_bytes = _base58_decode(proof_value[1:])
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Cannot decode proof_value: {exc}",
            "agent_id": None,
            "permissions": None,
        }

    payload = _vc_signing_payload(vc)
    if not default_backend.verify(payload, sig_b64, public_key_b64):
        return {
            "valid": False,
            "reason": "Signature verification failed.",
            "agent_id": None,
            "permissions": None,
        }

    return {
        "valid": True,
        "reason": None,
        "agent_id": vc.credential_subject.agent_id,
        "permissions": vc.credential_subject.permissions,
    }


def agent_credential_to_vc(
    credential: AgentCredential,
    issuer_did: str,
    domain: str = "cordprotocol.dev",
) -> VerifiableCredential:
    """Convert an :class:`~cordprotocol.credential.AgentCredential` to VC format.

    The existing Ed25519 signature is re-encoded as a base58btc ``proof_value``.
    Because the signing payload format differs from the VC payload, this VC
    should be verified with :func:`~cordprotocol.verifier.verify_credential`,
    not :func:`verify_verifiable_credential`.
    """
    from cordprotocol.did.resolver import agent_id_to_did

    agent_did = agent_id_to_did(credential.agent_id, domain)
    multibase = public_key_to_multibase(credential.issuer_public_key)
    key_did = f"did:key:{multibase}"

    sig_bytes = base64.b64decode(credential.signature)
    proof_value = "z" + _base58_encode(sig_bytes)

    return VerifiableCredential(
        context=_VC_CONTEXT,
        id=f"urn:uuid:{credential.id}",
        type=_VC_TYPE,
        issuer=issuer_did,
        issuance_date=credential.issued_at.isoformat(),
        expiration_date=credential.expires_at.isoformat(),
        credential_subject=VCCredentialSubject(
            id=agent_did,
            agent_id=credential.agent_id,
            issued_to=credential.issued_to,
            permissions=list(credential.permissions),
            attestation_hash=credential.attestation_hash,
        ),
        proof=VCProof(
            type="Ed25519Signature2020",
            created=credential.issued_at.isoformat(),
            verification_method=f"{key_did}#key-1",
            proof_purpose="assertionMethod",
            proof_value=proof_value,
        ),
    )


def vc_to_agent_credential_dict(vc: VerifiableCredential) -> dict:
    """Convert a :class:`~cordprotocol.did.types.VerifiableCredential` to an
    :class:`~cordprotocol.credential.AgentCredential`-compatible dict.

    Strips the ``urn:uuid:`` prefix from ``id`` if present.
    Decodes ``proof_value`` from base58btc back to base64.
    Recovers the public key bytes from the ``did:key`` in
    ``proof.verification_method``.
    """
    key_did = vc.proof.verification_method.split("#")[0]

    public_key_b64 = ""
    if key_did.startswith("did:key:z"):
        try:
            multibase = key_did[len("did:key:"):]
            decoded = _base58_decode(multibase[1:])
            plen = len(_ED25519_MULTICODEC_PREFIX)
            public_key_b64 = base64.b64encode(decoded[plen:]).decode("utf-8")
        except Exception:
            pass

    sig_b64 = ""
    proof_value = vc.proof.proof_value
    if proof_value.startswith("z"):
        try:
            sig_bytes = _base58_decode(proof_value[1:])
            sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
        except Exception:
            pass

    cred_id = vc.id
    if cred_id.startswith("urn:uuid:"):
        cred_id = cred_id[len("urn:uuid:"):]

    return {
        "id": cred_id,
        "agent_id": vc.credential_subject.agent_id,
        "issued_to": vc.credential_subject.issued_to,
        "issued_at": vc.issuance_date,
        "expires_at": vc.expiration_date or "",
        "permissions": vc.credential_subject.permissions,
        "attestation_hash": vc.credential_subject.attestation_hash,
        "issuer_public_key": public_key_b64,
        "signature": sig_b64,
    }
