#!/usr/bin/env python3
"""
Basic example: generate a keypair and issue an agent credential.

Run with:
    python examples/basic_issue.py
"""

import json

from cordprotocol import SCOPES, generate_keypair, issue_credential


def main() -> None:
    # 1. Generate an issuer keypair.
    #    In production, generate this once and store it securely (e.g. a KMS).
    keypair = generate_keypair()
    print("Issuer keypair generated")
    print(f"  Algorithm : {keypair.algorithm}")
    print(f"  Public key: {keypair.public_key[:32]}...")
    print()

    # 2. Issue a signed credential for an AI agent.
    credential = issue_credential(
        agent_id="my-langchain-agent-001",
        issued_to="acme-corp",
        permissions=[SCOPES.READ, SCOPES.WRITE, SCOPES.EXECUTE],
        expires_in="24h",
        private_key=keypair.private_key,
        attestation_hash=None,
    )

    print("Credential issued!")
    print(json.dumps(credential.to_dict(), indent=2))
    print()
    print(f"Credential ID  : {credential.id}")
    print(f"Permissions    : {credential.permissions}")
    print(f"Expires at     : {credential.expires_at.isoformat()}")


if __name__ == "__main__":
    main()
