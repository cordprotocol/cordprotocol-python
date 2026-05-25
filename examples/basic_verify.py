#!/usr/bin/env python3
"""
Basic example: verify a credential and check individual permissions.

Run with:
    python examples/basic_verify.py
"""

from cordprotocol import (
    SCOPES,
    generate_keypair,
    has_permission,
    is_expired,
    issue_credential,
    verify_credential,
)


def main() -> None:
    # --- Issue a credential (stand-in for loading one from storage) ---
    keypair = generate_keypair()
    credential = issue_credential(
        agent_id="my-langchain-agent-001",
        issued_to="acme-corp",
        permissions=[SCOPES.READ, SCOPES.WRITE],
        expires_in="24h",
        private_key=keypair.private_key,
    )

    # --- Verify ---
    result = verify_credential(credential)

    if result.valid:
        print(f"Credential VALID")
        print(f"  Agent     : {result.credential.agent_id}")
        print(f"  Issued to : {result.credential.issued_to}")
        print(f"  Expires   : {result.credential.expires_at}")
    else:
        print(f"Credential INVALID: {result.error}")
        return

    # --- Permission checks ---
    print()
    print("Permission audit:")
    all_scopes = [SCOPES.READ, SCOPES.WRITE, SCOPES.EXECUTE, SCOPES.COMMUNICATE, SCOPES.SPEND]
    for scope in all_scopes:
        granted = has_permission(credential, scope)
        status = "GRANTED" if granted else "DENIED "
        print(f"  [{status}] {scope}")

    # --- Expiry ---
    print()
    print(f"Is expired: {is_expired(credential)}")


if __name__ == "__main__":
    main()
