"""
Simple CLI for cordprotocol.

Commands:
    cord keygen                    Generate a new keypair (JSON output)
    cord issue  --agent-id ...     Issue a new credential (JSON output)
    cord verify <file>             Verify a credential JSON file
"""

from __future__ import annotations

import argparse
import json
import sys

from cordprotocol.credential import AgentCredential
from cordprotocol.issuer import generate_keypair, issue_credential
from cordprotocol.verifier import verify_credential


def _cmd_keygen(_args: argparse.Namespace) -> None:
    kp = generate_keypair()
    print(json.dumps(
        {"algorithm": kp.algorithm, "public_key": kp.public_key, "private_key": kp.private_key},
        indent=2,
    ))


def _cmd_issue(args: argparse.Namespace) -> None:
    permissions = [p.strip() for p in args.permissions.split(",") if p.strip()]
    cred = issue_credential(
        agent_id=args.agent_id,
        issued_to=args.issued_to,
        permissions=permissions,
        expires_in=args.expires_in,
        private_key=args.private_key,
        attestation_hash=args.attestation_hash or None,
    )
    print(cred.to_json())


def _cmd_verify(args: argparse.Namespace) -> None:
    try:
        with open(args.file) as fh:
            data = json.load(fh)
        cred = AgentCredential.from_dict(data)
    except Exception as exc:
        print(f"Failed to load credential: {exc}", file=sys.stderr)
        sys.exit(1)

    result = verify_credential(cred)
    if result.valid:
        print(f"VALID  agent={cred.agent_id}  permissions={cred.permissions}")
    else:
        print(f"INVALID  {result.error}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cord",
        description="cordprotocol CLI — post-quantum identity for AI agents",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("keygen", help="Generate a new keypair")

    issue_p = sub.add_parser("issue", help="Issue a new agent credential")
    issue_p.add_argument("--agent-id", required=True, dest="agent_id")
    issue_p.add_argument("--issued-to", required=True, dest="issued_to")
    issue_p.add_argument("--permissions", required=True, help="Comma-separated scope list")
    issue_p.add_argument("--expires-in", default="24h", dest="expires_in")
    issue_p.add_argument("--private-key", required=True, dest="private_key")
    issue_p.add_argument("--attestation-hash", default=None, dest="attestation_hash")

    verify_p = sub.add_parser("verify", help="Verify a credential JSON file")
    verify_p.add_argument("file", help="Path to credential JSON file")

    args = parser.parse_args()

    dispatch = {
        "keygen": _cmd_keygen,
        "issue": _cmd_issue,
        "verify": _cmd_verify,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
