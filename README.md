# cordprotocol

**Post-quantum cryptographic identity for AI agents — Python SDK**

[![PyPI version](https://img.shields.io/pypi/v/cordprotocol.svg)](https://pypi.org/project/cordprotocol/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cord Protocol gives every AI agent a cryptographically signed identity credential so that tools, services, and other agents can verify *who* is calling before acting.  The Python SDK is a first-class implementation designed for developers building [LangChain](https://www.langchain.com/), [AutoGen](https://github.com/microsoft/autogen), and [CrewAI](https://www.crewai.com/) agents.

> **TypeScript developer?**  
> The JavaScript/TypeScript SDK is [`@cordprotocol/sdk`](https://www.npmjs.com/package/@cordprotocol/sdk) on npm.  
> Both SDKs share the same credential schema, so credentials are mutually inspectable across languages.

---

## Installation

```bash
pip install cordprotocol
```

Requires Python 3.9+ and depends only on [`cryptography`](https://pypi.org/project/cryptography/) and [`pydantic`](https://pypi.org/project/pydantic/).

---

## Quick start

```python
from cordprotocol import generate_keypair, issue_credential, verify_credential, SCOPES

# Generate an issuer keypair (generate once, store securely)
kp = generate_keypair()

# Issue a signed credential for an agent
cred = issue_credential(
    agent_id="my-agent-001",
    issued_to="acme-corp",
    permissions=[SCOPES.READ, SCOPES.EXECUTE],
    expires_in="24h",
    private_key=kp.private_key,
)

# Verify it
result = verify_credential(cred)
assert result.valid
print(result.credential.agent_id)  # "my-agent-001"
```

---

## API reference

### `generate_keypair(backend=None) -> KeyPair`

Generate a new cryptographic keypair.

```python
from cordprotocol import generate_keypair

kp = generate_keypair()
print(kp.algorithm)    # "Ed25519"
print(kp.public_key)   # base64-encoded public key
print(kp.private_key)  # base64-encoded private key (keep secret)
```

| Field | Type | Description |
|---|---|---|
| `private_key` | `str` | Base64-encoded private key |
| `public_key` | `str` | Base64-encoded public key |
| `algorithm` | `str` | Algorithm identifier, e.g. `"Ed25519"` |

---

### `issue_credential(...) -> AgentCredential`

Issue a signed identity credential for an AI agent.

```python
from cordprotocol import issue_credential, SCOPES

cred = issue_credential(
    agent_id="langchain-prod-001",     # unique agent identifier
    issued_to="acme-corp",             # recipient (user, org, etc.)
    permissions=[SCOPES.READ, SCOPES.WRITE],
    expires_in="7d",                   # "30m" | "24h" | "7d" | "30d" …
    private_key=kp.private_key,
    attestation_hash=None,             # optional SHA-256 of audit doc
)
```

| Parameter | Type | Description |
|---|---|---|
| `agent_id` | `str` | Unique identifier for the agent |
| `issued_to` | `str` | Entity receiving the credential |
| `permissions` | `List[str]` | Permission scopes (see `SCOPES`) |
| `expires_in` | `str` | Duration: `m` minutes, `h` hours, `d` days |
| `private_key` | `str` | Base64-encoded issuer private key |
| `attestation_hash` | `Optional[str]` | SHA-256 hash of an attestation document |

---

### `verify_credential(credential, backend=None) -> VerificationResult`

Verify a credential's signature and expiry.

```python
from cordprotocol import verify_credential

result = verify_credential(cred)

if result.valid:
    print(f"Agent {result.credential.agent_id} verified")
else:
    print(f"Rejected: {result.error}")
```

| Field | Type | Description |
|---|---|---|
| `valid` | `bool` | `True` if signature and expiry are OK |
| `error` | `Optional[str]` | Reason for failure when `valid=False` |
| `credential` | `Optional[AgentCredential]` | The credential on success |

---

### `is_expired(credential) -> bool`

```python
from cordprotocol import is_expired
print(is_expired(cred))  # False (for a freshly issued credential)
```

---

### `has_permission(credential, scope) -> bool`

```python
from cordprotocol import has_permission, SCOPES
print(has_permission(cred, SCOPES.WRITE))  # True | False
```

---

### `SCOPES`

Standard permission scopes, compatible with the TypeScript SDK:

| Constant | Value | Purpose |
|---|---|---|
| `SCOPES.READ` | `"read:data"` | Read access to data sources |
| `SCOPES.WRITE` | `"write:data"` | Write / mutate data |
| `SCOPES.EXECUTE` | `"execute:actions"` | Trigger external actions |
| `SCOPES.COMMUNICATE` | `"communicate:agents"` | Talk to other agents |
| `SCOPES.SPEND` | `"spend:budget"` | Authorise spending operations |

---

### `AgentCredential`

Pydantic model — schema identical to the TypeScript `AgentCredential`.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | UUID v4 |
| `agent_id` | `str` | Agent identifier |
| `issued_to` | `str` | Recipient |
| `issued_at` | `datetime` | UTC issue time |
| `expires_at` | `datetime` | UTC expiry time |
| `permissions` | `List[str]` | Granted scopes |
| `attestation_hash` | `Optional[str]` | Optional audit hash |
| `issuer_public_key` | `str` | Base64 public key |
| `signature` | `str` | Base64 signature |

Serialisation helpers: `.to_dict()`, `.from_dict()`, `.to_json()`, `.from_json()`.

---

## Integration examples

### LangChain

```python
from cordprotocol import generate_keypair, issue_credential, verify_credential, SCOPES

ISSUER_KP = generate_keypair()  # generate once, store in your KMS

def make_agent_credential(agent_id: str):
    return issue_credential(
        agent_id=agent_id,
        issued_to="langchain-runtime",
        permissions=[SCOPES.READ, SCOPES.EXECUTE],
        expires_in="1h",
        private_key=ISSUER_KP.private_key,
    )

class CordProtectedTool(BaseTool):  # from langchain.tools
    name = "my_tool"
    description = "..."

    def __init__(self, credential):
        super().__init__()
        self.credential = credential

    def _run(self, query: str) -> str:
        result = verify_credential(self.credential)
        if not result.valid:
            raise PermissionError(f"Identity check failed: {result.error}")
        if not has_permission(self.credential, SCOPES.READ):
            raise PermissionError("Missing read:data permission")
        # ... your tool logic here
```

See [`examples/langchain_example.py`](examples/langchain_example.py) for the full runnable demo.

### CrewAI

```python
from cordprotocol import generate_keypair, issue_credential, SCOPES

registry_kp = generate_keypair()

def register_crew_agent(agent_id: str, permissions: list):
    return issue_credential(
        agent_id=agent_id,
        issued_to="crewai-runtime",
        permissions=permissions,
        expires_in="2h",
        private_key=registry_kp.private_key,
    )
```

See [`examples/crewai_example.py`](examples/crewai_example.py) for the full trust-registry pattern.

---

## CLI

```bash
# Generate a keypair
cord keygen

# Issue a credential
cord issue \
  --agent-id my-agent \
  --issued-to acme \
  --permissions read:data,write:data \
  --expires-in 24h \
  --private-key <base64-private-key>

# Verify a saved credential
cord verify credential.json
```

---

## Post-quantum roadmap

The SDK is designed for a seamless upgrade to CRYSTALS-Dilithium (NIST PQC standard).  Every location that needs to change is marked with `[PQ SWAP POINT]` in the source.  The swap requires changing one line:

```python
# cordprotocol/crypto/signatures.py
default_backend: CryptoBackend = DilithiumBackend()  # was Ed25519Backend()
```

No changes are needed in application code.

---

## Hosted API integration

The `CordProtocol` client wraps the core SDK with optional registry auto-posting and revocation checking against the live API at `https://api.cordprotocol.dev`.

### Basic usage (unchanged)

```python
from cordprotocol import generate_keypair, issue_credential, verify_credential, SCOPES

kp = generate_keypair()

cred = issue_credential(
    agent_id="my-agent",
    issued_to="paul@example.com",
    permissions=["read:data"],
    expires_in="24h",
    private_key=kp.private_key,
)

result = verify_credential(cred)
assert result.valid
```

### With registry and revocation (new in v0.2.0)

```python
from cordprotocol import CordProtocol, CordProtocolConfig, generate_keypair, SCOPES

kp = generate_keypair()

cord = CordProtocol(CordProtocolConfig(
    registry=True,
    api_key="your-api-key",
))

# Issues the credential AND automatically registers the public key
# in the Cord Protocol registry.  Registry failure is silent.
cred = cord.issue_credential(
    agent_id="my-agent",
    issued_to="paul@example.com",
    permissions=["read:data", "write:orders"],
    expires_in="24h",
    private_key=kp.private_key,
)

# Verifies signature + expiry AND checks revocation status via the API.
result = cord.verify_credential(cred)
if not result.valid:
    print(result.error)  # e.g. "Credential has been revoked."

# Revoke a credential (requires api_key)
cord.revoke_credential(cred.id, cred.agent_id, reason="decommissioned")

# Look up a registered agent
registration = cord.lookup_agent("my-agent")
if registration:
    print(registration.active, registration.credential_count)
```

### Low-level registry functions

All registry functions are also available directly, as both async and sync variants:

```python
from cordprotocol import (
    register_agent, register_agent_sync,
    lookup_agent, lookup_agent_sync,
    check_revocation_status, check_revocation_status_sync,
    revoke_credential, revoke_credential_sync,
)

# Async (use inside async functions)
registration = await register_agent("my-agent", kp.public_key, "paul@example.com")
status = await check_revocation_status(cred.id)

# Sync (use in regular code)
registration = register_agent_sync("my-agent", kp.public_key, "paul@example.com")
status = check_revocation_status_sync(cred.id)
# {"revoked": False, "revoked_at": None, "reason": None}
```

### Error handling

```python
from cordprotocol import RegistryError, RevocationError

try:
    await register_agent("my-agent", kp.public_key, "alice")
except RegistryError as e:
    print(f"Registry error: {e}")

try:
    cord.revoke_credential(cred.id, cred.agent_id)
except RevocationError as e:
    print(f"Revocation failed: {e}")
except ValueError as e:
    print(f"Config error: {e}")  # no api_key set
```

---

## Links

- Website: [cordprotocol.dev](https://cordprotocol.dev)  
- npm package: [`@cordprotocol/sdk`](https://www.npmjs.com/package/@cordprotocol/sdk)  
- Issues: [GitHub Issues](https://github.com/cordprotocol/cordprotocol-python/issues)

---

## License

MIT
