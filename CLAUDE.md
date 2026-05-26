# CLAUDE.md — cordprotocol Python SDK

This file gives Claude Code the context it needs to work effectively in this repository.

## What this project does

`cordprotocol` is the Python SDK for [Cord Protocol](https://cordprotocol.dev) — a post-quantum cryptographic identity system for AI agents.  Developers building LangChain, AutoGen, and CrewAI agents use it to issue and verify signed credentials so that tools and services can confirm *who* is calling before acting.

The TypeScript equivalent is [`@cordprotocol/sdk`](https://www.npmjs.com/package/@cordprotocol/sdk).  Both SDKs share the same `AgentCredential` schema; credentials serialised by one SDK are fully inspectable by the other.

---

## Repository layout

```
cordprotocol/           ← main package
  __init__.py           ← public API exports
  credential.py         ← AgentCredential + VerificationResult (Pydantic)
  issuer.py             ← generate_keypair(), issue_credential()
  verifier.py           ← verify_credential(), is_expired(), has_permission()
  permissions.py        ← SCOPES constants, validate_scopes()
  registry.py           ← register_agent(), lookup_agent(), check_revocation_status(),
                          revoke_credential() + sync wrappers; RegistryError, RevocationError
  client.py             ← CordProtocol class + CordProtocolConfig
  cli.py                ← `cord` CLI entry point
  crypto/
    __init__.py
    keys.py             ← KeyPair dataclass, generate_keypair()
    signatures.py       ← CryptoBackend ABC + Ed25519Backend [PQ SWAP POINT]

tests/
  test_credential.py    ← serialisation + signing-payload tests
  test_issuer.py        ← keypair gen + issuance tests
  test_verifier.py      ← verify / is_expired / has_permission tests
  test_registry.py      ← registry functions + sync wrappers (mocked httpx)
  test_client.py        ← CordProtocol client (mocked registry)

examples/
  basic_issue.py        ← generate keys, issue, print
  basic_verify.py       ← verify, audit permissions
  langchain_example.py  ← LangChain integration pattern
  crewai_example.py     ← CrewAI trust-registry pattern
```

---

## Key design decisions

### CryptoBackend ABC

`cordprotocol/crypto/signatures.py` defines an abstract `CryptoBackend` with `generate_keypair()`, `get_public_key()`, `sign()`, `verify()`, and `algorithm_id`.  `Ed25519Backend` is the concrete implementation.  The module-level `default_backend` variable is the single swap point for upgrading to post-quantum algorithms.

### Deterministic signing payload

`AgentCredential.to_signing_payload()` produces `bytes` by JSON-serialising all fields *except* `signature`, with:
- `sort_keys=True` — alphabetical key order
- `sorted(permissions)` — permission list is treated as a set
- ISO-8601 datetime strings

This matches the TypeScript SDK so cross-language credential inspection works correctly.

### Public key derivation

`issue_credential()` accepts only a `private_key` string.  The public key is derived from it via `CryptoBackend.get_public_key()` and embedded in the credential automatically.  This keeps the caller API minimal.

### Pydantic v2

`AgentCredential` and `VerificationResult` are Pydantic `BaseModel` subclasses.  Use `.model_copy(update={...})` to create modified copies (not `.copy()`).

---

## Running tests

```bash
pip install -e ".[dev]"
pytest                        # all tests (137 total)
pytest tests/test_issuer.py   # single file
pytest -v                     # verbose output
```

---

## Running examples

```bash
python examples/basic_issue.py
python examples/basic_verify.py
python examples/langchain_example.py   # no LangChain required
python examples/crewai_example.py      # no CrewAI required
```

---

## Key design decisions (v0.2.0 additions)

### CordProtocol client

`cordprotocol/client.py` provides `CordProtocol` — a high-level wrapper that wires the core issuer and verifier to the hosted API.  `CordProtocolConfig.registry=True` makes `issue_credential` auto-post the public key.  `CordProtocolConfig.api_key` makes `verify_credential` also check revocation.  Both features fail silently so credential operations are never blocked by network issues.

### Registry module

`cordprotocol/registry.py` contains four async functions (`register_agent`, `lookup_agent`, `check_revocation_status`, `revoke_credential`) with sync wrappers (same name + `_sync` suffix) using `asyncio.run()`.  Uses `httpx` for async HTTP.  `RegistryError` covers non-revocation API failures; `RevocationError` covers revocation failures.

### Dependencies

`httpx>=0.24.0` was added as a runtime dependency in v0.2.0 to support the async registry HTTP calls.

---

## Common tasks

### Adding a new permission scope

1. Add the constant to `SCOPES` in `cordprotocol/permissions.py`.
2. Add it to `SCOPES.all()`.
3. Update `tests/test_verifier.py` if the all-scopes test needs updating.

### Swapping to a post-quantum backend

All swap points are tagged `[PQ SWAP POINT]` in the source.  The minimum change is:

```python
# cordprotocol/crypto/signatures.py
class DilithiumBackend(CryptoBackend):
    ...  # implement the ABC

default_backend: CryptoBackend = DilithiumBackend()  # one-line change
```

No changes are needed in `issuer.py`, `verifier.py`, or application code.

### Adding a new duration unit to `expires_in`

Edit `_parse_expires_in()` in `cordprotocol/issuer.py` and add a branch for the new unit (e.g. `"w"` for weeks).

---

## Python-specific notes

- **Pydantic v2** — use `model_copy(update={...})` not `.copy()` or `.dict()`.
- **datetime timezone** — all datetimes are UTC (`datetime.now(tz=timezone.utc)`).  Never use naive datetimes.
- **base64** — keys and signatures use standard base64 (`base64.b64encode` / `b64decode`), not URL-safe.
- **Imports** — avoid star imports; the public API is explicit in `cordprotocol/__init__.py`.

---

## Links

- Website: https://cordprotocol.dev  
- TypeScript SDK: https://www.npmjs.com/package/@cordprotocol/sdk  
- Python SDK repo: https://github.com/cordprotocol/cordprotocol-python
