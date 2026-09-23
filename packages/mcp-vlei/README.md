# mcp-vlei

Verifiable **organizational** identity for the Model Context Protocol, using GLEIF's vLEI.

Implements the `org.gleif.vlei/identity` extension defined in [`spec/SPEC.md`](../../spec/SPEC.md).
Nothing in MCP's core schema is modified: every field this package puts on the wire travels in
`extensions` or `_meta`, which core MCP already reserves for extensions.

```bash
pip install mcp-vlei
pip install "mcp-vlei[keri]"   # adds keripy for offline chain walking
```

Requires the MCP Python SDK 2.2.0+ (`mcp.server.extension.Extension`, SEP-2133).

## Server — three lines

```python
from mcp.server import MCPServer
from mcp_vlei import VleiIdentity

mcp = MCPServer(name="association", version="0.1.0", extensions=[VleiIdentity(
    le_credential="credentials/le.cesr",
    requires="ECR",
    verifier_url="http://localhost:7676",
    accepted_roots=["EHJ2kA8vQZ4Yd3mRr7TcN1sWpLxFbGuV9oKqDzXnA5eM"],
)])
```

A tool states its own requirement, and the extension enforces it:

```python
@mcp.tool(meta={"org.gleif.vlei/requires": {"credential": "ECR", "role": "member-registration"}})
def register_member(name: str, email: str) -> str:
    ...
```

The tool body contains no vLEI code and makes no verification decisions. That separation is the
point: the same requirement can be enforced in-process, at a gateway, or by a third party without
the tool changing.

## Client — three lines

```python
from mcp_vlei import VleiClient

session = VleiClient(session, credential="credentials/ecr.cesr",
                     key_store="./keys", verify_server=True)
await session.connect()          # verifies the server's LE before anything is called
await session.list_tools()       # reads each tool's org.gleif.vlei/requires

if session.entitlement_for("register_member"):
    await session.call_tool("register_member", {"name": "A", "email": "a@example.org"})
```

`entitlement_for` is answered locally, **before** the call. The requirement is declared in the tool's
schema precisely so that an agent can decline in terms the user understands rather than attempt the
call and interpret a rejection — and so a foreseeable failure does not land in the counterparty's
audit log.

## Modules

| Module | Responsibility |
|---|---|
| `extension.py` | `VleiIdentity(Extension)` — `settings()`, `tools()` (`vlei_whoami`), `intercept_tool_call()`; reads `Tool._meta` requirements and enforces role and scope |
| `client.py` | `VleiClient` — verifies the server's LE (from `discover` or `/.well-known/vlei`), signs each call, verifies an attestation before believing it |
| `signing.py` | RFC 8785 canonicalization, digest, Ed25519 signing and verification, replay cache, scope comparison |
| `verifier.py` | Thin adapter over GLEIF-IT/vlei-verifier, result caching, offline fallback |
| `attest.py` | Producing and verifying `VleiAttestation` (mode (b), letter of confirmation) |
| `errors.py` | Failure layers |

## Design rules this package follows

**Verification logic lives here, never in a server.** A server declares what it requires; it does
not decide what "valid" means.

**Failures name their layer.** `revoked`, `role_mismatch`, `digest_mismatch`, `scope_exceeded`,
`chain_invalid`, `unknown_root`, `invalid_signature`, `stale_signature`. The correct recovery
differs per layer, and `skills/vlei-identity/SKILL.md` keys its behavior off these exact strings. Of
the eight, exactly one — `stale_signature` — is worth retrying.

**Signature freshness defaults to 60 seconds, plus a replay cache.** The window alone bounds replay
to a minute rather than eliminating it; the cache is the other half.

**Verification results are cached per `ttl_ms` (default 30s).** A revocation therefore takes effect
no later than cache expiry. Set `ttl_ms=0` for high-value tools, where a stale "valid" costs more
than a round trip.

**An empty `accepted_roots` raises.** It is not "accept anything" — it is the entire trust decision,
and an empty list is a configuration error.

**`digest_mismatch` is checked before `invalid_signature`.** Altered arguments and a bad key state
are operationally different problems and must not be collapsed into one message.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

44 tests covering the acceptance list — valid call, no credential, revoked, tampered arguments,
expired signature, role mismatch, scope exceeded — plus canonicalization, replay, check ordering,
and the attestation safety property that a key the attester chose for itself does not help.

The tests use a stub verifier: what they exercise is this package's decision logic. The live
`vlei-verifier` is exercised end to end by `scripts/bootstrap-credentials.sh` checks 3–6.

## Key custody

`Signer.from_key_store` reads a raw Ed25519 seed from disk. That is a demo affordance so the
reference agent is runnable and inspectable. **In production, use Signify**: the private key stays
on the holder's device and the agent receives signatures rather than keys.

## Honesty statement

Real KERI, real ACDC, real verifier. The root of trust is self-configured; in production it would be
GLEIF's.
