# mcp-vlei

Verifiable **organizational** identity for the Model Context Protocol, using GLEIF's vLEI.

Implements the `org.gleif.vlei/identity` extension defined in [`spec/SPEC.md`](../../spec/SPEC.md).
Nothing in MCP's core schema is modified: every field this package puts on the wire travels in
`extensions` or `_meta`, which core MCP already reserves for extensions.

```bash
pip install mcp-vlei
```

Requires the MCP Python SDK 2.2.0+ (`mcp.server.extension.Extension`, SEP-2133).

## Server — three lines

```python
from mcp.server import MCPServer
from mcp_vlei import VleiIdentity

vlei = VleiIdentity(
    le_credential="credentials/le.cesr",
    requires="ECR",
    accepted_roots=["EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"],
    witness_url="http://localhost:5642",   # callers' key state and revocation, from their own logs
)
mcp = MCPServer(name="association", version="0.1.0", extensions=[vlei])
vlei.bind(mcp)   # so the extension can read each tool's declared requirement
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
                     signer=agent_signer(),      # the key stays in the keystore
                     accepted_roots=["EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"],
                     witness_url="http://localhost:5642",   # an attester's key state
                     verify_server=True)          # needs accepted_roots; raises without them
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
| `chain.py` | Reads an ACDC chain, recomputes every SAID, walks the edges to an accepted root — no service required |
| `verifier.py` | `OfflineVerifier` for a counterparty's credential; a thin adapter over GLEIF-IT/vlei-verifier for revocation |
| `revocation.py` | Three selectable revocation sources, and a refusal when the log cannot be read |
| `report.py` | `VerificationReport` — which checks ran, what each cost, which one stopped the call |
| `attest.py` | Producing and verifying `VleiAttestation` (mode (b), letter of confirmation) |
| `errors.py` | Failure layers |

## Design rules this package follows

**Verification logic lives here, never in a server.** A server declares what it requires; it does
not decide what "valid" means.

**Failures name their layer.** The correct recovery differs per layer, and
`skills/vlei-identity/SKILL.md` keys its behaviour off these exact strings.

| Layer | Means | Retry? |
|---|---|---|
| `missing_credential` | Nothing was presented. Not a failure to verify — a failure to present | no; attach one |
| `stale_signature` | Outside the freshness window, or a replay | **once** |
| `digest_mismatch` | Arguments do not match the signed digest — altered after signing | no |
| `invalid_signature` | Does not verify under the signing AID's key state | no |
| `chain_invalid` | A SAID does not recompute, a link is broken, or a log could not be read | no |
| `revoked` | Withdrawn in the issuer's transaction event log | no; a new credential must be issued |
| `unknown_root` | The chain is sound but terminates at a root this party does not accept | no; the two organizations must agree |
| `role_mismatch` | The ECR role does not satisfy the tool's requirement | no |
| `scope_exceeded` | The request exceeds the tool's declared scope | no; ask before retrying in scope |

Nine layers, and exactly one — `stale_signature` — is worth retrying.

## Settings

| Setting | Default | Notes |
|---|---|---|
| `accepted_roots` | — | **Security critical.** The entire trust decision. An empty list raises rather than accepting anything |
| `revocation_source` | `"tel"` | `"tel"` reads the issuer's log from a witness; `"verifier"` asks a `vlei-verifier`; `"none"` marks every result `revocation_checked=False` |
| `witness_url` | — | **Required.** Every caller's current key state is read from its key event log here — never from the request — and `revocation_source="tel"` reads the issuers' transaction event logs here too |
| `verifier_url` | — | Required by `revocation_source="verifier"`; choosing that source without one raises |
| `freshness_seconds` | 60 | Signature freshness window, paired with a replay cache that retains for twice as long |
| `ttl_ms` | 30000 | How long a verification result may be cached. **Set to 0 for high-value tools** — a revocation takes effect no later than cache expiry |

Two of these are security critical and worth stating plainly: **`accepted_roots` must never be
empty**, and **an unreadable revocation source refuses rather than allows**. Reporting "could not
check" as "not revoked" is the one failure this package is built to prevent.

**`digest_mismatch` is checked before `invalid_signature`.** Altered arguments and a bad key state
are operationally different problems and must not be collapsed into one message.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

143 tests, no containers required. They cover every failure layer, RFC 8785 canonicalization, replay,
check ordering, key event log verification, issuance anchoring, the vLEI chain shape, the report's
contents, and the attacks the first version let through — someone else's credential signed with your
own key, a key sent along with the request, a delegate of the wrong person, a credential its issuer
never anchored, a QVI issuing an ECR with no legal entity in the chain.

Nothing is stubbed but the network. `mcp_vlei.testing.World` mints a real KERI deployment —
witnessed, delegated key event logs, registries, issuances — and serves it through an
`httpx.MockTransport` shaped like a witness, so the package's own verification and HTTP code is what
runs. With a bootstrapped `credentials/`, the same checks also run against what `kli` wrote. The live
stack is exercised end to end by `scripts/bootstrap-credentials.sh` and
`examples/association-server/tests/`.

## Key custody

Two signers ship. `CommandSigner` never holds a key: it sends the payload to something that holds
one — `kli sign` against a KERI keystore in the reference agent — and receives a signature back.
That is the arrangement Signify provides in production, reached through a local command instead of
a KERIA agent, and swapping one for the other changes one class.

`Signer.from_key_store` reads a raw Ed25519 seed from disk. It exists for tests. keripy exposes no
way to export a private seed, which is correct: a key you can copy is a key that can be taken.

## Honesty statement

Real KERI, real ACDC, real verifier. The root of trust is self-configured; in production it would be
GLEIF's.
