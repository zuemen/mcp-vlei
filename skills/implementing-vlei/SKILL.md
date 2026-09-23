---
name: implementing-vlei
description: Implement the org.gleif.vlei/identity extension for MCP — verifiable legal-entity identity and agent authority. Use when writing or reviewing an MCP server or client that needs to establish which legal entity a call is made on behalf of, or what an agent is authorised to do.
---

# Implementing org.gleif.vlei/identity

This skill is for **build time**. It tells a coding assistant how to write an MCP
server or client that conforms to the extension. It is not a runtime policy — the
security properties come from the verification code you write here, not from any
instruction a model follows later.

Specification: `spec/SPEC.md`. Types: `spec/schema.ts`. Reference implementation:
`packages/mcp-vlei/`. Acceptance status: `examples/README.md`.

The companion skill, `skills/vlei-identity/`, is for **runtime**: it tells a running agent what to
present and how to read a refusal. The difference is worth holding onto — what you write here is
reviewed once and then executed every time; what that skill says is guidance a model may or may not
follow. Put the security properties here.

---

## What the extension adds

MCP verifies domains (TLS, OAuth `iss`, `client_id`) and users (OAuth `sub`). It
does not express a legal entity, and `clientInfo` is self-asserted — the
specification says not to rely on it. This extension adds four namespaced keys to
fields MCP already provides. **The core schema is not modified.**

| Where | Key | Carries |
|---|---|---|
| `extensions` | `org.gleif.vlei/identity` | capability declaration |
| request / result `_meta` | `org.gleif.vlei/credential` | CESR-encoded ACDC — LE for servers, ECR for agents |
| request `_meta` | `org.gleif.vlei/delegatedAid` | the agent's delegated AID |
| request `_meta` | `org.gleif.vlei/signature` | single-pass signature over the request |
| request / result `_meta` | `org.gleif.vlei/attestation` | a third party's signed verification result |
| `Tool._meta` | `org.gleif.vlei/requires` | credential, role and scope this tool requires |

The prefix is available because MCP reserves only prefixes whose **second label**
is `mcp` or `modelcontextprotocol`. Here the second label is `gleif`.

---

## Building a server

**In the Python SDK, do not plumb this by hand.** `mcp` 2.2.0 ships the extension framework this
design targets (SEP-2133):

```python
from mcp.server.extension import Extension, ToolBinding
from mcp.server.mcpserver import MCPServer

class VleiIdentity(Extension):
    identifier = "org.gleif.vlei/identity"          # validated at subclass definition

    def settings(self) -> dict:                     # advertised at capabilities.extensions[id]
        return {"presents": ["LE"], "requires": "ECR", "acceptedRoots": [...], ...}

    async def intercept_tool_call(self, params, ctx, call_next):
        ...                                         # verify here; call_next(ctx) to allow

mcp = MCPServer(name="…", version="…", extensions=[VleiIdentity()])
```

Three things to know about that surface, because each costs an afternoon to discover:

- `settings()` returns the capability **value**, not a dict keyed by the identifier again.
- `intercept_tool_call(params, ctx, call_next)` — three arguments. `params` is the validated
  `CallToolRequestParams`, so `params.meta` is the request `_meta` as a plain dict.
- Results use pydantic field names: `CallToolResult(is_error=True, meta={...})`, not `isError`.

Five things, in this order.

### 1. Declare the capability

```jsonc
"capabilities": {
  "extensions": {
    "org.gleif.vlei/identity": {
      "presents": ["LE"],
      "requires": "ECR",
      "acceptedRoots": ["E..."],
      "signatureAlgs": ["Ed25519"],
      "ttlMs": 3600000,
      "discovery": { "wellKnown": "https://host/.well-known/vlei" }
    }
  }
}
```

`acceptedRoots` MUST be explicit configuration. Never treat an empty or absent
set as "accept any root" — raise at construction instead. It is the entire trust decision, and an
empty list read as "anything" would accept every forged chain while passing every other check.

Field shapes, since the asymmetry is real and not a typo: `presents` and `signatureAlgs` are
**lists**, `requires` is a **single string** — a party requires one credential type, and may be
able to present several. `discovery` currently carries only `wellKnown`.

### 2. Present your own credential

Publish the LE credential at `discovery.wellKnown` — a plain `GET /.well-known/vlei`,
`application/json`, no session required:

```json
{
  "extension":     "org.gleif.vlei/identity",
  "credential":    "<CESR stream: the LE credential and its chain>",
  "acceptedRoots": ["EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"],
  "signatureAlgs": ["Ed25519"]
}
```

The key names matter more here than anywhere else in this document: this is the one artefact a
counterparty parses **before any session exists**, so there is no negotiation to fall back on. A counterparty can then fetch and
verify it **before** sending anything, which is the point of mode (a) in `spec/SPEC.md`
(*Two verification modes*).

You may also put it in the `_meta` of the discover result. Do not rely on that alone: in the
reference implementation the well-known document is the route that works today, and a client
falls back to it when the discover result carries no credential.

There is no third option. `Implementation` — the type of `serverInfo` — has no `_meta`, which is
the structural gap this extension exists to work around.

### 3. Declare requirements per tool

```jsonc
{
  "name": "submit_filing",
  "inputSchema": { "...": "..." },
  "_meta": {
    "org.gleif.vlei/requires": {
      "credential": "ECR",
      "role": "regulatory-filing",
      "scope": { "maxAmount": 1000000 }
    }
  }
}
```

The credential says **who the holder is**. This says **what may be done, within
what limits**. Put the requirement on the tool, not on the server: different
tools on one server legitimately need different authority.

**Scope is compared against the credential, not against the arguments.** The tool's `scope` states
what authority it demands; the credential carries what authority the entity granted. The check is
whether the second covers the first — a numeric requirement is met when the credential's value is
at least as large, a list when the credential's list is a superset.

**A key the credential does not carry is not satisfied.** Deny, do not default to allow. This is a
security decision and it belongs in the specification rather than in each implementer's judgement.

The specification fixes *where* scope lives and *that* it is checked. It does not impose a universal
algebra, so a deployment with different semantics replaces the comparison — but not this default.

### 4. Verify, in this order

Stop at the first failure and report its layer.

| # | Check | Failure layer |
|---|---|---|
| 0 | A credential and a signature were presented at all | `missing_credential` |
| 1 | Every credential in the chain hashes to its own SAID | `chain_invalid` |
| 2 | Each link's issuer is the previous link's issuee | `chain_invalid` |
| 3 | The chain terminates at a root you accept | `unknown_root` |
| 4 | `ts` within the freshness window, signature not seen before | `stale_signature` |
| 5 | `digest` matches the received parameters | `digest_mismatch` |
| 6 | Signature verifies against the signing AID's key | `invalid_signature` |
| 7 | No credential in the chain is revoked | `revoked` |
| 8 | Role satisfies the tool's requirement; request satisfies its scope | `role_mismatch` / `scope_exceeded` |

**Everything local before the one remote check.** Checks 1–6 are decided from the request itself;
only revocation requires asking anyone. Ordering it last means a verification service that is slow
or down degrades one specific check instead of every check — which is not a theoretical benefit: it
is the difference between a tampered-arguments test that reports `digest_mismatch` and one that
reports a connection error.

**How to recompute a SAID** (check 1), because the whole check rests on getting this exact:

> Take the credential's bytes **as they arrived**. Replace the 44-character value of its `d` field
> with 44 `#` characters — same length, so the `v` field's encoded size stays true. Blake3-256 over
> those bytes. CESR-encode as `E` + base64url of the 32-byte digest, 44 characters total.

Recompute over the received bytes, not over a re-serialized copy: any difference in field order or
spacing changes the digest, and re-serializing would hide exactly the tampering the check exists to
find.

The ACDC fields you will need: `d` is the SAID, `i` the issuer, `a.i` the issuee, `a.LEI` the LEI,
`a.engagementContextRole` the role, `ri` the registry, `s` the schema SAID, and `e.<label>.n` the
SAID an edge points at.

**Determine a credential's type from `s`, its schema SAID** — not from a name or a guessed field.
The published vLEI schema SAIDs are stable; an ECR is
`EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw`.

Note what check 1 buys you without any key at all. The SAID is a digest over the credential's
content, so altering any field breaks it. A relying party can detect tampering before it has
established anything about who issued what.

### 5. Report failures by layer

- Client never declared the extension, but the tool requires it →
  JSON-RPC error **`-32021`**. `data.requiredCapabilities` is a **`ClientCapabilities` object**,
  not a list of identifiers — the same shape the client sends at `initialize`, so the answer reads
  as "declare this and try again":

  ```json
  {"code": -32021,
   "data": {"requiredCapabilities": {"extensions": {"org.gleif.vlei/identity": {}}}}}
  ```

  The SDK has `types.MISSING_REQUIRED_CLIENT_CAPABILITY` and
  `types.MissingRequiredClientCapabilityErrorData` for exactly this. Use them.
- Declared but verification failed → `CallToolResult` with `isError: true`, the failing layer
  **first and unadorned in the text**, and the same layer in the result `_meta` under
  `org.gleif.vlei/failure`:

  ```json
  {"content": [{"type": "text", "text": "revoked: the credential has been revoked in the issuer's transaction event log"}],
   "isError": true,
   "_meta": {"org.gleif.vlei/failure": {"layer": "revoked", "message": "…"}}}
  ```

  Both, not either. A caller cannot switch on prose, and a person reading a log should not have to
  parse JSON. Do **not** reuse `org.gleif.vlei/attestation` for this — that key carries a third
  party's signed verification of someone else, which is a different statement entirely.

There are **nine** layers. Eight are verification failures — `invalid_signature`,
`stale_signature`, `digest_mismatch`, `chain_invalid`, `revoked`, `role_mismatch`,
`scope_exceeded`, `unknown_root` — and the ninth, `missing_credential`, is not a failure to verify
but a failure to present. Keeping it separate matters: the caller's next step is to attach a
credential, not to fix one.

Only `stale_signature` is worth retrying, and only once. Every other layer is a state of the world
that a retry cannot change.

---

## Building a client

### 1. Verify the server before calling anything

Fetch the server's credential — from `discovery.wellKnown`, or from the discover result's
`_meta` — and verify it **yourself**. You cannot delegate this: `/presentations` is the holder's
endpoint (see *Common mistakes*), so there is no service to hand a counterparty's credential to.

Recompute each SAID, follow the `e` edges, require that each link's issuer is the previous link's
issuee, and confirm the chain terminates in your `acceptedRoots`. If it fails, **do not proceed**.

Be honest about what you did not establish. Issuer signatures need each issuer's key event log;
revocation needs each issuer's transaction event log. If you reached neither, say so in the result
rather than letting a caller read "verified" — the reference implementation carries
`signatures_checked` and `revocation_checked` flags for exactly this. *Checked as far as we could*
is not *valid*, and conflating the two is the failure this whole extension exists to prevent.

### 2. Check yourself before sending

Read each tool's `org.gleif.vlei/requires`. If your role or scope does not cover
it, do not send the call. This saves a round trip; it is **not** a security
control — the server decides.

### 3. Sign the request

```
signature over:  method + "\n" + ts + "\n" + digest
digest        =  base64url(sha256(JCS(params without _meta)))    unpadded
```

Exactly, because every one of these breaks interop if guessed:

- `method` is the **JSON-RPC method** — the literal string `"tools/call"` — not the tool's name.
- `ts` is **RFC 3339 UTC**, e.g. `2026-09-23T04:12:47Z`. Not epoch seconds, not milliseconds.
- `digest` is unpadded base64url of the SHA-256 over the **RFC 8785 (JCS)** canonicalization of
  `params`, with the whole `_meta` member removed — not just the signature key, so the rule stays
  auditable by eye. `params` of `None` and `{}` must produce the same digest.
- The signature is CESR: `0B` + 86 characters for a non-indexed Ed25519 signature. Accept indexed
  forms too (`A…`, 88 characters) — a keystore-backed signer emits those, and they carry the same
  64 raw bytes.

The four request `_meta` keys, in full, so there is nothing to invent:

```json
"_meta": {
  "org.gleif.vlei/credential":     "<CESR stream: the ACDC and its chain>",
  "org.gleif.vlei/credentialSaid": "EM3weUSh…",
  "org.gleif.vlei/delegatedAid":   "EPP835Iz…",
  "org.gleif.vlei/signature":      {"aid": "EPP835Iz…", "ts": "2026-09-23T04:12:47Z",
                                    "digest": "9pQzR4mK…", "sig": "0BDwS8nU…", "alg": "Ed25519"}
}
```

`credentialSaid` names which credential in the stream is being presented. A chained export carries
several, and "the first one in the stream" is the root of the chain, not the leaf.

---

## Common mistakes

These are the ones that cost real time. The first three were found by building
this, not by reading the spec.

### Presentation is the holder's step, not the verifier's

`vlei-verifier`'s `PUT /presentations/{said}` requires **headers signed by the
AID the credential was issued to**. A relying party cannot present someone
else's credential on their behalf. It reads back what the holder established, via
`GET /authorizations/{aid}`. GLEIF's regulatory filing pilot works the same way.

### Ask about the issuee, not the signer

The agent signs with its **delegated AID**; the credential was issued to the
**person**. The verifier's record is keyed by the holder. Read the issuee out of
the credential rather than trusting the caller to name it.

### Protocol version negotiation decides whether extensions exist at all

Extensions are active only at protocol `2026-07-28`. In the Python SDK the high-level `Client`
negotiates it; `ClientSession.initialize()` alone negotiates a legacy version — 2025-11-25 — at
which `capabilities.extensions` comes back `null` no matter what the server declares.

**A server that appears to advertise nothing is usually a client that never got past the legacy
handshake.** Check the negotiated version first. This cost us an afternoon of looking at a server
that was working perfectly.

### Do not put the credential in `clientInfo`

`Implementation` has no `_meta` field — `Tool`, `Resource` and `Prompt` do, but
this type does not — and the specification limits its use to display, logging and
debugging. There is nowhere to put it and no permission to rely on it.

### Do not sign a nonce alone

Signing only a challenge value leaves the parameters unprotected: an intercepted
request can be replayed with different arguments. The digest exists for exactly
this. This is also why the design is single-pass — a stateless gateway evaluating
external authorization sees one message, not two.

### Do not use a reserved prefix

`io.modelcontextprotocol/`, `dev.mcp/`, `com.mcp.tools/` are reserved: the rule
is about the **second** label. `com.example.mcp/` is fine. So is
`org.gleif.vlei/`.

### Decide where revocation comes from, explicitly

Revocation lives in the issuer's transaction event log. There are two honest ways to reach it, and
one dishonest one:

- **Read the log from a witness** — `GET {witness}/query?typ=tel&vcid={said}`. No dependency on a
  verification service. The reference implementation's default (`revocation_source="tel"`).
- **Ask a verification service.** Right in production, where the verifier is operated and has its
  own view of the ecosystem (`revocation_source="verifier"`).
- **Skip it**, and mark every result as unchecked. Legitimate only if the relying party is told.

Never take the holder's word for it. A holder presenting a withdrawn credential simply omits the
withdrawal, so a `rev` event's absence from what *they* sent you establishes nothing.

And if the log cannot be read: **refuse**. Reporting "could not check" as "not revoked" is the one
failure mode worth being absolute about.

### Do not confuse the freshness window with `ttlMs`

They are different numbers doing different jobs, and reusing one for the other is a security bug:

| | What it bounds | Sensible default |
|---|---|---|
| freshness window | How old a request signature may be | **60 seconds** |
| replay-cache retention | How long `(aid, digest, ts)` is remembered | **at least** the freshness window |
| `ttlMs` | How long a *verification result* may be cached | 30s, and **0** for high-value tools |

An hour-long `ttlMs` used as a replay window would accept an hour-old signature. The replay cache
must outlive the freshness window, or a signature can be replayed the moment it is forgotten.

### Do not cache revocation with the chain

Chain verification MAY be cached for `ttlMs`. Revocation state SHOULD NOT be —
caching it buys a window in which a revoked credential is still honoured.

### Do not log the whole credential

Credentials carry a natural person's name. Log the LEI, the role, the credential
SAID and the delegated AID. That is enough for audit and no more than necessary.

---

## Conformance checklist

A server is conformant when all of these hold:

- [ ] Declares `org.gleif.vlei/identity` in `capabilities.extensions`
- [ ] Publishes its LE credential at `discovery.wellKnown`, reachable without a session
- [ ] Declares `org.gleif.vlei/requires` on every protected tool
- [ ] Runs checks 0–8 in order, stopping at the first failure, local checks before the remote one
- [ ] Establishes revocation from the issuer's log, and refuses when it cannot
- [ ] Returns `-32021` when the extension is required but was not declared
- [ ] Returns `isError: true` with the failing layer named otherwise
- [ ] **Serves unprotected tools normally to clients that do not support the extension**
- [ ] `acceptedRoots` is explicit configuration, never empty by default

The last two are the ones reviewers should check first: the additive property is
what makes the extension adoptable, and an empty root set silently accepts
anything.

A client is conformant when it verifies the server before its first call, signs
every protected call over method, timestamp and parameter digest, and surfaces
the failing layer rather than a generic error.
