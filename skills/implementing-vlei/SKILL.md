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
set as "accept any root".

### 2. Present your own credential

Publish the LE credential at `discovery.wellKnown` — a plain `GET /.well-known/vlei` returning
the credential, the accepted roots and the signature suites. A counterparty can then fetch and
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

Note what check 1 buys you without any key at all. The SAID is a digest over the credential's
content, so altering any field breaks it. A relying party can detect tampering before it has
established anything about who issued what.

### 5. Report failures by layer

- Client never declared the extension, but the tool requires it →
  JSON-RPC error **`-32021`**, with `data.requiredCapabilities` naming the extension.
- Declared but verification failed → `CallToolResult` with `isError: true`, and
  the failing layer named in the text.

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
digest        =  base64url(sha256(JCS(params without _meta)))
```

Canonicalise with RFC 8785. Remove the whole `_meta` member before hashing — not
just the signature key — so the rule stays auditable by eye.

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
