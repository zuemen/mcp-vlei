---
name: implementing-vlei
description: Implement the org.gleif.vlei/identity extension for MCP — verifiable legal-entity identity and agent authority. Use when writing or reviewing an MCP server or client that needs to establish which legal entity a call is made on behalf of, or what an agent is authorised to do.
---

# Implementing org.gleif.vlei/identity

> **Namespace.** This draft uses `org.gleif.vlei/identity` as a provisional, demonstration
> namespace. It has not been reviewed or endorsed by GLEIF. Reverse-domain prefixes conventionally
> belong to the domain's owner, so the final name is expected to follow GLEIF's view — it may stay
> as is, or move to another prefix. Implementations should treat the namespace as configuration
> (`MCP_VLEI_NAMESPACE`), not as a constant.

Build every key and the extension identifier from one configured namespace
(`packages/mcp-vlei/src/mcp_vlei/namespace.py` does it for the reference implementation), and treat
a client that declared the extension under another namespace as one that did not declare it:
`-32021`.

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
specification says not to rely on it. This extension adds namespaced keys to
fields MCP already provides. **The core schema is not modified.**

| Where | Key | Carries |
|---|---|---|
| `extensions` | `org.gleif.vlei/identity` | capability declaration |
| request / result `_meta` | `org.gleif.vlei/credential` | CESR-encoded ACDC — LE for servers, ECR for agents |
| request `_meta` | `org.gleif.vlei/delegatedAid` | the agent's delegated AID; optional, and when present it must equal `signature.aid` |
| request `_meta` | `org.gleif.vlei/credentialSaid` | which credential in the presented stream is the one being presented; optional — without it, the leaf |
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

Six things, in this order.

### 1. Declare the capability

```jsonc
"capabilities": {
  "extensions": {
    "org.gleif.vlei/identity": {
      "presents": ["LE"],
      "requires": "ECR",
      "acceptedRoots": ["E..."],
      "signatureAlgs": ["Ed25519"],
      "signatureFormats": ["vlei-sig/0.3"],
      "pop": "/.well-known/vlei/pop",
      "ttlMs": 300000,
      "discovery": { "wellKnown": "https://host/.well-known/vlei" }
    }
  }
}
```

`acceptedRoots` MUST be explicit configuration. Never treat an empty or absent
set as "accept any root" — raise at construction instead. It is the entire trust decision, and an
empty list read as "anything" would accept every forged chain while passing every other check.

Field shapes, since the asymmetry is real and not a typo: `presents`, `signatureAlgs` and
`signatureFormats` are **lists**, `requires` is a **single string** — a party requires one
credential type, and may be able to present several. `discovery` currently carries only
`wellKnown`.

`signatureFormats` names the request-signature format you verify, `["vlei-sig/0.3"]`; `pop` is where
you answer a proof-of-possession challenge (step 3) — a path resolved against the origin of your MCP
endpoint, or an absolute URL. A v0.3 client refuses a server that declares no `vlei-sig/0.3` or no
`pop` as `unsupported_version`, before presenting anything. `ttlMs` is how long a client may rely on
its verification of you before it verifies you again — chain, revocation, proof; the reference
client re-checks after 300 s at most.

### 2. Present your own credential

Publish the LE credential at `discovery.wellKnown` — a plain `GET /.well-known/vlei`,
`application/json`, no session required:

```json
{
  "extension":     "org.gleif.vlei/identity",
  "credential":    "<CESR stream: the LE credential and its chain>",
  "acceptedRoots": ["EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"],
  "signatureAlgs": ["Ed25519"],
  "signatureFormats": ["vlei-sig/0.3"],
  "pop": "/.well-known/vlei/pop",
  "ttlMs": 300000
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

### 3. Answer proof-of-possession challenges

Your LE credential is public; anyone can publish a copy of it. So before presenting anything, a
v0.3 client challenges you to prove you hold its key (`spec/SPEC.md`, *Proof of possession*).
Answer at the `pop` you declared — conventionally `/.well-known/vlei/pop`, reachable without a
session, like the well-known document:

```
POST /.well-known/vlei/pop   {"v": "vlei-pop/0.3", "nonce": "<22-64 chars of base64url>", "url": "<endpoint URL>"}
200   {"v": "vlei-pop/0.3", "aid", "nonce", "url", "ts", "exp", "sig"}
      sig over UTF-8(JCS({"aid", "exp", "nonce", "ts", "url", "v"}))
```

- **Sign with the LE's issuee, or with an AID it delegated to** — one whose `dip` names the LE's
  issuee in `di` and is anchored in the LE's key event log. A delegate lets the LE's own key stay
  offline; the client reads the signer's key state from witnesses and checks both.
- **Echo the challenge's nonce and URL, and sign only for URLs you are reached at.** Any other URL
  is `403` naming `audience_mismatch`, without listing your URLs, so a relay at another address
  cannot obtain a proof for the URL its victim dialled.
- `ts` now, `exp` shortly after: 60 s in the reference; a client refuses more than 120 s.
- A malformed challenge is `400`; a keystore that cannot sign is `503`. The client then reports the
  proof as not established and presents nothing.

`spec/examples/pop-exchange.json` has a real exchange. In Python, `mcp_vlei.pop.PopResponder(signer,
recipient).respond(body)` returns `(status, JSON body)` — `signer` is anything with `.aid` and
`.sign(bytes)`, such as a `CommandSigner` over `kli sign` — and `VleiIdentity(pop_signer=…)`
declares `pop` and answers through `pop_response(body)`; route the `POST` to it.

### 4. Declare requirements per tool

```jsonc
{
  "name": "enroll_employee",
  "inputSchema": { "...": "..." },
  "_meta": {
    "org.gleif.vlei/requires": {
      "credential": "ECR",
      "role": "labor-insurance-filing",
      "scope": { "maxAmount": 1000000 },
      "arguments": { "start_date": { "dateWithinDays": [0, 10] } }
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

**`arguments` is the one rule that does look at the arguments** — a window that holds whoever calls,
such as "the start date is today or up to ten days ahead". `dateWithinDays: [lo, hi]` is the only
rule defined; a missing or unreadable date fails it, a rule you do not implement refuses the call,
and a failure is `scope_exceeded` naming the argument.

**A key the credential does not carry is not satisfied.** Deny, do not default to allow. This is a
security decision and it belongs in the specification rather than in each implementer's judgement.

The specification fixes *where* scope lives and *that* it is checked. It does not impose a universal
algebra, so a deployment with different semantics replaces the comparison — but not this default.

### 5. Verify, in this order

Stop at the first failure and report its layer.

| # | Check | Failure layer |
|---|---|---|
| 0 | A credential, a signature and a `credentialSaid` were presented at all; the signature is `vlei-sig/0.3` | `missing_credential`; `unsupported_version` |
| 1 | `ts`/`exp` inside the window (`exp > ts`, `exp − ts` ≤ 60 s, `ts ≤ now + skew`, `now ≤ exp + skew`), and `ts ≥ memory_since + skew` | `stale_signature` |
| 2 | `aud.aid` is your own LE's issuee and `aud.url` one of your endpoint URLs; `digest` matches the received parameters | `audience_mismatch`; `digest_mismatch` |
| 3 | The rebuilt statement verifies under the **signing AID's current key state, read from its key event log at a quorum of witnesses** — never under a key the request carries | `invalid_signature` |
| 4 | `(aid, nonce)` claimed atomically — **only after** check 3 passed | `stale_signature` |
| 5 | The signing AID **is** the credential's issuee, or is **delegated by** the issuee in the issuee's own key event log | `invalid_signature` |
| 6 | Every credential hashes to its own SAID, and each link's issuer is the previous link's issuee | `chain_invalid` |
| 7 | The chain terminates at a root you accept | `unknown_root` |
| 8 | Every credential's issuance is **anchored in its issuer's key event log** | `chain_invalid` |
| 9 | The chain has the vLEI shape: each edge points at a credential of the schema it declares; an ECR or OOR is issued under an LE credential **naming the same LEI**; an LE credential is issued under a QVI credential | `chain_invalid` |
| 10 | The leaf's schema is the type the tool requires | `chain_invalid` |
| 11 | For **every** credential in the chain, the issuer's live transaction event log records its issuance and no revocation | `revoked` (`chain_invalid` if the log has no issuance) |
| 12 | The credential's role is the tool's `role`; the credential's `scope` covers the tool's declared `scope` | `role_mismatch` / `scope_exceeded` |

**Decide from the request first, then ask.** Checks 1 and 2 need nothing but the request and
your own configuration, so a stale, misdirected or altered call is refused without a round trip; check 3 onwards needs the signer's key
event log. Ordering matters for the report as much as for cost: a tampered-arguments test must
report `digest_mismatch`, not a connection error to a witness.

**Checks 3, 5, 8 and 9 are the security of the whole extension. Get them exactly right.**

- **Where the key comes from (check 3).** Fetch the signing AID's key event log from a witness —
  `GET <witness>/query?typ=kel&pre=<aid>` on a keripy witness — and verify it: the inception's SAID
  is the prefix, every event's SAID recomputes, each event names the previous one, each is signed
  by the keys current at that point, each carries witness receipts up to its threshold, and every
  rotation reveals keys the previous establishment event committed to. The current keys are the
  last establishment event's `k`. **Never verify under a key the request carries** — whoever sends
  a call would then choose the key it is checked against, and any credential anyone has ever been
  shown could be presented as theirs. A request whose signature cannot be checked is refused;
  there is no "skipped".
- **Who may sign (check 5).** A credential is sent with every call, so every server a holder has
  ever called has a copy. What makes a presentation the holder's is that the signer is the holder
  — or an AID whose inception is a `dip` naming the holder in `di`, **and** whose inception the
  holder's own key event log anchors with a seal `{"i": <agent AID>, "s": "0", "d": <dip SAID>}`.
  Claiming a delegator is not being delegated.
- **Who issued it (check 8).** A SAID proves a credential was not altered; it does not prove who
  made it. Anyone can write an ECR naming a real LE as issuer and themselves as issuee, and every
  SAID recomputes. The credential's `ri` names a registry; that registry's `vcp` must name the
  credential's issuer in `ii`; the `iss` event for the credential must be in that registry; and the
  issuer's key event log must anchor both (`{"i": <registry>, "s": "0", "d": <vcp SAID>}` and
  `{"i": <credential SAID>, "s": "0", "d": <iss SAID>}`). A `kli vc export --full` stream carries
  the issuers' logs, the registry events and the credentials together, so this is decidable from the
  presented stream.
- **Whose LEI (check 9).** Issuance proves each credential was made by the identifier it names; it
  does not prove the chain means what the leaf claims. A QVI can issue an ECR straight off its own
  QVI credential — no legal entity anywhere, any LEI it cares to write — and an LE can issue an ECR
  naming another entity's LEI. Every issuance anchors, every SAID recomputes. So an ECR or OOR must
  be issued under an LE credential (`s` = `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY`) whose
  `a.LEI` equals the ECR's, that LE credential under a QVI credential
  (`EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao`), and every edge's `s` must equal the schema of
  the credential it points at.
- **Revocation covers the chain (check 11).** An ECR under a withdrawn LE is withdrawn authority. Ask
  the live log about every link, and read "this log has no issuance" as *not established*, never as
  *not revoked*.

In Python, `mcp_vlei` has each of these as a function you can call rather than rewrite:
`mcp_vlei.kel.WitnessKeyStates` (check 3, and the delegation in check 5 — it raises `ChainInvalid`
when a log cannot be read or does not verify; a server reports that as `invalid_signature`, because
the signature was not checked), `mcp_vlei.signing.precheck_request` / `verify_request` (checks 1–4),
`mcp_vlei.verifier.OfflineVerifier` (checks 6–9, in that order; check 10 is yours),
`mcp_vlei.revocation.TelRevocationChecker` (check 11). In another language, use a KERI library
(keripy, Signify, keriox) for the key event log rather than writing one; the rules above are what
it must enforce.

**How to recompute a SAID** (check 6), because the whole check rests on getting this exact:

> Take the credential's bytes **as they arrived**. Replace the 44-character value of its `d` field
> with 44 `#` characters — same length, so the `v` field's encoded size stays true. Blake3-256 over
> those bytes. CESR-encode as `E` + base64url of the 32-byte digest, 44 characters total.

Recompute over the received bytes, not over a re-serialized copy: any difference in field order or
spacing changes the digest, and re-serializing would hide exactly the tampering the check exists to
find.

The ACDC fields you will need: `d` is the SAID, `i` the issuer, `a.i` the issuee, `a.LEI` the LEI,
`a.engagementContextRole` the role, `a.scope` the scope (an object; absent means no scope), `ri` the
registry, `s` the schema SAID, `e.<label>.n` the SAID an edge points at and `e.<label>.s` the schema
it declares. An `acceptedRoots` entry is an **issuer AID**: the walk stops at the first credential
whose `i` is in the set. `spec/examples/digest-vectors.json` has digest and signature test vectors.

**Determine a credential's type from `s`, its schema SAID** — not from a name or a guessed field.
The published vLEI schema SAIDs are stable; an ECR is
`EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw`.

Note what check 6 buys you without any key at all. The SAID is a digest over the credential's
content, so altering any field breaks it. A relying party can detect tampering before it has
established anything about who issued what.

### 6. Report failures by layer

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

There are **eleven** layers. Nine are verification failures — `invalid_signature`,
`stale_signature`, `audience_mismatch`, `digest_mismatch`, `chain_invalid`, `revoked`,
`role_mismatch`, `scope_exceeded`, `unknown_root`. `missing_credential` is not a failure to verify
but a failure to present, and `unsupported_version` says one side does not speak vlei-sig/0.3.
Keeping them separate matters: the caller's next step is to attach a credential, or upgrade, not to
fix one.

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

Then **challenge it** (`spec/SPEC.md`, *Proof of possession*): `POST` `{"v": "vlei-pop/0.3",
"nonce", "url"}` to the `pop` it declares, and accept the answer only if it echoes your nonce and
URL, is fresh, and verifies under the key state — from a majority of your witnesses — of the LE's
issuee or of an AID whose `dip` the LE's key event log anchors. A server that declares no
`vlei-sig/0.3`, or no `pop`, is `unsupported_version`: present nothing. Verify all of it again
before presenting once the server's `ttlMs` (or your own limit) has passed.

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
signature over:  JCS({"aid", "aud": {"aid", "url"}, "cred", "digest", "exp",
                      "method", "nonce", "ts", "v": "vlei-sig/0.3"})
digest        =  base64url(sha256(JCS(params without _meta)))    unpadded
```

Exactly, because every one of these breaks interop if guessed:

- `method` is the **JSON-RPC method** — the literal string `"tools/call"` — not the tool's name.
- `aud.aid` is the issuee of the LE you verified for the server; `aud.url` the endpoint URL you send
  to, normalised (lower-case scheme and host, no default port, no query).
- `cred` is the `credentialSaid` you send beside the signature — required.
- `ts` and `exp` are **RFC 3339 UTC**, e.g. `2026-09-23T04:12:47.000Z`, `exp` 30 s later. `nonce`
  is 16 random bytes, base64url, unpadded.
- `digest` is unpadded base64url of the SHA-256 over the **RFC 8785 (JCS)** canonicalization of
  `params`, with the whole `_meta` member removed. Numbers as ECMAScript writes them (`1e+21`),
  integers within ±(2⁵³−1). `params` of `None` and `{}` must produce the same digest.
  `spec/examples/digest-vectors.json` and `jcs-number-vectors.json` settle the bytes.
- The signature is CESR: `0B` + 86 characters for a non-indexed Ed25519 signature. Accept indexed
  forms too (`A…`, 88 characters) — a keystore-backed signer emits those, and they carry the same
  64 raw bytes.

The four request `_meta` keys, in full, so there is nothing to invent:

```json
"_meta": {
  "org.gleif.vlei/credential":     "<CESR stream: the ACDC and its chain>",
  "org.gleif.vlei/credentialSaid": "EM3weUSh…",
  "org.gleif.vlei/delegatedAid":   "EPP835Iz…",
  "org.gleif.vlei/signature":      {"v": "vlei-sig/0.3", "aid": "EPP835Iz…",
                                    "aud": {"aid": "EReg…", "url": "http://localhost:3000/mcp"},
                                    "ts": "2026-09-23T04:12:47.000Z", "exp": "2026-09-23T04:13:17.000Z",
                                    "nonce": "q3V0b2tlbi1ub25jZS0x", "digest": "9pQzR4mK…",
                                    "sig": "0BDwS8nU…", "alg": "Ed25519"}
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

### Never verify a signature under a key the request supplied

The most damaging mistake this repository made, and it shipped with every test green. The request
carried the signer's public key, the server verified under it, and a request with no key skipped
the check. The credential in a request is not a secret — it is sent to every server the holder
calls — so anyone who had seen one could sign with their own key and be accepted as its holder.
The tests passed because they only ever signed with the right key. Write the test that signs
someone else's credential with a key of your own, and watch it fail before you believe the check.

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
| clock tolerance (`skew`) | How far `ts` may be ahead of your clock, and how long after `exp` a signature is still accepted | **60 seconds** |
| longest lifetime | How long a signature may ask to live, `exp − ts` (the reference client asks for 30 s) | **60 seconds** |
| nonce claims | How long a claimed `(aid, nonce)` is remembered | **at least `exp + 2 × skew`** |
| `ttlMs` | How long a counterparty may rely on its *verification of you* | 30 s, and **0** for high-value tools |

An hour-long `ttlMs` used as a replay window would accept an hour-old signature. A nonce claim must
outlive the last instant the time check accepts, `exp + skew`, by one more skew: the claim is made a
moment after the check, and a claim that lapsed at `exp + skew` could already be gone when a copy
checked just before that instant is claimed. Claim `(aid, nonce)` atomically and **only after the
signature verifies** — claiming earlier lets anyone who saw a nonce burn it with a signature that
does not verify. And know where your memory starts (`memory_since`): after a restart that lost the
claims, refuse `ts < memory_since + skew`, the only signatures you could have accepted before.

### Do not cache revocation with the chain

Chain verification MAY be cached for `ttlMs`. Revocation state SHOULD NOT be —
caching it buys a window in which a revoked credential is still honoured.

### Do not log the whole credential

Credentials carry a natural person's name. Log the LEI, the role, the credential
SAID and the delegated AID. That is enough for audit and no more than necessary.

---

## Conformance checklist

A server is conformant when all of these hold:

- [ ] Declares `org.gleif.vlei/identity` in `capabilities.extensions`, with `signatureFormats`
      `["vlei-sig/0.3"]` and `pop`
- [ ] Publishes its LE credential at `discovery.wellKnown`, reachable without a session
- [ ] Answers proof-of-possession challenges at `pop` with its LE's key or a delegate's, only for
      the URLs it is reached at
- [ ] Refuses a signature made for another recipient (`audience_mismatch`), and claims each
      `(aid, nonce)` once, after the signature verifies
- [ ] Declares `org.gleif.vlei/requires` on every protected tool
- [ ] Runs checks 0–12 in order, stopping at the first failure
- [ ] Verifies request signatures under the signer's key state **from its key event log**, never
      under a key the request carries, and refuses a request whose signature cannot be checked
- [ ] Accepts a signer only if it is the issuee or delegated by the issuee in the issuee's log
- [ ] Establishes that every credential was issued by the identifier it names (issuer's log anchors it)
- [ ] Refuses an ECR or OOR that is not issued under an LE credential naming the same LEI
- [ ] Establishes revocation for **every** credential in the chain from the issuers' live logs, and
      refuses when it cannot
- [ ] Returns `-32021` when the extension is required but was not declared
- [ ] Returns `isError: true` with the failing layer named otherwise
- [ ] **Serves unprotected tools normally to clients that do not support the extension**
- [ ] `acceptedRoots` is explicit configuration, never empty by default

The last two are the ones reviewers should check first: the additive property is
what makes the extension adoptable, and an empty root set silently accepts
anything.

A client is conformant when it verifies the server — chain, revocation and proof of possession —
before presenting anything, and again once the server's `ttlMs` (or its own limit) has passed; signs
every protected call as `vlei-sig/0.3`, over the recipient (`aud`: the server's LE AID and the
endpoint URL), the `credentialSaid`, the parameter digest, `ts` and `exp`, a fresh nonce and the
method; and surfaces the failing layer rather than a generic error.
