# vLEI Identity Extension for MCP

> **Namespace.** This draft uses `org.gleif.vlei/identity` as a provisional, demonstration
> namespace. It has not been reviewed or endorsed by GLEIF. Reverse-domain prefixes conventionally
> belong to the domain's owner, so the final name is expected to follow GLEIF's view — it may stay
> as is, or move to another prefix. Implementations should treat the namespace as configuration
> (`MCP_VLEI_NAMESPACE`), not as a constant.

**Extension identifier:** `org.gleif.vlei/identity` (provisional — see *Namespace*)
**Base specification:** MCP 2026-07-28
**Status:** v0.3 — validated against a reference implementation; field details may still change.
v0.3 binds every request signature to its recipient, its credential and a single use, and has the
client verify that a server holds its legal entity's key (threat model: *Security Considerations*)
**Repo:** `mcp-vlei`

This extension adds verifiable **organizational** identity and **role-scoped** authorization to MCP
using GLEIF's vLEI ecosystem (KERI AIDs, ACDC credentials, LE and ECR credential types). It does not
modify `modelcontextprotocol/modelcontextprotocol`'s `schema.ts`. It defines new types that travel in
the fields the core specification already reserves for this purpose: `ClientCapabilities.extensions`
and `ServerCapabilities.extensions`, `RequestMetaObject`, `ResultMetaObject`, and `Tool._meta`.

The extension identifier follows the core naming rules: a reverse-DNS prefix whose second label is
`gleif`, which is outside the reserved `modelcontextprotocol` / `mcp` range. The name itself is
provisional; *Namespace* below says what that means for an implementation.

## Motivation

`docs/PROBLEM.md` states the boundary in full. In brief:

- Every verified layer in MCP proves **domain control** (TLS, OAuth `iss`, OAuth `client_id`) or the
  identity of a **human user** (OAuth `sub`). No layer expresses a legal entity.
- `clientInfo` / `serverInfo` are self-reported, not verified by the protocol, and the specification
  says they SHOULD NOT be relied on for security decisions — correctly, since nothing backs them.
- `agent`, `principal`, `delegation`, and `mandate` appear zero times in the normative schema, so the
  entity that invokes a tool has no protocol representation.
- `Implementation` has no `_meta`, so there is no schema-level place to attach a credential to a
  *party* (as opposed to a tool, resource, or prompt).

vLEI already solves the identity half: a **Legal Entity (LE)** credential issued through a Qualified
vLEI Issuer binds an AID to an LEI; an **Engagement Context Role (ECR)** credential binds a person's
AID to a role within that entity; both are ACDCs, both are revocable, and both are verifiable
offline against a KEL. What is missing is the binding into MCP's call path. That binding is what this
document specifies.

**ECR, not OOR.** OOR credentials assert an *official organizational role* drawn from a controlled
list of public positions, and require GLEIF-side validation of that position. ECR credentials assert
a context-specific engagement role whose vocabulary the legal entity itself defines. Agent mandates —
"may file regulatory returns up to this amount" — are engagement contexts, not public offices, so ECR
is the correct credential type.

## Specification

### Design principles

1. **Optional.** A party that does not declare the extension behaves exactly as core MCP specifies.
2. **Additive.** Every field this extension introduces lives in `extensions` or `_meta`. An
   implementation that does not understand those keys ignores them, per core MCP.
3. **Composable.** The extension coexists with OAuth rather than replacing it. **OAuth answers
   *which user authorized this client*; vLEI answers *which legal entity is accountable, acting in
   which role, within which scope*.** A deployment MAY require both; neither substitutes for the
   other.

### Namespace

Every name this extension puts on the wire — the extension identifier and each `_meta` key — is
`<namespace>/<name>`: `org.gleif.vlei/identity`, `org.gleif.vlei/credential`, and so on. This
section is about the `<namespace>` part.

**The convention.** MCP's `_meta` keys and extension identifiers carry a reverse-domain prefix. By
the same convention that governs Java packages and similar registries, a reverse-domain prefix
belongs to whoever owns the domain: `org.gleif.*` to the owner of `gleif.org`.

**What MCP reserves.** The 2026-07-28 revision reserves every prefix whose second label is
`modelcontextprotocol` or `mcp` — `io.modelcontextprotocol/`, `dev.mcp/`, and also
`com.mcp.tools/` — while `com.example.mcp/` is not reserved, its second label being `example`
(*Basic*, *General fields › `_meta`*). A namespace for this extension must not be a reserved one.
`org.gleif.vlei` is not: its second label is `gleif`.

**The status of the name.** `org.gleif.vlei` is a **provisional, demonstration** namespace. It has
not been reviewed or endorsed by GLEIF. Because the prefix follows GLEIF's domain, the final name is
expected to follow GLEIF's view: it may stay as it is, or the extension may move to another prefix.
This specification does not presume either outcome.

**Configuration, not a constant.** An implementation builds every name from one configured
namespace — in the reference implementation, `MCP_VLEI_NAMESPACE`, defaulting to the provisional
name (`packages/mcp-vlei/src/mcp_vlei/namespace.py`). Changing the name is therefore a change of
configuration, on both sides, and of nothing else:

- Both parties **MUST** use the same namespace. The keys a client presents, the requirement a tool
  declares and the extension a client declares at `initialize` are all read under the server's
  namespace.
- A server that requires the extension **MUST** treat a client that declared it under a different
  namespace exactly as a client that did not declare it: `-32021` (see *Errors*). An authorizer in
  front of the server that sees each request on its own — an HTTP gateway, which never sees
  `initialize` — cannot know what was declared; it verifies what the request carries and refuses
  with the failure layer (`missing_credential` when nothing under its namespace was presented).
- A tool whose `_meta` declares its requirement under another namespace is a misconfiguration. A
  server **MUST NOT** read it as a tool with no requirement — that would serve it as public — and
  **SHOULD** refuse calls to it, naming both namespaces. The same holds for near misses: a key whose
  last segment is `requires` in another case, with stray whitespace, or with no prefix. (A server
  that is given its requirements directly rather than reading its tools' `_meta` — the gateway
  arrangement — enforces exactly the requirements it was given.)
- The examples in this specification and in `spec/examples/` use the provisional default.

### Capability declaration

A party declares participation in the `extensions` member of its capabilities — a client in
`ClientCapabilities.extensions` at `initialize`, a server in `ServerCapabilities.extensions` of its
`initialize` or `server/discover` result — under the key `org.gleif.vlei/identity`, with a
`VleiIdentityCapability` value (see `schema.ts`). `Implementation` (`clientInfo` / `serverInfo`)
carries no `extensions` member; the MCP Python SDK 2.2.0 types agree.

- `presents` — which credential types this party is able to present (`"LE"`, `"ECR"`).
- `requires` — the credential type this party requires of its counterparty.
- `acceptedRoots` — AIDs of roots of trust this party will accept: **issuer AIDs**, not credential
  SAIDs. A chain is accepted when, walking its edges from the presented credential, it reaches a
  credential whose issuer is in this set. In production this is GLEIF's root; in this project's demo
  environment it is a self-configured root, and the demonstration says so wherever it is shown.
- `signatureAlgs` — currently `["Ed25519"]`.
- `signatureFormats` — the request-signature formats this party produces or verifies; currently
  `["vlei-sig/0.3"]` (see *Request signing*). A v0.3 client refuses a server that does not declare
  it (`unsupported_version`), before presenting anything.
- `pop` — where this party answers a proof-of-possession challenge: an absolute URL, or a path
  resolved against the origin of its MCP endpoint; conventionally `/.well-known/vlei/pop` (see
  *Proof of possession*).
- `ttlMs` — the longest a **counterparty** may cache its verification of this party — of this
  party's credential, and of a result this party returns — before verifying again; `0` means every
  time (see *Security Considerations*, revocation latency). A v0.3 client verifies the server again
  — chain, revocation, proof of possession — before presenting a credential once this much time,
  or its own limit (300 s in the reference client), has passed. It says nothing about this party's
  own caches.
- `discovery.wellKnown` — the URL at which this party publishes its credential for **passive
  verification** (mode (a) below).

### Two verification modes

Both modes are normative; an implementation MUST support (a) and SHOULD support (b).

**(a) Passive verification from a public location.** The presenting party publishes its credential
somewhere the verifier can fetch it without the presenter doing anything per-request: the `_meta` of
a `server/discover` result, or a `/.well-known/vlei` document at `discovery.wellKnown`. The verifier
fetches it, walks the chain to an accepted root, checks revocation, and decides on its own. The
presenter performs no per-verification work beyond answering a proof-of-possession challenge, which a
v0.3 client sends before presenting anything (see *Proof of possession*). This is the default for
server → client identity.

**(b) Attested confirmation ("來函確認" / letter of confirmation).** The verifier asks a party that
already holds a verification record — a gateway that has already verified the subject, or a peer
institution — to confirm an identity. That party replies with a `VleiAttestation`: who verified, who
was verified, the LEI, the role, the time of verification, and a signature by the attesting party's
own AID. The verifier checks the attesting party's signature and chain, and then trusts the
statement. This mirrors the way one government office writes to another to confirm a record, and it
is what makes inter-agency lookup expressible as a verifiable agent call.

**Presentation is the holder's step.** This is not a stylistic point; it decides the shape of every
deployment. GLEIF's `vlei-verifier` requires a presentation to carry HTTP headers signed by the AID
the credential was issued to, so a relying party **cannot** hand a counterparty's credential to a
verification service and ask about it. The division of labour follows: the holder presents once, and
the relying party reads back what that established (`GET /authorizations/{aid}`). GLEIF's regulatory
filing pilot is arranged the same way. A relying party checking a *counterparty's* credential —
mode (a) — therefore has no service to delegate to and MUST verify the chain itself.

An attestation is a statement *about* a verification, not a substitute for the credential. A verifier
MUST validate the attesting party's own identity under mode (a) before accepting any attestation
from it.

### Delegation: how an agent presents a person's credential

ECR credentials are issued to **natural persons** — the WebOfTrust/vLEI ECR schema makes
`personLegalName` a required attribute. There is no such thing as an ECR issued to a piece of
software, and this extension does not invent one.

An agent therefore does not hold its own credential. It holds a **delegated AID**, created under the
ECR holder's key event log, and uses it to present *the holder's* ECR. The credential says who the
person is and what role the entity granted them; the delegated AID says which agent the person
authorized to act within it; the signature ties a specific request to that agent.

This produces **two independent revocation switches**, and the distinction matters operationally:

| Revoke | Effect |
|---|---|
| The ECR credential | The person's authority is withdrawn. Every agent acting under it stops, and so does the person. |
| The delegation | That one agent stops. The person's credential and every other delegation are untouched. |

An institution that discovers a misbehaving agent does not have to strip a member of staff of their
role to stop it. An institution whose member of staff changes jobs revokes one credential and every
agent under it stops at once.

**A verifier MUST establish the holder from the credential, not from the caller.** The agent signs
with its delegated AID; the credential was issued to the person; a verification service keys its
record by that person. An implementation MUST read the issuee out of the presented credential and
MUST NOT accept a caller's assertion of whose record to consult — otherwise a caller could point the
question at an identifier whose record happens to be favourable. The delegated AID identifies who
acted; the issuee identifies whose authority they acted under, and the two are recorded separately.
The presented credential is the one `org.gleif.vlei/credentialSaid` names or, when that key is
absent, the leaf of the presented chain: `credentialSaid` selects *which* credential in the stream is
being presented — a `--full` export carries the whole chain — never *whose* it is.

`delegatedAid` is nonetheless **optional** in the schema. A deployment that cannot support delegated
inception may sign directly with the ECR holder's AID; it keeps every other property and loses only
the second switch.

### Request signing (vlei-sig/0.3)

A request signature is computed over a small **statement**, serialised with RFC 8785 (JCS):

```
statement = {
  "aid":    signature.aid,                         the signing AID
  "aud":    {"aid": <recipient LE AID>, "url": <endpoint URL>},
  "cred":   _meta["org.gleif.vlei/credentialSaid"],
  "digest": base64url(sha256(JCS(params without _meta))), unpadded,
  "exp":    RFC 3339, UTC,
  "method": "tools/call",
  "nonce":  128 random bits, base64url, unpadded (22 characters),
  "ts":     RFC 3339, UTC, at signing time,
  "v":      "vlei-sig/0.3"
}
signed bytes = UTF-8(JCS(statement))
```

The `VleiSignature` in `params._meta["org.gleif.vlei/signature"]` carries `v`, `aid`, `aud`, `ts`,
`exp`, `nonce`, `digest`, `sig` and `alg`; `cred` is `org.gleif.vlei/credentialSaid`, which a v0.3
request **MUST** carry. A verifier **MUST** rebuild the statement from those fields and its own
recomputation of the digest, never take it from the request. Every field is an identifier, a
timestamp, base64url or a normalised URL, so the signed bytes are ASCII. Test vectors, including a
deterministic signature: `spec/examples/digest-vectors.json`.

- **The recipient.** `aud.aid` is the issuee of the LE credential the client verified for that
  server; `aud.url` the endpoint URL the call is sent to, normalised (scheme and host lower-case,
  the host IDNA-encoded, the default port dropped, an empty path written `/`, percent-encoded octets
  in upper case; user-info, a query or a fragment refused). A verifier **MUST** refuse a signature
  whose `aud.aid` is not the issuee of its own LE credential, or whose `aud.url` is not one of the
  URLs it is reached at, as `audience_mismatch`. Only a well-formed `aud.aid` names another
  recipient: one that is not a 44-character CESR identifier is a malformed signature object,
  `invalid_signature`. A verifier that cannot state those URLs cannot check this, and **MUST NOT**
  verify v0.3 requests.
- **The arguments.** `digest` covers every member of `params` except `_meta` — for `tools/call`,
  the `name` and, when it is sent, `arguments`; a call with no arguments sends no `arguments`
  member and signs none. The canonical form is RFC 8785 over I-JSON (RFC 7493): numbers serialised
  as ECMAScript's `Number::toString` (`1e+21`, `1e-7`; `spec/examples/jcs-number-vectors.json`),
  integers beyond ±(2⁵³−1) refused rather than rounded, lone surrogates and NaN refused. A verifier
  that reads the request body itself **MUST** refuse a body with a repeated member name: two
  parsers read two different calls from it. All of these are `digest_mismatch`.
- **The time.** A client signs with `exp` shortly after `ts` (30 s in the reference client). A
  verifier with a clock tolerance `skew` (default 60 s) and a longest lifetime (default 60 s)
  **MUST** refuse, as `stale_signature`: `exp ≤ ts`; `exp − ts` beyond the longest lifetime;
  `ts > now + skew`; `now > exp + skew`. A `ts` or `exp` that is not an RFC 3339 timestamp with an
  offset is a malformed signature object, refused as `invalid_signature`: no clock makes it fresh,
  and `stale_signature` would tell the caller that re-signing the same way could succeed.
- **The nonce.** A verifier **MUST** claim `(aid, nonce)` atomically — insert if absent, in one
  operation — **after** the signature has verified and before anything else is decided, and
  **MUST** refuse a repeat as `stale_signature`. Claiming earlier lets anyone who saw a nonce burn
  it with a signature that does not verify. A claim **MUST** be kept until at least
  `exp + 2 × skew`: the time check accepts until `exp + skew`, and the claim is made a moment
  later, so a claim that lapsed at `exp + skew` could already be gone when a copy checked just
  before that instant is claimed.
- **Restarts.** A verifier **MUST** know the earliest instant from which it remembers every claim
  (`memory_since`) and **MUST** refuse, as `stale_signature`, any signature with
  `ts < memory_since + skew` — the only signatures it could have accepted before its memory began.
  A store that survives restarts keeps its `memory_since`; one held in memory starts it again, and
  refuses calls for `skew` seconds after each start.
- **Several instances.** Verifiers that share an audience **MUST** share one store of claims.
- **A nonce is not an idempotency key.** It makes a signature single-use, not an operation. A
  client **MUST** re-sign to retry; a tool whose effect is not idempotent **SHOULD** take an
  idempotency key among its arguments (covered by the digest), on which the server de-duplicates.

This is still a **single-pass** design: a gateway decides from one message. The nonce is the
client's, so the verifier needs no round trip — only a memory of the nonces it has accepted until
they expire.

### Proof of possession

A server's LE credential is public; anyone can publish a copy. Before presenting anything to a
server, a v0.3 client **MUST** have it prove that it holds the key of the LE it presents:

```
POST <pop>   {"v": "vlei-pop/0.3", "nonce": <128 random bits, base64url>, "url": <endpoint URL>}
200          {"v": "vlei-pop/0.3", "aid", "nonce", "url", "ts", "exp", "sig"}
             sig over UTF-8(JCS({"aid", "exp", "nonce", "ts", "url", "v"}))
```

- The signer **MUST** be the LE's issuee, or an AID whose delegated inception names the LE's
  issuee and is anchored in the LE's key event log. The client reads its key state from witnesses,
  as a verifier reads a request signer's, and checks the signature under it.
- A server **MUST** sign only for URLs it is reached at (`403` naming `audience_mismatch`
  otherwise), so a relay at another URL cannot obtain a proof for the URL its victim dialled.
- A client refuses: an answer to another nonce or URL (`audience_mismatch`); `exp ≤ ts`,
  `exp − ts > 120 s`, or a statement outside its clock tolerance (`stale_signature`); a signature
  that does not verify, a malformed proof (a `ts` or `exp` that is not RFC 3339 among it), a signer
  that is neither the LE nor its delegate, or a proof it could not obtain (`invalid_signature`); a
  server that declares no `pop`, or answers `404` (`unsupported_version`). Nothing is presented to
  a server that has not proven itself.
- A client verifies the server again — chain, revocation, proof — before presenting a credential
  once its last verification is older than the server's `ttlMs` or its own limit, and after any
  refusal naming `audience_mismatch`.

One exception: a client that trusts a gateway by configuration rather than verifying it (a console
or a script pointed at its own operator's gateway) takes the recipient from the gateway's published
document, unverified, and presents without a proof of possession; it **MUST** log that it did so.
The signature still names that recipient, so no other server can use it; what the client gives up
is knowing who the recipient is.

The proof shows who answers at that URL at that moment. It is not channel binding: it does not show
that no one sits between client and server at the same URL, which TLS is for.

### Whose key, and who may sign

A credential is not a secret. It is sent with every call, so every server a holder has ever called
holds a copy. What makes a presentation the holder's is **who signed the request** — so the key a
signature is checked against is the whole of the extension's security, and this section is
normative in every word.

- **Several witnesses, a majority agreeing.** A key state is read from every configured witness;
  each copy is verified on its own, fewer valid copies than the quorum (a majority by default, 2
  of 3) is *not established*, and two valid copies that differ is duplicity, refused. This holds
  for a verifier reading a request signer's log and for a client reading a server's — its LE's
  issuers' logs for revocation, and its proof signer's.
- **The key comes from the signer's key event log, never from the request.** A verifier MUST verify
  the request signature under the **current key state** of the AID named in `signature.aid`,
  established by verifying that AID's key event log as served by a witness (on a keripy witness,
  `GET /query?typ=kel&pre=<aid>`): the inception's SAID is the self-addressing prefix; every event's
  SAID recomputes; each names the previous event; each is signed by the keys current at that point to
  its threshold; each carries witness receipts to its witness threshold; and every rotation reveals
  keys the previous establishment event committed to. A verifier MUST NOT verify under a key carried
  in the request, and MUST refuse a request whose signature it cannot check — `invalid_signature`,
  never "skipped".
- **The signer must be the holder, or delegated by the holder.** The AID that signed MUST be either
  the issuee of the presented credential, or an AID whose inception is a delegated inception (`dip`)
  naming that issuee as delegator **and** whose inception the issuee's own key event log anchors
  (`{"i": <delegate>, "s": "0", "d": <dip SAID>}`). Otherwise `invalid_signature`. When
  `delegatedAid` is present it MUST equal `signature.aid`.
- **The credential must have been issued by the identifier it names.** A SAID proves a credential was
  not altered; it does not prove who made it. For every credential in the chain, a verifier MUST
  establish that the registry named by its `ri` was incepted (`vcp`) by the credential's issuer, that
  an `iss` event for it exists in that registry, and that the issuer's key event log anchors both.
  A `kli vc export --full` stream carries everything this needs. Otherwise `chain_invalid`.
- **Revocation covers every link.** A verifier MUST establish, from each issuer's live transaction
  event log, that every credential in the chain was issued and has not been revoked. A log that
  records no issuance is *not established* (`chain_invalid`), never *not revoked*.

### Tool-level requirements

A tool declares what it demands of a caller in its own `_meta`, under
`org.gleif.vlei/requires`: a credential type, an optional role string drawn from the entity's ECR
vocabulary, and an optional `scope` object of arbitrary constraints (`{"maxAmount": 1000000}`). This
places the permission **in the schema the client already reads**, so an agent can determine before
calling whether it is entitled to call — which is the precondition for the skill in
`skills/vlei-identity/`.

Scope semantics are deliberately open: a verifier compares the tool's declared `scope` against the
scope carried by the caller's ECR credential — the object at `a.scope` in its attribute block; a
credential without one carries no scope — using a comparison the deployment defines. Whatever the
comparison, a key the tool requires and the credential does not carry is **not** satisfied. The
extension specifies *where* scope lives and *that* it must be checked, not a universal scope algebra.

A requirement MAY also carry `arguments`: rules on the call's own arguments, keyed by argument
name, that hold whoever the caller is — a filing window, not a person's authority. They are checked
at the same stage as scope, after the role, and a call that breaks one fails with `scope_exceeded`,
naming the argument. This revision defines one rule, `dateWithinDays: [lo, hi]`: the argument is an
ISO 8601 calendar date between `lo` and `hi` days from the verifier's current date, inclusive. An
argument that is absent or not such a date does **not** satisfy the rule, and a verifier that meets
a rule it does not implement MUST refuse the call rather than skip the rule. `arguments` is
deployment policy: a server or gateway may hold it without publishing it, and a caller must not
assume that a tool whose published requirement carries no `arguments` has none.

### `_meta` keys

Every key is namespaced `org.gleif.vlei/`; `schema.ts` has the types.

| Key | Where | Carries |
|---|---|---|
| `credential` | request `params._meta`; a server's `server/discover` result `_meta` | CESR stream: an ECR and its chain from an agent, the LE from a server |
| `credentialSaid` | request | which credential in the stream is presented (see *Delegation*); **required** with a vlei-sig/0.3 signature, which speaks for it |
| `delegatedAid` | request | the agent's delegated AID; optional, and when present it must equal `signature.aid` |
| `signature` | request | the `VleiSignature`, `vlei-sig/0.3` (see *Request signing*) |
| `requires` | `Tool._meta` | the tool's requirement (see *Tool-level requirements*) |
| `attestation` | result `_meta` | a `VleiAttestation`, mode (b) |
| `failure` | result `_meta` of a refusal | `{layer, message, aid?, credentialSaid?}` — the layer again, for anything that parses rather than reads |
| `report` | result `_meta` | the ordered record of every check, what it established and what it cost (see *Errors*) — attached to a refusal by the reference `VleiIdentity`, and to every protected call by `examples/skill-server/` |
| `verkey` | request | **informational, never used for verification.** The reference `VleiClient` still sends the signer's current public key here; a verifier ignores it and reads the key state from the signer's key event log (see *Whose key, and who may sign*) |

### Errors

**Protocol-level.** If a server requires the extension and the client did not declare it — including a
client that declared it under a different namespace (see *Namespace*) — the server responds with
JSON-RPC error `-32021`. `data.requiredCapabilities` is a **`ClientCapabilities`
object** — `{"extensions": {"org.gleif.vlei/identity": {}}}` — not a list of identifiers: the same
shape the client sends at `initialize`, so the answer reads as "declare this and try again" rather
than needing translation. This lets a client distinguish "I am missing a capability" from "my
credential was rejected".

**Tool-level.** A refusal that occurs after the capability is present is returned as a tool result
with `isError: true`, and the text MUST name the failure layer using one of:

| Code | Meaning |
|---|---|
| `missing_credential` | The tool declares a requirement and the caller presented no credential, no signature, or no `credentialSaid` for a vlei-sig/0.3 signature. Not a failure to verify but a failure to present: the caller's fix is to attach a credential, not to repair one |
| `unsupported_version` | The other party does not speak `vlei-sig/0.3`: a signature without `v` (vlei-sig/0.2) or with another `v`, at a verifier; a server that declares no `signatureFormats` with it, or no proof of possession, at a client |
| `stale_signature` | Outside the signature's window (`ts`, `exp`, the clock tolerance, the longest lifetime), made before the verifier's replay memory began, or a nonce already claimed (a replay) |
| `audience_mismatch` | The signature — or a server's proof of possession — names another recipient: another LE AID, or another endpoint URL. A misconfigured client, or a call replayed to a server it was not meant for |
| `digest_mismatch` | `params` do not match the signed digest — arguments were altered after signing — or have no single canonical form (a repeated member name, an integer beyond I-JSON, NaN) |
| `invalid_signature` | Signature does not verify under the signing AID's current key state from its key event log, the key state could not be established, or the signer is neither the holder nor delegated by them |
| `chain_invalid` | The presented credential or its chain does not validate: an unreadable stream, a SAID that does not recompute, a broken link, an issuance not anchored in its issuer's key event log, a chain without the vLEI shape, a credential of a type other than the one the tool requires — or a live transaction event log that could not be read or records no issuance, which is revocation *not established* |
| `unknown_root` | Chain terminates at a root not in `acceptedRoots` |
| `revoked` | A credential in the chain is revoked |
| `role_mismatch` | Presented ECR role does not satisfy the tool's declared `role` |
| `scope_exceeded` | Request exceeds the tool's declared `scope`, or breaks one of its `arguments` rules |

**Not a layer: `verifier_error`.** A gateway whose own machinery fails while deciding — its replay
store, a client it uses, anything it defines no layer for — refuses rather than answering with an
unlabelled error, and names `verifier_error` where a layer would stand (the result text's first
word, `_meta["org.gleif.vlei/failure"].layer`; the reference gateway answers HTTP `503`). It is
local to that gateway and is not one of the eleven layers above: it says nothing about the
credential, the signature or the call, and the checks after the failure did not run. It is
retryable: a client **MAY** send the call again after a moment, re-signed — the nonce may already
have been claimed.

Naming the layer is a requirement, not a convenience: the skill's recovery behavior differs per
layer (retry, request a new credential, stop), and the demo depends on the layer being visible. The
reference implementation also puts the layer in `_meta["org.gleif.vlei/failure"]` for anything that
parses rather than reads, and the full check record in `_meta["org.gleif.vlei/report"]`.

**Order.** The reference implementation runs its checks in a fixed order and stops at the first
failure (`packages/mcp-vlei/src/mcp_vlei/report.py::CHECK_ORDER`, executed by
`extension.py::VleiIdentity._verify`). The report lists all eight, marking the ones after a failure
as not reached:

1. `credential_present` — a credential and a signature were presented → `missing_credential`; a
   signature of another format → `unsupported_version`; no `credentialSaid` →
   `missing_credential`; a stream that cannot be read, or a `credentialSaid` that is not in it →
   `chain_invalid`
2. `freshness` — `ts` and `exp` inside the window, and after the replay memory began →
   `stale_signature`
3. `digest` — signed for this server (`aud`) → `audience_mismatch`; the arguments match what was
   signed → `digest_mismatch`
4. `signature` — the statement verifies under the signer's current key state, read from a quorum of
   witnesses → `invalid_signature` (a malformed signature object too); the nonce claim follows it,
   and a replay is reported under `freshness` as `stale_signature`
5. `delegation` — the signer is the holder, or delegated by them → `invalid_signature`
6. `chain` — SAIDs, continuity, an accepted root, issuance, the vLEI shape, and the credential type
   the tool requires → `chain_invalid` / `unknown_root`
7. `revocation` — every link, from each issuer's live transaction event log (the default
   `revocation_source="tel"`) → `revoked` (`chain_invalid` when not established)
8. `authority` — role and scope → `role_mismatch` / `scope_exceeded`

Checks 1–3 need nothing but the request and the verifier's own configuration, so a stale,
misdirected or altered call is refused before any witness is asked.

Two checks read from a witness: `signature` (the signer's key event log) and `revocation` (each
issuer's transaction event log). Revocation is therefore neither the only remote check nor the last
one — `authority` follows it.

## Design Rationale

**Why `extensions` and `_meta` rather than new top-level fields.** Anything else requires a core
schema change and a version negotiation. The core already defines these fields as the extension
surface, and the `modelcontextprotocol/ext-auth` extensions establish the precedent.

**Why the server's credential is not in `Implementation._meta`.** It cannot be: `Implementation` has
no `_meta`. Hence two routes — the `_meta` of a `server/discover` result, and `/.well-known/vlei`.
The well-known route additionally lets a verifier check a server *before* connecting to it.

**Why the digest excludes `_meta`.** The signature lives in `_meta`; including it would be circular.
Excluding all of `_meta` rather than just the signature key keeps canonicalization simple and makes
the rule trivially auditable.

**Why a delegated AID rather than a credential for the agent.** The alternative — mint a credential
naming the agent — would require a credential type that does not exist and an issuance decision
nobody is positioned to make: no registrar validates software. Delegation reuses a mechanism KERI
already has, keeps the accountable party a person, and yields the two revocation switches described
above. See *Delegation* in the Specification.

**Why single-pass, with a client nonce.** A server-issued challenge per call would need the verifier
to hold state across two messages, which rules out a gateway that decides each request on its own —
the deployment shape that lets an institution adopt this without modifying its existing systems (see
`docs/GOVERNMENT.md`). A client nonce, claimed once, gives the same single use at gateway-compatible
cost; the window only bounds how long the claims are kept. The one challenge in the protocol is the
proof of possession, sent once per connection by the client, where a round trip costs nothing.

**Why the recipient twice.** The LE AID is the accountable party the client verified; the URL tells
apart two servers — or two routes of one gateway — that one legal entity operates. Either alone
leaves a replay open. Channel binding (RFC 9266) would be stronger, but TLS ends before the gateway's
authorizer, which never sees the exporter.

**Why a statement, canonicalised.** v0.2 joined three strings with newlines. A JSON statement under
RFC 8785 names each field, extends without ambiguity, and carries a format tag (`v`) that keeps a
proof of possession from passing as a request signature or the reverse.

## Backward Compatibility

- A client that does not declare the extension connects to an extension-aware server normally, sees
  all tools, and can call every tool that does not declare `org.gleif.vlei/requires`. A call to a
  tool that does declare it is answered `-32021`, naming the extension to declare — the "declare this
  and try again" of *Errors*, not a rejected credential. A client that declared the extension and
  then presents nothing is refused with the failure layer `missing_credential`.
- A server that does not declare the extension is connected to normally by an extension-aware
  client. If that client is configured with `verifyServer: true`, it reports that the server
  presented no identity and follows its configured policy (warn or stop).
- **v0.2 and v0.3 never accept each other's signatures.** A v0.3 verifier refuses a v0.2 signature
  as `unsupported_version`; a v0.2 verifier cannot verify a v0.3 one (the signed bytes differ) and
  refuses it as `invalid_signature`. A v0.3 client refuses a server that does not declare
  `vlei-sig/0.3` or offers no proof of possession, as `unsupported_version`, before presenting
  anything. There is no transitional mode in which either is accepted.
- Every field introduced here is ignorable. No message shape changes. No core type is redefined.

**Protocol negotiation decides whether the extension exists at all.** Extensions are active only at
protocol revision 2026-07-28. A client that completes only the legacy handshake negotiates an earlier
revision, and `capabilities.extensions` then comes back empty however the server is configured. In
the MCP Python SDK this is the difference between the high-level `Client`, which negotiates the
modern revision, and `ClientSession.initialize()` alone, which does not. A server that appears to
advertise nothing is, in our experience, usually a client that never got past the legacy handshake —
check the negotiated revision before concluding the server is misconfigured.

This is tested, not merely asserted, though not with a real host:
`examples/association-server/tests/test_acceptance.py::test_5_unmodified_client_is_additive` stands
in for an unmodified host with the MCP Python SDK's own `Client`, declaring no extensions. Against
the live reference server it connects, lists tools, successfully calls the public tool, and is
answered `-32021` on the protected one. Doing the same from Claude Desktop is a manual
procedure in `examples/README.md`, not part of any test.

## Reference Implementation

- `spec/schema.ts` — the type definitions, importable alongside the core schema.
- `spec/examples/` — wire-format examples for each message shape. In `tools-call-request.json` the
  digest is computed and the signature is real: it verifies against the test key of
  `digest-vectors.json`. The credential, its SAID and the delegated AID are illustrative — no key
  event log stands behind them, so a verifier refuses the request. The example shows the shape;
  the test key shows the arithmetic.
- `packages/mcp-vlei/` — Python implementation (`VleiIdentity` server extension, `VleiClient`;
  `audience.py`, `replay.py` and `pop.py` for v0.3's recipient, claims and proof of possession).
- `examples/regulator/vlei-pop/` — a gateway's public identity and its proof of possession, signed
  with `kli sign` in its own keystore by an AID its operator's LE delegated to.
- `examples/regulator/` — the labour-insurance case: a filing simulator with no vLEI code, behind a
  gateway that verifies.
- `examples/association-server/`, `examples/my-agent/` — the most basic end-to-end reference
  deployment.
- `skills/implementing-vlei/` — build-time guidance for implementing this specification.
- `skills/vlei-identity/` — runtime guidance for an agent using it.
- `examples/README.md` — the acceptance status of the reference deployment.
- `docs/CONFORMANCE.md` — every normative statement in this document, with the code that implements
  it and the test that holds it, including what is deliberately not claimed.

## Security Considerations

1. **This extension does not replace OAuth or TLS.** It adds a statement about the legal entity. A
   deployment that drops user authorization because it now has organizational identity has weakened
   itself.
2. **Verifiable is not trustworthy.** A validated ECR proves an entity asserted a role for a person.
   It says nothing about whether the request is a good idea. Authorization policy remains the
   deployment's responsibility.
3. **Replay.** A signature is bound to one recipient and used once: its nonce is claimed when it
   verifies, the claim outlives the window, and a verifier refuses what it could have accepted
   before its memory began. What remains: an on-path attacker at the same URL can delay a call it
   suppressed and deliver it once before `exp` — the call the client signed. TLS is the defence.
   A client's retry after a timeout is a new call; idempotency is the tool's to provide.
4. **Revocation latency.** Verification results are cached per `ttlMs`. A revocation takes effect no
   later than cache expiry. Deployments handling high-value actions SHOULD set `ttlMs` to zero for
   the tools concerned.
5. **Key custody.** A production deployment SHOULD use Signify so that private keys remain on the
   holder's device and the agent receives signatures rather than keys. The reference agent already
   works this way: it never holds a private key, and signs through `kli sign` against the KERI
   keystore (`examples/my-agent/kli_signer.py`, a `mcp_vlei.signing.CommandSigner`) — the Signify
   arrangement, reached through a local command instead of a KERIA agent. The package can also load
   a raw seed from a file (`Signer.from_key_store`), which puts the key in the agent's process; that
   path is not what the reference agent uses.
6. **Root of trust.** `acceptedRoots` is the whole of the trust decision. A verifier that accepts an
   arbitrary root accepts arbitrary identities. In production the root is GLEIF's; in this project's
   demo it is self-configured, and every artifact says so.
7. **Attestation trust transitivity.** Mode (b) makes the verifier trust the attesting party's
   judgment. An attestation MUST NOT be accepted from a party whose own identity has not been
   verified under mode (a), and a verifier SHOULD record which attesting party a decision rested on.
8. **Privacy.** Presenting an ECR discloses the entity, the role, the holder's AID and the
   person's `personLegalName` to the counterparty. This is intended — accountability is the point —
   but deployments should not present credentials to servers that do not require them, and nothing
   downstream of the verifier needs the credential: a gateway hands its backend the established
   facts, and its logs and reports carry identifiers, never the credential. ACDC graduated
   disclosure cannot yet withhold the name from the verifier itself.
9. **Proof of possession is not channel binding.** It shows who answers at a URL when challenged,
   not that nobody sits in front of it. Run the extension over TLS.
