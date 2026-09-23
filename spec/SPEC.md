# vLEI Identity Extension for MCP

**Extension identifier:** `org.gleif.vlei/identity`
**Base specification:** MCP 2026-07-28
**Status:** v0.2 — validated against a reference implementation; field details may still change
**Repo:** `mcp-vlei`

This extension adds verifiable **organizational** identity and **role-scoped** authorization to MCP
using GLEIF's vLEI ecosystem (KERI AIDs, ACDC credentials, LE and ECR credential types). It does not
modify `modelcontextprotocol/modelcontextprotocol`'s `schema.ts`. It defines new types that travel in
the fields the core specification already reserves for this purpose: `Implementation.extensions`,
`RequestMetaObject`, `ResultMetaObject`, and `Tool._meta`.

The extension identifier follows the core naming rules: a reverse-DNS prefix whose second label is
`gleif`, which is outside the reserved `modelcontextprotocol` / `mcp` range.

## Motivation

`docs/PROBLEM.md` states the boundary in full. In brief:

- Every verified layer in MCP proves **domain control** (TLS, OAuth `iss`, OAuth `client_id`) or the
  identity of a **human user** (OAuth `sub`). No layer expresses a legal entity.
- `clientInfo` / `serverInfo` are self-asserted and the specification states they MUST NOT be used
  for behavior changes or security decisions — correctly, since nothing backs them.
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

### Capability declaration

A party declares participation in `Implementation.extensions` under the key
`org.gleif.vlei/identity`, with a `VleiIdentityCapability` value (see `schema.ts`):

- `presents` — which credential types this party is able to present (`"LE"`, `"ECR"`).
- `requires` — the credential type this party requires of its counterparty.
- `acceptedRoots` — AIDs of roots of trust this party will accept. In production this is GLEIF's
  root; in this project's demo environment it is a self-configured root (see the honesty statement in
  `docs/DEMO.md`).
- `signatureAlgs` — currently `["Ed25519"]`.
- `discovery.wellKnown` — the URL at which this party publishes its credential for **passive
  verification** (mode (a) below).

### Two verification modes

Both modes are normative; an implementation MUST support (a) and SHOULD support (b).

**(a) Passive verification from a public location.** The presenting party publishes its credential
somewhere the verifier can fetch it without the presenter doing anything per-request: the `_meta` of
a `server/discover` result, or a `/.well-known/vlei` document at `discovery.wellKnown`. The verifier
fetches it, walks the chain to an accepted root, checks revocation, and decides on its own. The
presenter performs no per-verification work. This is the default for server → client identity.

**(b) Attested confirmation ("来函確認" / letter of confirmation).** The verifier asks a party that
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

`delegatedAid` is nonetheless **optional** in the schema. A deployment that cannot support delegated
inception may sign directly with the ECR holder's AID; it keeps every other property and loses only
the second switch.

### Request signing: single-pass design

A signature is computed over exactly three pieces of data, joined by newlines:

```
method + "\n" + ts + "\n" + digest
```

- `method` — the JSON-RPC method, e.g. `tools/call`.
- `ts` — RFC 3339 timestamp, UTC, at signing time.
- `digest` — `base64url(sha256(canonical))`, where `canonical` is the RFC 8785 (JCS) canonical
  serialization of the request `params` **with `_meta` removed**.

`_meta` is excluded because it carries the signature itself. The resulting `VleiSignature` goes in
`params._meta["org.gleif.vlei/signature"]`.

This is a **single-pass** design on purpose: a gateway or interceptor sees the method, the
credential, the delegated AID, and the signature in one message, and can decide to allow or deny
without a challenge/response round trip. There is no nonce exchange. Replay is bounded instead by:

- **Freshness** — a verifier MUST reject a signature whose `ts` is outside its freshness window
  (default 60 seconds, configurable).
- **Replay cache** — a verifier MUST cache `(aid, digest, ts)` for at least the freshness window and
  reject repeats.

### Tool-level requirements

A tool declares what it demands of a caller in its own `_meta`, under
`org.gleif.vlei/requires`: a credential type, an optional role string drawn from the entity's ECR
vocabulary, and an optional `scope` object of arbitrary constraints (`{"maxAmount": 1000000}`). This
places the permission **in the schema the client already reads**, so an agent can determine before
calling whether it is entitled to call — which is the precondition for the skill in
`skills/vlei-identity/`.

Scope semantics are deliberately open: a verifier compares the tool's declared `scope` against the
scope carried by the caller's ECR credential, using a comparison the deployment defines. The
extension specifies *where* scope lives and *that* it must be checked, not a universal scope algebra.

### Errors

**Protocol-level.** If a server requires the extension and the client did not declare it, the server
responds with JSON-RPC error `-32021`. `data.requiredCapabilities` is a **`ClientCapabilities`
object** — `{"extensions": {"org.gleif.vlei/identity": {}}}` — not a list of identifiers: the same
shape the client sends at `initialize`, so the answer reads as "declare this and try again" rather
than needing translation. This lets a client distinguish "I am missing a capability" from "my
credential was rejected".

**Tool-level.** A verification failure that occurs after the capability is present is returned as a
tool result with `isError: true`, and the text MUST name the failure layer using one of:

| Code | Meaning |
|---|---|
| `invalid_signature` | Signature does not verify under the presented AID's current key state |
| `stale_signature` | `ts` outside the freshness window, or a replay |
| `digest_mismatch` | `params` do not match the signed digest — arguments were altered after signing |
| `chain_invalid` | Credential chain does not validate (LE → ECR linkage, schema, or KEL) |
| `revoked` | A credential in the chain is revoked |
| `role_mismatch` | Presented ECR role does not satisfy the tool's declared `role` |
| `scope_exceeded` | Request exceeds the tool's declared `scope` |
| `unknown_root` | Chain terminates at a root not in `acceptedRoots` |

Naming the layer is a requirement, not a convenience: the skill's recovery behavior differs per
layer (retry, request a new credential, stop), and the demo depends on the layer being visible.

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

**Why single-pass.** Challenge/response would be stronger against replay but requires the verifier to
hold state across two messages, which rules out stateless gateway deployment — the deployment shape
that lets an institution adopt this without modifying its existing systems (see `docs/GOVERNMENT.md`).
Freshness plus a replay cache buys the same property at gateway-compatible cost.

## Backward Compatibility

- A client that does not declare the extension connects to an extension-aware server normally, sees
  all tools, and can call every tool that does not declare `org.gleif.vlei/requires`. Calls to tools
  that do declare it are refused with a named failure layer.
- A server that does not declare the extension is connected to normally by an extension-aware
  client. If that client is configured with `verifyServer: true`, it reports that the server
  presented no identity and follows its configured policy (warn or stop).
- Every field introduced here is ignorable. No message shape changes. No core type is redefined.

**Protocol negotiation decides whether the extension exists at all.** Extensions are active only at
protocol revision 2026-07-28. A client that completes only the legacy handshake negotiates an earlier
revision, and `capabilities.extensions` then comes back empty however the server is configured. In
the MCP Python SDK this is the difference between the high-level `Client`, which negotiates the
modern revision, and `ClientSession.initialize()` alone, which does not. A server that appears to
advertise nothing is, in our experience, usually a client that never got past the legacy handshake —
check the negotiated revision before concluding the server is misconfigured.

This is demonstrated, not merely asserted: `examples/` includes a test in which Claude Desktop — an
unmodified host — connects to the reference server, lists tools, successfully calls the public tool,
and is refused on the protected one.

## Reference Implementation

- `spec/schema.ts` — the type definitions, importable alongside the core schema.
- `spec/examples/` — wire-format examples for each message shape.
- `packages/mcp-vlei/` — Python implementation (`VleiIdentity` server extension, `VleiClient`).
- `examples/association-server/`, `examples/my-agent/` — end-to-end reference deployment.
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
3. **Replay.** Bounded by freshness window plus replay cache, not by a nonce. Deployments with a
   stricter threat model SHOULD shorten the window and MAY layer a challenge on top; the extension
   does not forbid it.
4. **Revocation latency.** Verification results are cached per `ttlMs`. A revocation takes effect no
   later than cache expiry. Deployments handling high-value actions SHOULD set `ttlMs` to zero for
   the tools concerned.
5. **Key custody.** The reference agent holds a delegated AID's private key on disk for
   demonstrability. A production deployment SHOULD use Signify so that private keys remain on the
   holder's device and the agent receives signatures rather than keys.
6. **Root of trust.** `acceptedRoots` is the whole of the trust decision. A verifier that accepts an
   arbitrary root accepts arbitrary identities. In production the root is GLEIF's; in this project's
   demo it is self-configured, and every artifact says so.
7. **Attestation trust transitivity.** Mode (b) makes the verifier trust the attesting party's
   judgment. An attestation MUST NOT be accepted from a party whose own identity has not been
   verified under mode (a), and a verifier SHOULD record which attesting party a decision rested on.
8. **Privacy.** Presenting an ECR discloses the entity, the role, and the holder's AID to the
   counterparty. This is intended — accountability is the point — but deployments should not present
   credentials to servers that do not require them.
