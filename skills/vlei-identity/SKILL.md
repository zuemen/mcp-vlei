---
name: vlei-identity
description: Use when an MCP server declares the org.gleif.vlei/identity extension or a tool's _meta contains org.gleif.vlei/requires — tells the model which credential to present, what to verify before trusting a server, whether it is entitled to call a tool, and how to respond to each named failure layer.
---

# vLEI Identity for MCP

**Runtime skill.** For writing a server or client that implements the extension, see
`skills/implementing-vlei/` instead — that one is build time, and its output is code that will be
reviewed and then executed. This one is guidance to a running agent, which is a weaker guarantee,
so nothing here is load-bearing for security.

This skill teaches you the **rules** of the `org.gleif.vlei/identity` extension. It does not perform
cryptography — signing, chain validation, revocation checking and canonicalization are done by the
`mcp_vlei` package. Your job is to know what must be true at each stage, to refuse to proceed when
it is not, and to explain accurately why.

Normative text: `spec/SPEC.md`. Staged procedure: `workflow.md` in this directory.

**Background in one paragraph.** Every layer MCP verifies proves control of a domain (TLS, OAuth
`iss`, OAuth `client_id`) or the identity of a human user (OAuth `sub`). None proves which **legal
entity** is calling, and `clientInfo` is self-asserted and must never be used as a basis for trust.
This extension adds two things without changing core MCP: a server presents a **Legal Entity (LE)**
credential so you can verify who operates it, and you present an **Engagement Context Role (ECR)**
credential so the server can verify which entity you act for and in what role. OAuth still verifies
the user; vLEI verifies the organization. Neither replaces the other.

**One structural fact that shapes everything below.** ECR credentials are issued to natural persons
— the schema requires `personLegalName`. You do not have a credential of your own. You hold a
delegated AID under the credential holder's key event log, and you present *their* ECR. You are
acting on a person's authority, and saying so accurately is part of the job.

## When to use

A tool requires a credential if and only if its `_meta` contains `org.gleif.vlei/requires`. That
object names a credential type (`"ECR"`), optionally a `role`, and optionally a `scope`.

Tools without that key are public. Do not present credentials to servers that do not require them —
presenting an ECR discloses the entity, the role, and the holder's AID.

If the server returns JSON-RPC error `-32021`, the extension was not declared at `initialize`.
`data.requiredCapabilities` is a `ClientCapabilities` object naming what to declare —
`{"extensions": {"org.gleif.vlei/identity": {}}}`. That is a configuration
problem, not a rejected credential. Say so precisely, and reconnect with the capability declared.

## Before connecting

Obtain the server's LE credential from `server/discover`'s `_meta`, or from the `/.well-known/vlei`
URL given in its declared `discovery.wellKnown`. The package recomputes every SAID, walks the chain
to a root in your accepted list, and checks that each credential was issued by the identifier it
names — anchored in that issuer's key event log, carried in the stream. With a witness configured,
`VleiClient.connect` also reads every link's transaction event log, and refuses a withdrawn
credential — or, by default, one whose logs it cannot read. A client constructed with
`on_unchecked_revocation="warn"` connects anyway and says so (`revocation_checked=False`): describe
such a server as verified except for revocation; never say its revocation was checked.

- **Verification passes** → continue.
- **Verification fails** → tell the user the **failure layer by name** and **stop**. Do not call any
  tool on that server, including public ones. An organization that cannot prove it is who it claims
  is not one to send a member's email address to.
- **The server presents nothing** → it is unverified, not untrusted. Report that it presented no
  organizational identity and follow the configured policy. Never describe an unverified server as
  verified.

## Before calling a tool

Read `org.gleif.vlei/requires` on the tool you intend to use and compare it against the credential
you hold:

- Does the ECR's role satisfy the tool's `role`?
- Does the credential's scope cover the tool's declared `scope` for these arguments?

**If it does not, do not make the call.** Tell the user which role or scope is required, which one
you hold, and that a new ECR must be issued by their legal entity. A refusal you can explain in
advance is more useful than a server-side rejection, it saves the counterparty the verification
work, and it keeps a foreseeable failure out of their audit log.

## When a call is rejected

A rejection arrives as a tool result with `isError: true` whose text names the layer (the same layer
is in `_meta["org.gleif.vlei/failure"]`). Each layer has one correct response. They are listed in the
order the server checks: what the request alone settles, then the signer's key state, then the
chain, then revocation, then role and scope.

| Layer | What it means | What you do |
|---|---|---|
| `missing_credential` | The tool requires a credential and the call carried none, or no signature. Not a verdict on any credential | If the credential you hold covers the tool (see *Before calling a tool*), make the call with it presented — the package presents once it has read the tool's requirement from `tools/list`. Otherwise tell the user the tool needs an ECR you do not hold. Never describe this as your credential being rejected. |
| `stale_signature` | Timestamp outside the freshness window, or a replay | Re-sign and retry **once**. If it fails again, tell the user to check the system clock, and stop. |
| `digest_mismatch` | Arguments do not match the signed digest | Stop. The request was altered in transit. Report it as an integrity problem, not a retryable error. |
| `invalid_signature` | One of three things, all about **who signed**: the signature does not verify under the signing AID's current key state, which the server reads from that AID's key event log at a witness (a key sent along with the request is ignored); the server could not establish that key state at all; or the AID that signed is neither the credential's holder nor delegated by the holder in the holder's key event log | Stop. **Do not retry**, and never re-sign with a different key or present the credential under another AID to get past it — that is exactly what this layer refuses. Report which of the three the message names: a key-state problem (a rotated key, a log the witness could not serve) or an authorization problem (this agent is not the holder's delegate). Both are for the holder or operator to fix. |
| `chain_invalid` | The presented credential or its chain does not validate — a SAID that does not recompute, a broken link, an issuance not anchored in its issuer's key event log, a chain without the vLEI shape, a credential of a type other than the one the tool requires — **or** revocation could not be established, because an issuer's live transaction event log could not be read or records no issuance | Stop. **Do not retry.** Report a credential-configuration problem. When the message says revocation was not established, say exactly that — neither "revoked" nor "valid". |
| `unknown_root` | The chain terminates at a root the counterparty does not accept | Stop. Report which root you chain to and that they do not accept it. This is a trust-configuration mismatch between two organizations; only they can resolve it. |
| `revoked` | A credential in the chain has been revoked | Stop. Tell the user a new credential must be issued by their entity. **Do not retry with a different credential.** |
| `role_mismatch` | The ECR role does not satisfy the tool's requirement | Stop. Name the required role and the one you hold. |
| `scope_exceeded` | The request exceeds the tool's declared scope | Stop. State the limit and the requested value. You may offer to retry within the limit — ask first. |

Retrying a request is correct for exactly one layer: `stale_signature`, once. Presenting a credential
after `missing_credential` is not a retry — it is the first presentation.

**Attestations.** A result may carry `org.gleif.vlei/attestation` — a signed statement by one party
that it verified another. Accept it only after the package has verified the **attesting party's
own** signature and credential chain. When you rely on one, say whose attestation you relied on: the
user is trusting that party's judgment, not a credential you checked yourself.

## Never do

- **Never swap, re-issue, or select a different credential to get past a rejection.** If the
  credential you hold does not entitle you to the call, the answer is that you are not entitled.
- **Never call a tool on a server whose identity verification failed**, including a public tool.
- **Never put a private key, a credential, or any part of either into a tool's arguments.** They
  belong in `_meta`, which the package populates. Arguments are application data and may be logged,
  echoed, or forwarded.
- **Never treat `clientInfo`, `serverInfo`, a server's name, or its domain as evidence of who
  operates it.** They are not, and the specification says so.
- **Never present a credential to a server that does not require one.**
- **Never report a verification as passing when it was skipped, cached past its TTL, or
  unavailable.** "Unverified" and "verified" are different words, and the distinction is the entire
  point.

## Vocabulary

- **Host** = the AI application. **Client** = the connection component inside the host.
  **Server** = the tool provider.
- **LE** = Legal Entity credential, identifying an organization by LEI. **ECR** = Engagement Context
  Role credential, identifying a person's role within it. ECR, not OOR: an agent's mandate is an
  engagement context, not a public office.
- OAuth verifies the **user** and the **client software** — not the agent, and not the legal entity.
