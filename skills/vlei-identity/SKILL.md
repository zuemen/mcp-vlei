---
name: vlei-identity
description: Use when connecting to or calling an MCP server that declares the org.gleif.vlei/identity extension, or when a tool's _meta contains org.gleif.vlei/requires. Tells the model which credential to present at each stage, what to verify before trusting a server, how to decide in advance whether it is entitled to call a tool, and how to respond to each named verification failure layer.
---

# vLEI Identity for MCP

This skill teaches you the **rules** of the `org.gleif.vlei/identity` extension. It does not perform
cryptography. Signing, chain validation, revocation checking, and canonicalization are done by the
`mcp_vlei` package. Your job is to know what must be true at each stage, to refuse to proceed when it
is not, and to explain accurately to the user why.

The full normative text is `spec/SPEC.md`. The staged procedure is `workflow.md` in this directory —
follow it for any session with a vLEI-aware server.

## Background in one paragraph

Every layer MCP verifies proves control of a domain (TLS, OAuth `iss`, OAuth `client_id`) or the
identity of a human user (OAuth `sub`). None of them proves which **legal entity** is calling, and
`clientInfo` is self-asserted and must never be used as a basis for trust. This extension adds two
things on top, without changing core MCP: a server presents a **Legal Entity (LE)** credential so you
can verify who operates it, and you present an **Engagement Context Role (ECR)** credential so the
server can verify which entity you act for and in what role. OAuth still verifies the user; vLEI
verifies the organization. Neither replaces the other.

## 1. Know when a credential is needed

A tool requires a credential if and only if its `_meta` contains `org.gleif.vlei/requires`. That
object names a credential type (`"ECR"`), optionally a `role`, and optionally a `scope`.

Tools without that key are public. Do not present credentials to servers that do not require them —
presenting an ECR discloses the entity, the role, and the holder's AID.

If the server returns JSON-RPC error `-32021` with `data.requiredCapabilities` containing
`"org.gleif.vlei/identity"`, the problem is that the extension was not declared at `initialize` — not
that a credential was rejected. Say so precisely; it is a configuration problem, not an authorization
one.

## 2. Before connecting: verify the server

Obtain the server's LE credential from `server/discover`'s `_meta`, or from the `/.well-known/vlei`
URL given in its declared `discovery.wellKnown`. The package validates the chain, the revocation
status, and that the chain terminates at an accepted root.

- **Verification passes** → continue.
- **Verification fails** → tell the user the **failure layer by name** and **stop**. Do not call any
  tool on a server whose identity failed verification, including public tools.
- **The server presents nothing** → it is unverified, not untrusted. Report that it presented no
  organizational identity and follow the configured policy. Never describe an unverified server as
  verified.

## 3. Before calling: check your own entitlement

Read `org.gleif.vlei/requires` on the tool you intend to use and compare it against your own
credential:

- Does your ECR's role satisfy the tool's `role`?
- Does your credential's scope cover the tool's declared `scope` for these arguments?

**If it does not, do not make the call.** Tell the user which role or scope is required, which one you
hold, and who in their organization issues it. A refusal you can explain in advance is more useful
than a server-side rejection, and a call you know will fail wastes the counterparty's verification
work and appears in their audit log as a failed attempt.

## 4. Responding to each failure layer

A rejection arrives as a tool result with `isError: true` whose text names the layer. Each layer has
one correct response:

| Layer | What it means | What you do |
|---|---|---|
| `revoked` | A credential in the chain has been revoked | Stop. Tell the user the credential was revoked and that a new one must be issued by their entity. Do not retry. |
| `role_mismatch` | Your ECR role does not satisfy the tool's requirement | Stop. Name the required role and the role you hold. Do not retry. |
| `scope_exceeded` | The request exceeds the tool's declared scope | Stop. State the limit and the requested value. You may offer to retry with arguments inside the limit — ask first. |
| `stale_signature` | Timestamp outside the freshness window, or a replay | Re-sign and retry **once**. If it fails again, report a clock-skew or replay-cache problem and stop. |
| `digest_mismatch` | Arguments do not match the signed digest | Stop and report it. This means the request was altered after signing — treat it as a integrity problem, not a retryable error. |
| `invalid_signature` | Signature does not verify under the AID's key state | Stop. Report a key-state or configuration problem. Do not retry. |
| `chain_invalid` | Credential chain does not validate | Stop. Report it as a credential-configuration problem. Do not retry. |
| `unknown_root` | Chain terminates at a root the counterparty does not accept | Stop. Report which root you chain to and that the counterparty does not accept it. This is a trust-configuration mismatch between two organizations, and only they can resolve it. |

Retrying is correct for exactly one layer: `stale_signature`, once.

## 5. Attestations (mode (b), "letter of confirmation")

A result may carry `org.gleif.vlei/attestation` — a signed statement by one party that it verified
another. Accept it only after the package has verified the **attesting party's own** signature and
identity. When you rely on an attestation, say whose attestation you relied on; the user is trusting
that party's judgment, not a credential you checked yourself.

## 6. Never do these

- Never swap, re-issue, or select a different credential in order to get past a rejection. If the
  credential you hold does not entitle you to the call, the answer is that you are not entitled.
- Never call a tool on a server whose identity verification failed.
- Never describe `clientInfo`, `serverInfo`, a server's name, or its domain as evidence of who
  operates it. They are not, and the specification says so.
- Never present a credential to a server that does not require one.
- Never report a verification as passing when it was skipped, cached past its TTL, or unavailable.
  "Unverified" and "verified" are different words and the distinction is the entire point.

## Vocabulary

Use these terms exactly, including when explaining to users:

- **Host** = the AI application. **Client** = the connection component inside the host.
  **Server** = the tool provider.
- **LE** = Legal Entity credential, identifies an organization by LEI.
  **ECR** = Engagement Context Role credential, identifies a person's role within that organization.
  ECR, not OOR: agent mandates are engagement contexts, not public offices.
- OAuth verifies the **user** and the **client software** — not the agent, and not the legal entity.
