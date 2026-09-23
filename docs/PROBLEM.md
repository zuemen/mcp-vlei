# Problem Statement: The Organizational-Identity Applicability Boundary in MCP

**Status:** Informational · **Target spec revision:** MCP 2026-07-28 · **Repo:** `mcp-vlei`

This document describes an *applicability boundary* of the Model Context Protocol (MCP), not a
vulnerability. MCP does what it was designed to do. The boundary is that its trust model was
designed for a human-in-the-loop deployment, and it is being carried into deployments where the
caller is an autonomous agent acting on behalf of a legal entity. Nothing below implies an
implementation defect in MCP, in any SDK, or in any host application.

## 1. Every verified layer in MCP verifies domain control, not legal identity

MCP inherits a well-specified authentication stack. Each layer answers a real question, and none of
them answers *"which legal entity is this?"*

| Layer | What it proves | What it does not prove |
|---|---|---|
| TLS | Control of a DNS name | Who the operator is as a legal person |
| OAuth `iss` | That the authorization server is the expected one. The comparison is a MUST, and normalization is forbidden — no case folding, no omitting a default port, no adding or removing a trailing slash | Anything about the calling software's operator |
| OAuth `client_id` (client-ID metadata documents, CIMD) | Control of the URL that serves the client metadata | That the URL's controller is an identifiable, accountable organization |
| OAuth `sub` | The identity of the **human user** at that authorization server | Which agent inside the client software is acting, or under what mandate |
| `clientInfo` / `serverInfo` | Nothing — it is self-asserted; the specification states it MUST NOT be used to change behavior or make security decisions | Everything |

The composite result is a chain of domain-control proofs plus one human-user proof. An
organizational identity — *this call is made by a legal entity with a known registration, under a
named role, with a revocable authorization* — is not expressible anywhere in the stack.

### Two formulations that must be stated precisely

Two loose paraphrases circulate, and both are wrong in ways that a GLEIF or AAIF audience will
notice:

- **Not:** "OAuth only recognizes Claude Desktop." **Correct:** OAuth verifies the **end user**
  (`sub`) and the **client software** (`client_id`). It does not verify *which agent inside that
  client* is acting, and it does not bind either the user or the client to a legal entity.
- **Not:** "The specification tells both sides not to trust each other." **Correct:** The
  specification says `clientInfo` / `serverInfo` are self-asserted and MUST NOT be used as a basis
  for trust or security decisions. The other layers — TLS, OAuth — do provide verification. This is
  a scoping statement about one field, not a zero-trust posture.

## 2. The agent is absent from the protocol

The normative schema (`schema/2026-07-28/schema.ts`, 3197 lines) contains **zero** whole-word
occurrences of `agent`, `principal`, `delegation`, or `mandate`. The protocol models a *host*, a
*client*, and a
*server*. The entity that actually decides to invoke a tool — the agent — has no representation, and
therefore no way to be named, delegated to, constrained, or revoked at the protocol layer.

## 3. The `Implementation` type has no `_meta`

`Tool`, `Resource`, and `Prompt` all carry `_meta`, so out-of-band data can be attached to them
through the standard extension mechanism. `Implementation` — the type of `clientInfo` and
`serverInfo`, which describes the two *parties* in `initialize` — does not. Consequently there is no
schema-level location to attach a credential to a party, which is precisely where an organizational
identity would belong. This is the narrow structural gap that motivates the extension in `spec/`.

## 4. The trust premise is the human in the loop

The premise is not implicit. It is stated in the warning box of the **Tools** chapter of the
specification: there should always be a human in the loop with the ability to deny a tool
invocation.

Under that premise, self-asserted metadata is harmless, because a person is the accountable party
at the point of action. When an agent executes autonomously — scheduled, chained, or acting across
organizational boundaries — the premise does not hold, and the layer that was carrying
accountability is simply not present.

## 5. A measurement at the protocol layer

To test whether the gap is structural rather than a matter of implementation quality, we ran the
official **`mcp` Python SDK 2.2.0** over the **STDIO** transport, with a server policy of:

> if `clientInfo.name` contains `"Claude"`, grant the partner tier of 100 hours; otherwise grant 1
> hour.

This policy **deliberately violates the specification's SHOULD NOT**. The point of the experiment is
not that the policy is unwise — the specification already says so — but that the protocol layer
offers no means to detect or prevent it.

The same client binary was run three times. The only difference was the `client_info` argument:

| Run | `client_info` | Approved |
|---|---|---|
| 1 | honest self-description | 1 hour |
| 2 | impersonating Claude Desktop, including the description and URL | 50 hours |
| 3 | omitted — the SDK fills in `mcp 0.1.0` automatically | 1 hour |

Run 3 is worth noting on its own: when the field is omitted, the SDK supplies a default rather than
leaving it empty, so "nothing was claimed" and "something was claimed" are indistinguishable at the
receiving end.

No layer of the stack observed a difference between the three runs, because there was no verifiable
statement to compare against. A well-behaved server avoids this policy. A well-behaved server still
has nothing to put in its place when the question is *"is this caller an accountable
organization?"*

## 6. External corroboration

- **NSA, May 2026** — cybersecurity information sheet on MCP security. It notes that MCP does not
  define how a session maps to a verifiable identity, that authentication is optional, and that
  role-based permissions are not part of the protocol.
- **MCP Security Interest Group, `server-identity` proposals** — SEP-1289, issue #1959, issue #3354.
  Every candidate published to date roots trust in a domain name, DNS, or a registry operator. These
  are coherent answers to *"which deployment is this?"*; none is an answer to *"which legal entity
  is this?"*, and none is revocable by an authority that the counterparty's regulator also
  recognizes.

## 7. What follows

The gap is addressable **additively**. MCP already defines `extensions` and `_meta` for exactly this
purpose. GLEIF's vLEI already supplies the missing pieces — a Legal Entity credential, an Engagement
Context Role credential, a revocation mechanism, and offline verifiability. This project binds the
two: an extension (`org.gleif.vlei/identity`), a skill and workflow so a model knows what to present
and what to check at each stage, and a reference implementation. The MCP core schema is not modified.

---

## 30-second spoken version

> Every layer MCP authenticates — TLS, OAuth issuer, client ID, user subject — proves control of a
> domain or the identity of a human user. None of them proves which legal entity is calling.
>
> The word "agent" does not appear once in MCP's 3,197-line schema, so the entity that actually
> invokes the tool cannot be named, constrained, or revoked at the protocol layer.
>
> That was fine while a human approved every action. Once agents act autonomously across
> organizations, the accountable party has to be verifiable in the call itself — which is exactly
> what vLEI already provides, and what we attach through MCP's own extension mechanism.
