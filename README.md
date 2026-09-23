# mcp-vlei

[![tests](https://github.com/zuemen/mcp-vlei/actions/workflows/test.yml/badge.svg)](https://github.com/zuemen/mcp-vlei/actions/workflows/test.yml)

**Reference design · v0.2 · root of trust self-configured**

Verifiable **organizational** identity for the Model Context Protocol, using GLEIF's vLEI ecosystem.

MCP authenticates domains (TLS, OAuth `iss`, OAuth `client_id`) and human users (OAuth `sub`). No
layer expresses a legal entity, and `clientInfo` is self-asserted and must not be used for trust
decisions. When an agent acts autonomously across organizational boundaries, the accountable party
is not verifiable in the call. This project closes that gap **additively**, through MCP's own
extension mechanism. The MCP core schema is not modified.

**Extension identifier:** `org.gleif.vlei/identity`

## Layout

| Path | Contents |
|---|---|
| `docs/PROBLEM.md` | Problem statement — the applicability boundary, with measurements and corroboration |
| `docs/GOVERNMENT.md` | Adoption path for public-sector institutions |
| `docs/DEMO.md` | Recording script and talk materials |
| `spec/SPEC.md` | The extension specification |
| `spec/schema.ts` | Type definitions — additive, nothing in core MCP redefined |
| `spec/examples/` | Wire-format examples |
| `skills/implementing-vlei/` | **Build time** — how to implement the extension correctly. Output is code: reviewed once, then executed every time |
| `skills/vlei-identity/` | **Runtime** — how a running agent presents credentials and reads a refusal. Output is behaviour: guidance, not a guarantee |
| `docs/CONFORMANCE.md` | Every normative statement in the spec, with its implementation and its test |
| `docs/upstream/` | A defect found in `vlei-verifier` while building this, written up for GLEIF |
| `scripts/` | One-command credential environment bootstrap |
| `packages/mcp-vlei/` | Python implementation (`VleiIdentity` server extension, `VleiClient`) |
| `examples/impersonation/` | The problem, made executable: quota granted on a name the caller chose |
| `examples/console/` | The Trust Console — the interface the recording is shot on |
| `examples/` | Reference server, reference agent, regulator scenario |
| `deploy/agentgateway/` | Gateway configuration for zero-code-change adoption |

## What it adds

- A server presents a **Legal Entity (LE)** credential; a client verifies it before calling anything.
- An agent presents an **Engagement Context Role (ECR)** credential plus a delegated AID and a
  single-pass signature over the request.
- A tool declares its permission requirement in `Tool._meta` (`org.gleif.vlei/requires`), so an agent
  can determine **before calling** whether it is entitled to call.
- Two verification modes: passive verification from a public location, and signed attestation between
  institutions.
- Failures name their layer (`revoked`, `role_mismatch`, `digest_mismatch`, …), because the correct
  recovery differs per layer.

## Status

| Task | State |
|---|---|
| 0 — Problem statement | `docs/PROBLEM.md` |
| 1 — Schema extension | `spec/` |
| 2 — Skill and workflow | `skills/vlei-identity/` |
| 3 — Credential environment | `scripts/` — **all six acceptance checks pass** |
| 4 — Python package | `packages/mcp-vlei/` — 67 tests, against the real SDK types |
| 5 — Reference implementation | runs on SDK 2.2.0 at protocol 2026-07-28; acceptance tests green — see `examples/README.md` |
| 6A — Government adoption path | `docs/GOVERNMENT.md` |
| 6B — Government gateway | `examples/regulator/`, `deploy/agentgateway/` |
| 7 — Talk and recording | `docs/DEMO.md` |

`scripts/bootstrap-credentials.sh` now runs end to end against live containers: it issues the
chain, installs the self-configured root, presents the ECR credential to GLEIF's verifier (202),
reads back the LEI and role (200), revokes, and confirms the revocation is honoured (401).

The reference implementations run against the official SDK: the server registers its tools with
their `_meta` requirements, advertises `org.gleif.vlei/identity` at protocol 2026-07-28, verifies a
counterparty's credential locally, reads revocation from the issuer's transaction event log, and
refuses a protected tool to an unmodified client with a named failure layer.

A defect in `vlei-verifier` 1.0.0 that used to block half the acceptance suite is now off the
critical path — three selectable revocation sources, local checks before the remote one — and
written up for upstream in `docs/upstream/`. `examples/README.md` has the detail.

## Honesty statement

Real KERI, real ACDC, real verifier. The root of trust is self-configured; in production it would be
GLEIF's.
