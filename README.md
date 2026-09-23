# mcp-vlei

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
| `skills/vlei-identity/` | Skill and staged workflow so a model uses the extension correctly |
| `scripts/` | One-command credential environment bootstrap |
| `packages/mcp-vlei/` | Python implementation (`VleiIdentity` server extension, `VleiClient`) |
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
| 0 — Problem statement | done |
| 1 — Schema extension | done |
| 2 — Skill and workflow | done |
| 3 — Credential environment | not started |
| 4 — Python package | not started |
| 5 — Reference implementation | not started |
| 6A — Government adoption path | not started |
| 6B — Government gateway | optional |
| 7 — Talk and recording | not started |

## Honesty statement

Real KERI, real ACDC, real verifier. The root of trust is self-configured; in production it would be
GLEIF's.
