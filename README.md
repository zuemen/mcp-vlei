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
| 0 — Problem statement | `docs/PROBLEM.md` |
| 1 — Schema extension | `spec/` |
| 2 — Skill and workflow | `skills/vlei-identity/` |
| 3 — Credential environment | `scripts/` — **all six acceptance checks pass** |
| 4 — Python package | `packages/mcp-vlei/` — 44 tests passing |
| 5 — Reference implementation | `examples/association-server/`, `examples/my-agent/` |
| 6A — Government adoption path | `docs/GOVERNMENT.md` |
| 6B — Government gateway | `examples/regulator/`, `deploy/agentgateway/` |
| 7 — Talk and recording | `docs/DEMO.md` |

`scripts/bootstrap-credentials.sh` now runs end to end against live containers: it issues the
chain, installs the self-configured root, presents the ECR credential to GLEIF's verifier (202),
reads back the LEI and role (200), revokes, and confirms the revocation is honoured (401).

The remaining gap is the reference implementations in `examples/`: they have credentials to use
now, but have not yet been run against the official MCP SDK, so their server and client API calls
are written from the SEP-2133 description rather than verified. That is the next step.

## Honesty statement

Real KERI, real ACDC, real verifier. The root of trust is self-configured; in production it would be
GLEIF's.
