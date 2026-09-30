# Reference implementations

## The main case: labour-insurance filing (`regulator/`)

The government scenario, and the one the demonstration records. An employer's agent files
labour-insurance enrolments with a filing simulator — *simulated, not connected to the Bureau of
Labor Insurance*. The simulator does **no** vLEI verification at all. It sits behind a gateway
(`deploy/agentgateway/`) whose external-authorisation service, `regulator/vlei-authz/`, verifies the
agent's ECR and its signed request, and passes the simulator only the verified employer.

| Scene | What the agent does | Outcome |
|---|---|---|
| 1 | Enrols an employee on the start date (`enroll_employee`) | allowed |
| 2 | The same agent adjusts an insured salary (`adjust_insured_salary`) — a role its ECR does not carry | refused · `role_mismatch` |
| 3 | Enrols an employee fifteen days ahead — the tool allows today to ten days ahead (`dateWithinDays: [0, 10]`) | refused · `scope_exceeded` |
| 4 | The employer revokes the handler's ECR; the agent files again | refused · `revoked` |

Where it is tested:

- `regulator/tests/` — 43 tests, no containers: the authoriser (`test_vlei_authz.py`), the
  simulator (`test_labor_insurance_sim.py`) and the client that calls through the gateway
  (`test_gateway_client.py`).
- The four scenes as the console runs them: `console/tests/` (below).
- Against the live stack: `scripts/record-check.sh` checks every precondition, and
  `scripts/rehearse.py` drives scenes 1–4 in a real browser and checks that each ends as it should.
- On the wire: the tool's definition is `spec/examples/tool-with-requirement.json`, and a signed call
  of it is `spec/examples/tools-call-request.json`.

## The most basic reference implementation (`association-server/`)

The smallest complete deployment, without a gateway: the association's own MCP server presents its
LE, requires an ECR for `register_member`, and shows every decision on a live dashboard. It is where
the extension was first built end to end; *Running the whole thing* and *Status* below are about it.

## Everything else

The same agent is used throughout; its source does not change between deployments.

| Directory | What it is |
|---|---|
| `my-agent/` | An agent that presents a vLEI credential — Claude as the model, official MCP client, `VleiClient` for identity, and the skill loaded as its system prompt |
| `console/` | The Trust Console the recording is shot on. Every scene makes its real call — scenes 1–4 through the gateway to the simulator; `console/tests/` — 28 tests |
| `skill-server/` | A server written from `skills/implementing-vlei/SKILL.md` alone, with no stubs; what it found is in `skill-server/REPORT.md`. `skill-server/tests/` — 31 tests |
| `impersonation/` | The problem, made executable: a vendor server granting quota on a name the caller chose |
| `observatory/` | The same measurement off the laptop: a read-only MCP server that records what it receives about the client, so a real client (the claude.ai connector) and a replay of its `clientInfo` can be compared side by side at `/observatory`. `observatory/tests/` — 39 tests |

## Running the whole thing

```bash
# 1. Credential environment — real KERI, real ACDC, real verifier, self-configured root.
#    If Windows has reserved 5642-5644, set the witness host ports in scripts/.env first
#    (VLEI_WITNESS_HOST_PORT_WAN/WIL/WES and VLEI_WITNESS_URL); everything here reads it.
bash scripts/bootstrap-credentials.sh

# 2. The association's server (terminal 2)
pip install -e packages/mcp-vlei
python examples/association-server/server.py
#    dashboard: http://localhost:8080/dashboard/

# 3. The agent (terminal 3)
export ANTHROPIC_API_KEY=...
python examples/my-agent/agent.py "register Chen Wei-Ting, weiting@example.org"

# 4. Acceptance tests, printing layer-by-layer outcomes
pytest examples/association-server/tests -v -s
```

## Status

The server and the client run against the official MCP Python SDK 2.2.0, negotiating protocol
**2026-07-28** — which matters, because extensions are only active at that version. The high-level
`Client` reaches it; a bare `ClientSession` handshake does not, and a server that looks like it
advertises nothing is usually a client that never got past the legacy handshake.

All seven acceptance tests pass against the live stack (2026-09-24), the agent signing through
`kli sign` with its delegated AID:

| Test | State |
|---|---|
| 1 — valid credential succeeds | passes when the credential is live; see below |
| 2 — no credential → `missing_credential` | passes |
| 2b — public tool needs nothing | passes |
| 2c — someone else's credential, your own key → `invalid_signature` | passes |
| 3 — revoked credential → `revoked` | passes (revocation read from the issuer's log) |
| 4 — tampered arguments → `digest_mismatch` | passes |
| 5 — unmodified client is additive | passes |

### How the verifier was taken off the critical path

`vlei-verifier` 1.0.0 crashes on its own revocation path — `process_revocations_from_event_log`
writes a database key of `None` and keripy raises `TypeError: sequence item 0: expected str
instance, NoneType found`. It takes the HTTP service down with it and comes back with an empty
database, so a credential presented a moment earlier is answered `unknown AID`. Written up for
upstream in [`docs/upstream/issue-final.md`](../docs/upstream/issue-final.md), reproduced live on
both tags on 2026-09-24.

**Changing the image version does not help.** `0.1.5` (2026-08-20) is newer than `1.0.0`
(2026-06-29) despite the numbering, and carries the same defect — at `utils.py:241` in 1.0.0 and
`utils.py:143` in 0.1.5. The tag is now `VLEI_VERIFIER_TAG` so a fixed release can be adopted without editing
the compose file.

**Three revocation sources, selectable, all kept:**

| `revocation_source` | Reads | Why you would choose it |
|---|---|---|
| `"tel"` *(default)* | `GET {witness}/query?typ=tel&vcid={said}` — the issuer's transaction event log | No dependency on a verification service. Same authority, one fewer moving part |
| `"verifier"` | `vlei-verifier` | Right in production, where the verifier is operated and has its own view of the ecosystem |
| `"none"` | nothing | Every result is marked `revocation_checked=False`. Legitimate only if the relying party is told |

Two structural changes did as much as the source switch:

- **Decide from the request first.** Freshness and the digest need nothing but the request, so a
  stale or altered call is refused before anything is asked of a witness — which is why test 4
  reports `digest_mismatch` rather than a connection error. The signature then needs the signer's
  key state, read from its key event log at a witness (never from the request); the chain and
  issuance are decided from the presented stream; revocation reads each issuer's live log.
- **`VleiVerifier.wait_ready()`**, with a bounded exponential backoff, replaces racing the
  container restart policy. Bounded on purpose: an unbounded wait turns a dead service into a hung
  test, which is harder to diagnose than a failure.

Test 1 needs a credential that has not been revoked. The acceptance suite's own test 3 revokes it,
so run `bash scripts/bootstrap-credentials.sh --reissue` before a run where test 1 matters.

**Two flow facts learned along the way**, both now in `spec/SPEC.md`:

- **Presentation is the holder's step.** `/presentations` requires headers signed by the AID the
  credential was issued to, so a relying party cannot present someone else's credential — it reads
  back what the holder established, at `/authorizations/{aid}`. A counterparty's credential is
  therefore verified locally, by `mcp_vlei.chain`.
- **Ask about the issuee, not the signer.** The agent signs with its delegated AID; the credential
  was issued to the person. The extension reads the issuee out of the credential rather than
  trusting the caller to name it.

## What the seven acceptance tests establish

| # | Test | Establishes |
|---|---|---|
| 1 | Call `register_member` with a credential | The whole path works: key state, delegation, chain, issuance, revocation, root, role |
| 2 | Call it without one | Refused as `missing_credential` |
| 2b | Call `list_events` without one | Public tools are untouched |
| 2c | Present the real ECR, sign with your own key | Refused as `invalid_signature` — the key comes from the agent's log, not the request |
| 3 | Revoke from the dashboard, call again | Refused as `revoked`. The revocation is real, in the LE's TEL |
| 4 | Sign one set of arguments, send another | Refused as `digest_mismatch` — this is what the digest exists for |
| 5 | Connect an unmodified MCP client (the SDK's plain `Client`) | Connects, lists tools, `list_events` works, `register_member` refused |

Test 5 is the backward-compatibility section of the specification made executable. An unmodified
host is not broken by the extension, is not locked out of the server, and is not silently granted
anything either.

## Reproducing test 5 with the real Claude Desktop

Test 5 uses a plain MCP client to stand in for an unmodified host. To show it with the actual
application — which is what the recording does, because a real product is more convincing than a
test double — add the server to Claude Desktop's configuration:

```jsonc
// %APPDATA%\Claude\claude_desktop_config.json   (macOS: ~/Library/Application Support/Claude/)
{
  "mcpServers": {
    "association": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:8080/mcp"]
    }
  }
}
```

Restart Claude Desktop, then in a conversation:

1. Ask it to list the association's events → `list_events` succeeds.
2. Ask it to register a member → `register_member` is refused, and the refusal names its layer:
   `missing_credential`.

Watch the dashboard while you do it. The connection appears marked **unverified**, the public call
is marked **public**, and the protected one is **refused** — three distinct states, which is the
point. Claude Desktop has no vLEI support, was not modified, and was neither broken nor locked out.

## Running it against the government gateway instead

```bash
VLEI_ACCEPTED_ROOTS=<root AID from credentials/env.json> \
  docker compose -f deploy/agentgateway/docker-compose.yml up -d
MCP_SERVER_URL=http://localhost:3000/mcp python examples/my-agent/agent.py "..."
```

One environment variable. `git diff` on the agent is empty, which is the claim `deploy/agentgateway/`
exists to substantiate.
