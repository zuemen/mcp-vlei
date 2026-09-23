# Reference implementations

Three deployments, one agent. The agent's source does not change between them.

| Directory | What it is |
|---|---|
| `association-server/` | The association's own MCP server: presents its LE, requires an ECR for `register_member`, and shows every decision on a live dashboard |
| `my-agent/` | An agent that presents a vLEI credential — Claude as the model, official MCP client, `VleiClient` for identity, and the skill loaded as its system prompt |
| `regulator/` | The government scenario: a filing server that does **no** vLEI verification at all, sitting behind a gateway that does |

## Running the whole thing

```bash
# 1. Credential environment — real KERI, real ACDC, real verifier, self-configured root
bash scripts/bootstrap-credentials.sh

# 2. The association's server (terminal 2)
pip install -e packages/mcp-vlei
python examples/association-server/server.py
#    dashboard: http://localhost:8080/dashboard/

# 3. The agent (terminal 3)
export ANTHROPIC_API_KEY=...
python examples/my-agent/agent.py "register Chen Wei-Ting, weiting@example.org.tw"

# 4. Acceptance tests, printing layer-by-layer outcomes
pytest examples/association-server/tests -v -s
```

## Status

The server and the client run against the official MCP Python SDK 2.2.0, negotiating protocol
**2026-07-28** — which matters, because extensions are only active at that version. The high-level
`Client` reaches it; a bare `ClientSession` handshake does not, and a server that looks like it
advertises nothing is usually a client that never got past the legacy handshake.

| Test | State |
|---|---|
| 2 — no credential → `missing_credential` | passes |
| 2b — public tool needs nothing | passes |
| 5 — unmodified client is additive | passes |
| 1 — valid credential succeeds | blocked, see below |
| 3 — revoked credential refused | blocked, see below |
| 4 — tampered arguments refused | blocked, see below |

**What blocks the other three.** `vlei-verifier` 1.0.0 crashes on its own revocation path —
`process_revocations_from_event_log` writes a database key of `None` and keripy raises
`TypeError: sequence item 0: expected str instance, NoneType found`. It takes the HTTP service
down with it and comes back with an empty database, so a credential presented a moment earlier is
answered with `unknown AID`. The compose file restarts it automatically and the tests re-present
before each case, and it still loses the race often enough that these three cannot be called
green.

This is worth raising with GLEIF. It is also why the failures in this repository's history read as
connection errors rather than credential errors: a crashed verifier looks, from the client, exactly
like a network problem.

**Two flow facts learned along the way**, both now encoded in the package:

- **Presentation is the holder's step.** `/presentations` requires headers signed by the AID the
  credential was issued to, so a relying party cannot present someone else's credential — it reads
  back what the holder established, at `/authorizations/{aid}`. This is how GLEIF's regulatory
  filing pilot works too.
- **Ask about the issuee, not the signer.** The agent signs with its delegated AID; the credential
  was issued to the person. The verifier's record is keyed by the holder, so the extension reads
  the issuee out of the credential rather than trusting the caller to name it.

## What the five acceptance tests establish

| # | Test | Establishes |
|---|---|---|
| 1 | Call `register_member` with a credential | The whole path works: chain, revocation, root, signature, role |
| 2 | Call it without one | Refused as `missing_credential` — and `list_events` still works |
| 3 | Revoke from the dashboard, call again | Refused as `revoked`. The revocation is real, in the LE's TEL |
| 4 | Sign one set of arguments, send another | Refused as `digest_mismatch` — this is what the digest exists for |
| 5 | Connect an unmodified Claude Desktop | Connects, lists tools, `list_events` works, `register_member` refused |

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
docker compose -f deploy/agentgateway/docker-compose.yml up -d
MCP_SERVER_URL=http://localhost:3000/mcp python examples/my-agent/agent.py "..."
```

One environment variable. `git diff` on the agent is empty, which is the claim `deploy/agentgateway/`
exists to substantiate.
