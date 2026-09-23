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

## Running it against the government gateway instead

```bash
docker compose -f deploy/agentgateway/docker-compose.yml up -d
MCP_SERVER_URL=http://localhost:3000/mcp python examples/my-agent/agent.py "..."
```

One environment variable. `git diff` on the agent is empty, which is the claim `deploy/agentgateway/`
exists to substantiate.
