# Government gateway deployment

Stage 3 of [`docs/GOVERNMENT.md`](../../docs/GOVERNMENT.md), made executable: **verification at the
gateway, existing systems unmodified.**

```
agent ──▶ agentgateway :3000 ──▶ filing-server :8081
               │
               └── extAuthz ──▶ vlei-authz :9000 ──▶ vlei-verifier :7676
```

| Component | vLEI code it contains |
|---|---|
| `examples/regulator/filing-server/` | The names of four headers. Nothing else. |
| `examples/regulator/vlei-authz/` | All of it — the same `mcp_vlei` the in-process extension uses |
| `examples/my-agent/` | Unchanged from the association scenario |

## Running it

```bash
docker compose -f scripts/docker-compose.yml up -d        # witnesses, schemas, verifier
bash scripts/bootstrap-credentials.sh                      # credentials/
docker compose -f deploy/agentgateway/docker-compose.yml up -d

MCP_SERVER_URL=http://localhost:3000/mcp \
  python examples/my-agent/agent.py "submit the A1 return for 2026Q2"
```

## Acceptance

Run acceptance tests 1–4 from `examples/association-server/tests/` against port 3000 instead of
8080. The outcomes are identical, including the failure layer each one reports.

**Lines of agent code changed: 0.** One environment variable points it somewhere else. `git diff`
on `examples/my-agent/` after switching is empty, and that is the whole argument — an institution
adopting this does not ask its counterparties to rewrite their agents.

## Two places the configuration differs from the obvious design

Both are constraints of the current agentgateway release, verified against its documentation rather
than assumed. They are written down because a reviewer will otherwise assume the configuration is
careless.

**1. The credential travels in headers, not the body.** agentgateway's HTTP external authorization
forwards request *headers* to the authorizer (`protocol.includeRequestHeaders`); there is no
documented request-body forwarding, and the vLEI credential and signature live in the JSON-RPC
body's `_meta`. The client therefore mirrors those values into `x-vlei-*` headers
(`VleiClient(..., mirror_headers=True)`).

This does not weaken the check. The signature's digest covers the canonicalized `params`, so a
mirrored header that disagrees with the body fails on `digest_mismatch` rather than being believed.
`vlei-authz` prefers the body whenever one is present, so a future release that forwards it makes
the mirror redundant rather than wrong.

**2. The role check is in `vlei-authz`, not in the CEL rule.** The CEL variables available to
`mcpAuthorization` at request time are `mcp.tool.*` and `jwt.*`. Headers produced by external
authorization are not addressable there, so `role == "regulatory-filing"` cannot be expressed at
that layer.

Role enforcement therefore lives in `vlei-authz`, which parses the credential, knows the tool, and
denies with a named failure layer before the request reaches the MCP policy. What `mcpAuthorization`
contributes is a closed list of reachable tools, so a tool added to the backend is not exposed by
accident. If a release adds ext-authz response headers to the CEL environment, the role check
belongs in both places and the two layers then agree by construction.

## Why this shape matters for adoption

An institution evaluating this asks one question first: *do we have to change our systems?* The
answer determines whether adoption is a configuration change or a project.

`filing-server/server.py` is the answer in executable form. It receives `x-vlei-lei`,
`x-vlei-role`, `x-vlei-holder-aid` and `x-vlei-delegate-aid` and treats them exactly as it would
treat headers from any other authentication layer it already sits behind. Note also what is *not* a
parameter of `submit_filing`: which entity is filing. That comes from the verified credential, not
from the caller — which removes a class of impersonation without the file containing a line of
identity code.
