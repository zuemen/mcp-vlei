# Government gateway deployment

Stage 3 of [`docs/GOVERNMENT.md`](../../docs/GOVERNMENT.md), made executable: **verification at the
gateway, existing systems unmodified.**

The system behind the gateway is a labour-insurance filing **simulator** — *Simulated — not
connected to the Bureau of Labor Insurance.* It files nothing anywhere, knows employers only by a
test unified business number, and knows people only by fictitious references (`EMP-0001`).

```
agent ──▶ agentgateway :3000 ──▶ labor-insurance-sim :8081
               │
               └── extAuthz ──▶ vlei-authz :9000 ──▶ vlei-verifier :7676
```

| Component | vLEI code it contains |
|---|---|
| `examples/regulator/labor-insurance-sim/` | The names of four headers. Nothing else. |
| `examples/regulator/vlei-authz/` | All of it — the same `mcp_vlei` the in-process extension uses |
| `examples/my-agent/` | Unchanged from the association scenario |

## Running it

```bash
docker compose -f scripts/docker-compose.yml up -d        # witnesses, schemas, verifier
bash scripts/bootstrap-credentials.sh                      # credentials/
docker compose -f deploy/agentgateway/docker-compose.yml up -d

MCP_SERVER_URL=http://localhost:3000/mcp \
  python examples/my-agent/agent.py "enrol EMP-0001 in labour insurance from today, salary grade 3"
```

## Acceptance

Run acceptance tests 1–4 from `examples/association-server/tests/` against port 3000 instead of
8080. The outcomes are identical, including the failure layer each one reports.

**Lines of agent code changed: 0.** One environment variable points it somewhere else. `git diff`
on `examples/my-agent/` after switching is empty, and that is the whole argument — an institution
adopting this does not ask its counterparties to rewrite their agents.

## Three configuration details worth reading

All three were checked against agentgateway's published configuration JSON schema
(`schema/config.json` in `agentgateway/agentgateway`), not against prose examples.

**1. `maxRequestBytes` is raised to 65536.** The credential and signature live in the JSON-RPC
body's `_meta`, so the body must reach the authorizer — `extAuthz.includeRequestBody`. The default
cap is 8192 bytes, which a chained CESR ACDC exceeds.

`allowPartialMessage` stays `false` on purpose. A truncated credential is not a smaller credential;
it is an unverifiable one, and authorizing against a fragment would be worse than failing.

**2. `failureMode: deny` is stated explicitly** even though it is already the default. It is a
security property, and a reader should not have to know the default to know that an unreachable
authorizer refuses requests rather than waving them through.

**3. The role check is in `vlei-authz`, not in the CEL rule.** The CEL variables available to
`mcpAuthorization` at request time are `mcp.tool.*` and `jwt.*`. Headers produced by external
authorization are not addressable there, so `role == "labor-insurance-filing"` cannot be expressed
at that layer.

Role enforcement therefore lives in `vlei-authz`, which parses the credential, knows the tool, and
denies with a named failure layer before the request reaches the MCP policy. What `mcpAuthorization`
contributes is a closed list of reachable tools, so a tool added to the backend is not exposed by
accident. If a release adds ext-authz response headers to the CEL environment, the role check
belongs in both places, and the two layers then agree by construction.

The filing window lives in `vlei-authz` too, as an `arguments` rule in `policy.json`
(`start_date` / `end_date`: `dateWithinDays: [0, 10]` — the day itself, or up to ten days ahead). A
call outside it is refused as `scope_exceeded` before it reaches the simulator. The window is a
simplification: the published e-service rule also moves a deadline that falls on a holiday to the
next working day, which a fixed day count does not model.

## Audit log

`vlei-authz` writes one JSON object per line to `VLEI_AUDIT_LOG`
(default `/var/log/vlei-authz/decisions.jsonl`), for allowed and denied requests alike:

```json
{"decision":"allow","tool":"enroll_employee","lei":"984500ABCDEF12345678","role":"labor-insurance-filing","holderAid":"EDq8…","delegateAid":"EFn3…","credentialSaid":"EBcd…","at":"2026-09-23T04:12:47+00:00"}
{"decision":"deny","tool":"enroll_employee","layer":"revoked","message":"the credential has been revoked","aid":"EFn3…","at":"2026-09-23T04:15:02+00:00"}
```

A log of refusals alone cannot answer *who filed this?* — which is the question stage 5 of
`docs/GOVERNMENT.md` exists to make answerable — so allowed requests are recorded too.

## Why this shape matters for adoption

An institution evaluating this asks one question first: *do we have to change our systems?* The
answer determines whether adoption is a configuration change or a project.

`labor-insurance-sim/server.py` is the answer in executable form. It receives `x-vlei-lei`,
`x-vlei-role`, `x-vlei-holder-aid` and `x-vlei-delegate-aid` and treats them exactly as it would
treat headers from any other authentication layer it already sits behind. Note also what is *not* a
parameter of `enroll_employee`: which employer is filing. That comes from the verified credential —
the LEI, mapped to a unified business number through the entity record's `registeredAs` — not from
the caller — which removes a class of impersonation without the file containing a line of
identity code.
