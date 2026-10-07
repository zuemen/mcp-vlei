# Government gateway deployment

Stage 3 of [`docs/GOVERNMENT.md`](../../docs/GOVERNMENT.md), made executable: **verification at the
gateway, existing systems unmodified.**

The system behind the gateway is a labour-insurance filing **simulator** — *Simulated — not
connected to the Bureau of Labor Insurance.* It files nothing anywhere, knows employers only by a
test unified business number, and knows people only by fictitious references (`EMP-0001`).

```
agent ──▶ agentgateway :3000 ──▶ labor-insurance-sim :8081
               │
               ├── extAuthz ──▶ vlei-authz :9001 ──▶ witnesses (key states, revocation)
               └── /.well-known/vlei, /.well-known/vlei/pop ──▶ vlei-pop :9100 (kli sign, own keystore)
```

| Component | vLEI code it contains |
|---|---|
| `examples/regulator/labor-insurance-sim/` | The names of four headers. Nothing else. |
| `examples/regulator/vlei-authz/` | All of it — the same `mcp_vlei` the in-process extension uses |
| `examples/my-agent/` | Unchanged from the association-server scenario |

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

**1. `maxRequestBytes` is raised to 262144.** The credential and signature live in the JSON-RPC
body's `_meta`, so the body must reach the authorizer — `extAuthz.includeRequestBody`. The default
cap is 8192 bytes, which a chained CESR ACDC exceeds. It was 65536 until 2026-09-30, when an ECR
stream grew past it after a few re-issues — the exported stream carries the issuers' key event logs,
which grow with every issuance and revocation — and every call was refused with 413. The lasting
fix is to present the ACDC without the logs; the verifier reads them from the witnesses anyway.

`allowPartialMessage` stays `false` on purpose. A truncated credential is not a smaller credential;
it is an unverifiable one, and authorizing against a fragment would be worse than failing.

**2. `failureMode: deny` is stated explicitly** even though it is already the default. It is a
security property, and a reader should not have to know the default to know that an unreachable
authorizer refuses requests rather than waving them through.

**3. Every decision is in `vlei-authz`, and the MCP backend is plain HTTP.** Until 2026-10-01 the
route used an `mcp:` backend with an `mcpAuthorization` rule listing the four tools.

Two reasons led to the change.

- **The role check never fitted the CEL rule.** The CEL variables available to `mcpAuthorization`
  are `mcp.tool.*` and `jwt.*`. Headers produced by external authorization are not addressable
  there, so `role == "labor-insurance-filing"` cannot be expressed at that layer.
- **The MCP layer re-frames 2026-07-28 responses.** With the per-request envelope, v1.5.0 turns
  the server's JSON response into a `text/event-stream`. It also rebuilds the `tools/list` result
  without the server's `_meta["io.modelcontextprotocol/serverInfo"]`.

  The official SDK client accepts that. The claude.ai connector, connected to this gateway through
  the public tunnel, reported "This connector has no tools available". The same connector had
  listed and called tools on the observatory, an SDK server it reached directly.

  With a plain backend, the server's responses pass through byte for byte. claude.ai's sequence
  (`server/discover`, `tools/list` with no session) then gets exactly what the server sent: JSON,
  four tools, `serverInfo`.

Nothing that mattered was lost:

- The closed list of reachable tools is `vlei-authz`'s `policy.json`, which refuses an unlisted
  tool rather than treating it as public. `mcpAuthorization` only repeated it.
- Tool names were never prefixed.
- Every check, the rate limits and the identity headers are HTTP-level policies, unchanged.
- One thing does change: the gateway's own log no longer names the MCP method of each request.
  `vlei-authz`'s audit log still records every tool call.

The filing window lives in `vlei-authz` too, as an `arguments` rule in `policy.json`
(`start_date` / `end_date`: `dateWithinDays: [0, 10]` — the day itself, or up to ten days ahead). A
call outside it is refused as `scope_exceeded` before it reaches the simulator. The window is a
simplification: the published e-service rule also moves a deadline that falls on a holiday to the
next working day, which a fixed day count does not model.

## How a refusal reaches the model: gRPC ext-authz

`vlei-authz` is called over gRPC (Envoy's ext_authz `Check` API, on :9001), not over HTTP (:9000).
The reason is what each wire can say when a `tools/call` is refused.

- **HTTP ext-authz.** agentgateway v1.5.0 allows on any 2xx and returns anything else as it is, so
  a refusal can only be a 4xx.

  On 2026-10-01 the claude.ai connector showed that 403 as "The connector's server returned an
  error". Claude never saw `missing_credential`, called it a server fault, and offered to try again.

  A refusal sent as 203 was no answer either: agentgateway treated it as an allow, and the call
  reached the simulator.
- **gRPC ext-authz.** A refusal is a non-OK `CheckResponse` carrying its own HTTP response, and
  agentgateway returns it without calling the backend (`crates/agentgateway/src/http/ext_authz.rs`).

  `vlei-authz` answers a refused call with HTTP 200 and the call's own JSON-RPC answer: an MCP
  tool error (`isError: true`) whose first line is the layer, for example
  `missing_credential: this tool requires an ECR credential…`. A 2026-07-28 request also gets
  `resultType: complete`, and `serverInfo` naming `vlei-authz`, the component that answered.

  A body with no call in it to answer — unreadable, a batch, a call without a name — is still a
  403.

When a call is allowed, the `CheckResponse` first removes all six `x-vlei-*` headers and then sets
the ones established. A value a client sends under one of those names never reaches the simulator;
this was checked live on 2026-10-01 with forged `x-vlei-lei`, `x-vlei-role` and
`x-vlei-delegate-aid`.

The HTTP service keeps its contract (200 or 403) for gateways that speak only HTTP ext-authz. Both
wires share one decision function, one policy and one audit log.

The protocol buffers are agentgateway's own (`vlei-authz/envoy_authz/proto/`), compiled with
grpcio-tools 1.73.1.

## Rate limits, for when the gateway is public

The `/.well-known/vlei` and labor-insurance routes carry the same conditional `localRateLimit`:

- **Public callers.** Requests with `cf-connecting-ip` share one bucket of 60 per minute. Cloudflare
  sets that header on everything through the tunnel, and a caller cannot remove it.
- **Everything else.** The console, the credential proxy and the tests share another bucket, of 600
  per minute.
- **Over the limit.** A request over the limit is answered with 429.
- **The proof of possession** (`/.well-known/vlei/pop`) has its own public bucket of 5 per minute
  (local callers keep 600). vlei-pop signs one challenge at a time, 2–3 s each, with four waiting;
  at 60 a minute one public caller at one request a second keeps that queue full, and the
  credential proxy's connect and re-check get 503.

This matters because in v1.5.0 a local limit is one token bucket per entry, not one per client. A
single bucket would let a flood from outside stall the local demonstration; two buckets keep it
contained.

Per-client limits need a remote rate-limit service. Checked on 2026-10-01: 70 requests with the
header gave 60 × 200 then 10 × 429, and 70 without it gave 70 × 200.

## Who operates the gateway, and what each tool requires

A caller can establish both before presenting anything, with no authorization involved.

**The operator's LE at `/.well-known/vlei`.** The `well-known` route in `config.yaml` sends that
one path to `vlei-pop`, outside the `extAuthz` route. It publishes the file it is given
(`VLEI_LE_CREDENTIAL_FILE`), the signature format the gateway verifies (`vlei-sig/0.3`), where to
challenge it, and `ttlMs`.

**The proof that the operator holds its key, at `/.well-known/vlei/pop` (v0.3).** A client's
challenge is answered by `vlei-pop` with a statement signed by the `gateway` AID — delegated by the
operator's LE (`scripts/bootstrap-gateway-signer.sh`), its key only in `vlei-pop`'s own keystore
volume, signing with `kli sign`. It signs only for the URLs in `VLEI_AUDIENCE_URLS`. The credential
proxy presents nothing until this proof verifies.

**The recipient and the replay store (v0.3).** `vlei-authz` refuses a call signed for another LE or
another URL than those in `VLEI_AUDIENCE_URLS` (`audience_mismatch`), and claims each signature's
nonce once in `VLEI_REPLAY_DB`, a SQLite file on the `vlei-authz-state` volume, so a restart forgets
nothing. With a fresh volume, calls are refused for its first minute.

That LE belongs to the operator: *Simulated Labour Insurance Office (fictional)*, LEI
`984500LABORSIM000054`. `scripts/bootstrap-regulator.sh` issues it from the same QVI, and
`scripts/reset-demo.sh` starts the gateway with it:

```bash
VLEI_LE_CREDENTIAL_FILE=../../credentials/regulator/le.cesr \
  docker compose -f deploy/agentgateway/docker-compose.yml up -d
```

Without that variable the gateway publishes `credentials/le.cesr`, the employer's LE. That
answers "who operates this gateway?" with the wrong party.

**Each tool's requirement in its `_meta`.** The simulator copies
`org.gleif.vlei/requires` onto each tool from `vlei-authz/policy.json`, the same file the gateway
enforces, so what is published and what is enforced cannot drift apart. The backend is plain HTTP
(detail 3 above), so tool `_meta` reaches the caller exactly as the simulator wrote it.

The credential proxy (`examples/credential-proxy/`) relies on both. It refuses to list a tool
until the published LE verifies.

## Audit log

`vlei-authz` writes one JSON object per line to `VLEI_AUDIT_LOG`
(default `/var/log/vlei-authz/decisions.jsonl`), for allowed and denied requests alike:

```json
{"decision":"allow","tool":"enroll_employee","lei":"984500DEMOSTAFF00178","role":"labor-insurance-filing","holderAid":"EDq8…","delegateAid":"EFn3…","credentialSaid":"EBcd…","at":"2026-09-23T04:12:47+00:00"}
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
