# MCP Observatory

`examples/impersonation/` shows, in process, that a server cannot tell a claimed `clientInfo` from
a real one. This directory takes the same measurement off the laptop: a **real MCP client** — the
claude.ai custom connector — and **a replay script** connect to the same public server, and the
server puts what it received from each side by side at `/observatory`.

It is built to show two things, and only these:

1. At the protocol layer the two are indistinguishable: the `clientInfo` is the same.
2. Neither can say which legal entity is acting, which agent it is, or what it is authorised to do.

**This server is the repository author's own.** It is not pointed at, and does not test, anyone
else's service. It records no conversation content and no tool arguments.

## What is recorded

| Layer | Where | Fields |
|---|---|---|
| Transport | ASGI layer in `server.py`, before the SDK parses the request | JSON-RPC `method`; `initialize` params `protocolVersion` / `clientInfo` / `capabilities` (legacy handshake); the `_meta` keys `io.modelcontextprotocol/protocolVersion`, `…/clientInfo`, `…/clientCapabilities` (2026-07-28 envelope); `User-Agent`, `MCP-Protocol-Version`, `Origin`; whether `Authorization` was present; `X-Observatory-Run` |
| Protocol | inside `echo_identity` | `ctx.session.client_params` — what the SDK hands a tool after its own parsing |

Never recorded: tool arguments, any other `_meta` key, bearer tokens, IP addresses (the rate
limiter holds them in memory only), the session id itself (only an 8-character hash, to match an
`initialize` to the call after it). Every string is clipped at 300 characters.

The log is `data/observations.jsonl` (git-ignored), rotated at 10 MB into `.1`–`.3`.

## The surface

| Route | Methods | What it does |
|---|---|---|
| `/mcp` | POST, GET, DELETE | Streamable HTTP. Two tools, both annotated read-only: `echo_identity`, `ping`. No resources, no prompts. `DELETE` ends the caller's own session, as the transport defines. |
| `/observatory` | GET, HEAD | The comparison page, and every real client once. No script; CSP `default-src 'none'`. `?real=` and `?replay=` pin the pair (below). |
| `/observatory.json` | GET, HEAD | The same, as data. The console's scene 0 reads it; it takes the same parameters. |
| anything else | — | 404 |

Limits: request body 64 KB (413 above it), 60 requests per minute per client address (429), Host
header must be `127.0.0.1`, `localhost` or `OBS_PUBLIC_HOST` (421 otherwise). The server binds
127.0.0.1 and has no option to bind anything else.

## Run it locally

```bash
pip install -e packages/mcp-vlei uvicorn
python examples/observatory/server.py                       # http://127.0.0.1:8765/observatory
pytest examples/observatory/tests -q                        # the local acceptance
```

## Deploy: Cloudflare Tunnel to `mcp.zuemen.net`

`zuemen.net` is served by Vercel; its DNS is on Cloudflare. The observatory does not touch either:
it adds one new name, `mcp.zuemen.net`, which today does not exist. The site's own records are not
changed. Why a tunnel from the author's machine rather than serverless, a PaaS or a VPS is in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

```bash
winget install --id Cloudflare.cloudflared         # or brew install cloudflared
cloudflared tunnel login                           # browser: pick the zuemen.net zone
cloudflared tunnel create mcp-observatory
cloudflared tunnel route dns mcp-observatory mcp.zuemen.net
# copy deploy/cloudflared.example.yml to ~/.cloudflared/config.yml and fill in the tunnel id
```

`route dns` creates one record, `CNAME mcp → <tunnel-id>.cfargotunnel.com`. Do not pass
`--overwrite-dns`; without it, a name that already has a record is refused rather than replaced.

Then, in two terminals:

```bash
OBS_PUBLIC_HOST=mcp.zuemen.net OBS_TRUST_CF=1 python examples/observatory/server.py
cloudflared tunnel run mcp-observatory
```

`OBS_TRUST_CF=1` makes the rate limiter key on `CF-Connecting-IP`, and only for connections that
arrive from loopback — which is where cloudflared connects from. When the experiment is over, stop
both — in the order under *When the experiment is over*.

## The experiment

1. **Add the connector.** In claude.ai, add a custom connector in settings with the URL
   `https://mcp.zuemen.net/mcp`. No authentication.
2. **Real client.** In a new conversation, ask Claude to call `echo_identity`.
3. **Replay.**
   ```bash
   python examples/observatory/replay_client.py --url https://mcp.zuemen.net/mcp
   ```
   It prints two lines: the identity it is replaying, and the identity the server recorded.
4. **Compare.** Open `https://mcp.zuemen.net/observatory`.

### Pinning the comparison

Without parameters each side is its newest record, so the next client to connect replaces the
pair on screen. To keep one pair, name each side by its record's timestamp — or any prefix of it:

```
/observatory?real=2026-09-29T04:10:48.9&replay=2026-09-29T04:13:30.7
/observatory?real=2026-09-29T04:10&replay=2026-09-29T04:13
```

Timestamps are UTC, as recorded; the page shows each beside Taipei time. The newest matching record
of that side is used, the transport layer preferred, and the tool row comes from the same request.
A selector that matches nothing shows *no record matches* — it never falls back to the newest. The
two cards at the top say which records are compared, when, and how they were chosen. Anything but a
timestamp or its prefix is refused with 400.

Below the comparison, **All real clients** lists every client that connected without the replay
header, once per `clientInfo.name`, with its newest `clientInfo`, `protocolVersion`, `User-Agent`
and time.

### Evidence

```bash
python examples/observatory/export_evidence.py     --pick "claude.ai=real:2026-09-29T04:10:48.9"     --pick "replay=replay:2026-09-29T04:13:30.7"     --pick "claude-code=real:2026-09-29T04:17:30.3"     --out docs/evidence/observatory-2026-09-29.json
```

It writes only listed fields (not the session hash). Before writing, it checks each chosen record
and the file for an IP address, a bearer token or JWT, an `Authorization` value, and keys that carry
conversation (`arguments`, `messages`, `content`, …); any one stops it, and nothing is written. The
log itself (`data/`) is gitignored and stays on the machine that received it.

### When the experiment is over — in this order

1. **Export the evidence and take the screenshots** while the records and the page are there
   (above; the pinned URL for the screenshots).
2. **Disconnect the claude.ai connector** (claude.ai → settings → connectors → remove
   `mcp.zuemen.net`), so nothing calls a server that is about to disappear.
3. **Stop the server and the tunnel** — both terminals, Ctrl-C. `mcp.zuemen.net` then answers
   with a Cloudflare error; nothing else is affected.
4. **After the talk, delete the tunnel and its DNS record**:
   `cloudflared tunnel delete mcp-observatory`, and remove the `mcp` CNAME in the Cloudflare
   dashboard. Until then the name exists but points at nothing that runs.

The replay sends the recorded `clientInfo` unchanged and speaks the same handshake (legacy
`initialize`, or a 2026-07-28 envelope pinned to the recorded version). It is told apart only by
`X-Observatory-Run: replay`, an HTTP header that is not one of MCP's identity fields. Renaming the
replay would have made it not a replay.

`--match-user-agent` also sends the real client's `User-Agent`. Leave it off for the first run: the
point of the page is that the differing fields are shown, and that they too are only strings.

## Known limits

* **What the real client sends is not known until it is recorded.** Step 2 is the measurement.
* The real client may use the legacy `initialize` handshake rather than the 2026-07-28 envelope.
  Both are recorded; the page says which (`Handshake`).
* The replay goes through the SDK's `Implementation` model, which keeps the six fields MCP defines
  and drops any others. If the real client sends an extra field, `clientInfo` will show
  **Different** — correctly: the page does not paper over it.
* `capabilities` in the replay are the SDK client's own. If the real client advertises more, that
  row shows **Different**. Capabilities are negotiation, self-reported like everything else.
* `User-Agent`, `Origin` and `MCP-Protocol-Version` will likely differ. They are shown as they are.
  None of them is proof of anything either.
* The OAuth mode in the original plan (`OBS_OAUTH=1`) is not built. A claude.ai connector that
  authenticates needs a full authorisation server with dynamic client registration; a partial one
  would record a `client_id` this server issued to itself, which demonstrates nothing. The point it
  would make — a different `client_id` identifies the software, still not the legal entity or the
  agent — is stated here rather than staged.
