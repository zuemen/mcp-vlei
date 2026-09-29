# Where the observatory runs, and why

Decided 2026-09-29.

## What was there

* `zuemen.net` — two A records, served by **Vercel**.
* DNS — **Cloudflare** nameservers, the apex not proxied (no `cf-ray` on responses).
* `mcp.zuemen.net`, `www.zuemen.net`, and any other subdomain — **did not exist** (NXDOMAIN; no
  wildcard record).

Adding `mcp.zuemen.net` therefore creates a name; it edits nothing the site depends on.

## Why not a Vercel serverless function

* **The legacy handshake needs one process.** A real client may send `initialize`, receive a
  session id, and call the tool in a later request. Serverless has to run stateless, those requests
  can land on different instances, and `ctx.session.client_params` inside the tool may come back
  empty — losing the protocol layer the observatory exists to record.
* **The log would live with a third party.** No writable disk means the log, its rotation and the
  per-address limit move to an external store — one more company holding the records.
* **It would sit inside the personal site's repository.** A fault there is a fault on the CV site.

## Why a Cloudflare Tunnel from the author's machine, rather than a PaaS

| | Tunnel | Fly.io | Railway | Render free |
|---|---|---|---|---|
| Cost | none | ≈ US$1.94/month (shared-cpu-1x, 256 MB) | US$5/month | none |
| Always on | only while running | yes | yes | sleeps when idle |
| "Bind 127.0.0.1 only" | literally | needs a proxy inside the VM | same | same |
| Log | local file | remote volume | remote volume | none persistent |

* The requirement "bind 127.0.0.1; a reverse proxy terminates HTTPS" is met as written: cloudflared
  connects to loopback and Cloudflare terminates TLS. On a PaaS the app must listen on the VM's
  interface for the platform's proxy to reach it.
* The log stays a local file, so the console reads it directly on stage — no dependence on venue
  networking.
* The endpoint exists only while the experiment runs; there is no standing public server to keep
  patched.
* DNS is already on Cloudflare, so no new vendor is involved.

**If an always-on observatory is wanted later**, the same code moves to Fly.io unchanged except for
the bind address (a proxy in the VM) and `OBS_PUBLIC_HOST`.

## DNS change

One record, created by `cloudflared tunnel route dns mcp-observatory mcp.zuemen.net`:

```
CNAME  mcp  →  <tunnel-id>.cfargotunnel.com   (proxied)
```

The apex A records, the nameservers and the proxy setting of the apex are not touched.
