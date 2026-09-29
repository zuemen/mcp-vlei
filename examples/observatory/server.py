"""MCP Observatory — a server that only records what it receives about the client.

Two read-only tools (`echo_identity`, `ping`) over Streamable HTTP at `/mcp`, and a read-only page
at `/observatory` that puts the newest real client beside the newest replay.

Two layers are recorded, because a real client may use either handshake:

* **transport** — an ASGI layer in front of the SDK parses each POST body before the SDK sees it:
  `initialize` params (legacy handshake), the `_meta` identity keys (2026-07-28 envelope), and four
  headers. See `observations.py` for the exact list; nothing else is kept.
* **protocol** — inside `echo_identity`, what the SDK itself hands a tool: `ctx.session.client_params`.

This server belongs to the repository's author. It is not pointed at, and does not call, anyone
else's service. It binds 127.0.0.1 only; a reverse proxy (Cloudflare Tunnel in the README)
terminates HTTPS in front of it.

    python examples/observatory/server.py                # http://127.0.0.1:8765
    OBS_PUBLIC_HOST=mcp.zuemen.net OBS_TRUST_CF=1 python examples/observatory/server.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from mcp.server.mcpserver import Context, MCPServer  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

import page  # noqa: E402
from observations import (  # noqa: E402
    ObservationLog,
    protocol_record,
    summary,
    transport_records,
    valid_selector,
)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

DEFAULT_LOG = HERE / "data" / "observations.jsonl"
DEFAULT_PORT = 8765
MAX_BODY = 64 * 1024
RATE_PER_MINUTE = 60

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                            open_world_hint=False)


# ------------------------------------------------------------------------------------------- #
# The MCP server
# ------------------------------------------------------------------------------------------- #

def build_mcp(log: ObservationLog) -> MCPServer:
    server = MCPServer(
        name="zuemen-observatory",
        version="0.1.0",
        instructions=(
            "A read-only observatory. It records what it receives about the calling client "
            "and shows it back. It changes nothing and calls nothing."
        ),
    )

    @server.tool(annotations=READ_ONLY)
    def echo_identity(ctx: Context) -> dict[str, Any]:
        """Return what this server received about the calling client: protocol version,
        clientInfo, capabilities and a few HTTP headers. Read-only."""
        try:
            client_params = ctx.session.client_params
        except Exception:  # noqa: BLE001 - no session state is itself an observation
            client_params = None
        record = protocol_record(client_params, ctx.protocol_version, ctx.headers)
        _append(log, record)
        return {
            "asReceived": {k: record[k] for k in ("protocolVersion", "clientInfo", "capabilities")},
            "headers": record["headers"],
            "note": "Every value above was supplied by the client. None of it is verified.",
        }

    @server.tool(annotations=READ_ONLY)
    def ping() -> str:
        """Return pong. Read-only."""
        return "pong"

    return server


def _append(log: ObservationLog, record: dict[str, Any]) -> None:
    try:
        log.append(record)
    except OSError as exc:  # a full disk must not take the server down with it
        print(f"observatory: could not write log: {exc}", file=sys.stderr)


# ------------------------------------------------------------------------------------------- #
# Rate limiting
# ------------------------------------------------------------------------------------------- #

class RateLimiter:
    """Sliding one-minute window per client address. Addresses are held in memory only."""

    def __init__(self, per_minute: int = RATE_PER_MINUTE,
                 clock: Callable[[], float] = time.monotonic, max_clients: int = 10_000):
        self.per_minute = per_minute
        self.clock = clock
        self.max_clients = max_clients
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = self.clock()
        window = self._hits.get(key)
        if window is None:
            window = self._hits[key] = deque()
        else:
            self._hits.move_to_end(key)
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= self.per_minute:
            return False
        window.append(now)
        while len(self._hits) > self.max_clients:
            self._hits.popitem(last=False)
        return True


# ------------------------------------------------------------------------------------------- #
# The ASGI layer in front of the SDK
# ------------------------------------------------------------------------------------------- #

_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
]


class Observatory:
    """Routes, limits and records; forwards `/mcp` to the SDK unchanged.

    Routes: `/mcp` (GET, POST, DELETE — the Streamable HTTP transport), `/observatory` and
    `/observatory.json` (GET, HEAD). Everything else is 404. No route writes anything except
    the observation of the request itself.
    """

    def __init__(self, mcp_app: Callable[..., Awaitable[None]], log: ObservationLog, *,
                 allowed_hosts: list[str], public_host: str | None = None,
                 trust_cf_header: bool = False, limiter: RateLimiter | None = None):
        self.mcp_app = mcp_app
        self.log = log
        self.allowed_hosts = allowed_hosts
        self.public_host = public_host
        self.trust_cf_header = trust_cf_header
        self.limiter = limiter or RateLimiter()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.mcp_app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        send = _secured(send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        method, path = scope["method"], scope["path"]

        if not _host_allowed(headers.get("host"), self.allowed_hosts):
            await _plain(send, 421, "Misdirected request.")
            return
        if not self.limiter.allow(self._client_key(scope, headers)):
            await _plain(send, 429, "Too many requests: 60 per minute.",
                         [(b"retry-after", b"60")])
            return

        if path in ("/observatory", "/observatory/", "/observatory.json"):
            if method not in ("GET", "HEAD"):
                await _plain(send, 405, "Read-only.", [(b"allow", b"GET, HEAD")])
                return
            chosen = _selectors(scope)
            if chosen is None:
                await _plain(send, 400, "real and replay name a record by its timestamp, or a "
                             "prefix of it: ?real=2026-09-29T04:10&replay=2026-09-29T04:13")
                return
        if path in ("/observatory", "/observatory/"):
            html = page.render(summary(self.log, **chosen), self.public_host).encode()
            await _respond(send, 200, html, "text/html; charset=utf-8",
                           [(b"content-security-policy", page.CSP.encode())], method == "HEAD")
            return
        if path == "/observatory.json":
            data = json.dumps(summary(self.log, **chosen), ensure_ascii=False, indent=2).encode()
            await _respond(send, 200, data, "application/json; charset=utf-8", [],
                           method == "HEAD")
            return
        if path == "/":
            await _respond(send, 302, b"", "text/plain", [(b"location", b"/observatory")])
            return
        if path != "/mcp":
            await _plain(send, 404, "Not found.")
            return

        if method in ("GET", "DELETE"):
            await self.mcp_app(scope, receive, send)
            return
        if method != "POST":
            await _plain(send, 405, "Method not allowed.", [(b"allow", b"GET, POST, DELETE")])
            return

        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY:
            await _plain(send, 413, "Request body over 64 KB.")
            return
        body = await _read_body(receive, MAX_BODY)
        if body is None:
            await _plain(send, 413, "Request body over 64 KB.")
            return

        for record in transport_records(body, headers):
            _append(self.log, record)

        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.mcp_app(scope, replay_receive, send)

    def _client_key(self, scope: Scope, headers: dict[str, str]) -> str:
        peer = (scope.get("client") or ("unknown", 0))[0]
        # cloudflared connects from loopback; only then is its header the real client address.
        if self.trust_cf_header and peer in ("127.0.0.1", "::1") and headers.get("cf-connecting-ip"):
            return headers["cf-connecting-ip"][:64]
        return str(peer)


def _selectors(scope: Scope) -> dict[str, str | None] | None:
    """`?real=` and `?replay=`, each a record's timestamp or a prefix of it; `None` if either is
    anything else. Read-only: they choose what the page shows and change nothing recorded."""
    query = parse_qs(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
    chosen: dict[str, str | None] = {}
    for side in ("real", "replay"):
        values = query.get(side)
        if not values:
            chosen[side] = None
        elif len(values) == 1 and valid_selector(values[0]):
            chosen[side] = values[0]
        else:
            return None
    return chosen


def _host_allowed(host: str | None, allowed: list[str]) -> bool:
    if not host:
        return False
    if host in allowed:
        return True
    return any(a.endswith(":*") and host.startswith(a[:-2] + ":") for a in allowed)


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _secured(send: Send) -> Send:
    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            existing = {k.lower() for k, _ in message.get("headers", [])}
            message = dict(message)
            message["headers"] = list(message.get("headers", [])) + [
                (k, v) for k, v in _SECURITY_HEADERS if k not in existing
            ]
        await send(message)
    return wrapped


async def _respond(send: Send, status: int, body: bytes, content_type: str,
                   extra: list[tuple[bytes, bytes]], head_only: bool = False) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", content_type.encode()),
                            (b"content-length", str(len(body)).encode())] + extra})
    await send({"type": "http.response.body", "body": b"" if head_only else body})


async def _plain(send: Send, status: int, text: str,
                 extra: list[tuple[bytes, bytes]] | None = None) -> None:
    await _respond(send, status, (text + "\n").encode(), "text/plain; charset=utf-8", extra or [])


# ------------------------------------------------------------------------------------------- #
# Assembly
# ------------------------------------------------------------------------------------------- #

def build_app(log_path: Path | str = DEFAULT_LOG, *, public_host: str | None = None,
              trust_cf_header: bool = False, extra_origins: list[str] | None = None,
              limiter: RateLimiter | None = None) -> Observatory:
    log = ObservationLog(Path(log_path))
    allowed_hosts = ["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"]
    if public_host:
        allowed_hosts.append(public_host)
    origins = ["http://127.0.0.1:*", "http://localhost:*", "https://claude.ai",
               "https://claude.com"] + (extra_origins or [])
    if public_host:
        origins.append(f"https://{public_host}")
    mcp_app = build_mcp(log).streamable_http_app(
        streamable_http_path="/mcp",
        max_request_body_size=MAX_BODY,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=origins,
        ),
        host="127.0.0.1",
    )
    return Observatory(mcp_app, log, allowed_hosts=allowed_hosts, public_host=public_host,
                       trust_cf_header=trust_cf_header, limiter=limiter)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=int(os.environ.get("OBS_PORT", DEFAULT_PORT)))
    parser.add_argument("--log", default=os.environ.get("OBS_LOG", str(DEFAULT_LOG)))
    args = parser.parse_args()

    import uvicorn

    public_host = os.environ.get("OBS_PUBLIC_HOST") or None
    extra = [o for o in os.environ.get("OBS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    app = build_app(args.log, public_host=public_host,
                    trust_cf_header=os.environ.get("OBS_TRUST_CF") == "1", extra_origins=extra)
    print(f"observatory: http://127.0.0.1:{args.port}/observatory  (log: {args.log})")
    # Loopback only, by construction: there is no flag to change it.
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning",
                proxy_headers=False, server_header=False)


if __name__ == "__main__":
    main()
