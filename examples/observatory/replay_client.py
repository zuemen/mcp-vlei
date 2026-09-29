"""Replay the last real client's identity against the observatory, then show what it recorded.

Reads the newest record in the observatory's log that carries `clientInfo` and has no
`X-Observatory-Run` header — the real client — and connects to the same server with that exact
`clientInfo`, through the SDK's own Streamable HTTP client.

The replay is *not* marked by changing any identity field: a renamed replay would not be a replay.
It is marked by one HTTP header, `X-Observatory-Run: replay`, which is not part of MCP's identity
fields and exists only so `/observatory` can put the two records in separate columns.

    python examples/observatory/replay_client.py --url https://mcp.zuemen.net/mcp
    python examples/observatory/replay_client.py --url http://127.0.0.1:8765/mcp

The log is local (`data/observations.jsonl`, next to the server). To replay against a server whose
log you cannot read, pass `--from-page https://…/observatory.json`, which reads the same record
from the server's read-only summary.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from observations import ObservationLog, latest_identity  # noqa: E402

DEFAULT_LOG = HERE / "data" / "observations.jsonl"


def last_real(log_path: Path | None, page_url: str | None) -> dict[str, Any] | None:
    if page_url:
        import httpx2

        response = httpx2.get(page_url, timeout=15)
        response.raise_for_status()
        return response.json().get("real")
    return latest_identity(ObservationLog(log_path or DEFAULT_LOG).newest_first(), replay=False)


def _mode(record: dict[str, Any]) -> str:
    """Speak the same era the real client spoke: a 2026-07-28 envelope pins that version;
    otherwise the legacy initialize handshake."""
    version = record.get("protocolVersion")
    if record.get("era") == "modern" and isinstance(version, str):
        return version
    return "legacy"


async def replay(url: str, record: dict[str, Any], user_agent: str | None = None) -> dict[str, Any]:
    from mcp.client.client import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client
    from mcp.types import Implementation

    headers = {"X-Observatory-Run": "replay"}
    if user_agent:
        headers["User-Agent"] = user_agent

    client_info = Implementation.model_validate(record["clientInfo"])
    http = create_mcp_http_client(headers=headers)
    async with http:
        transport = streamable_http_client(url, http_client=http)
        async with Client(transport, client_info=client_info, mode=_mode(record)) as client:
            result = await client.call_tool("echo_identity", {})
    payload = getattr(result, "structured_content", None)
    if not isinstance(payload, dict):
        for item in getattr(result, "content", []) or []:
            text = getattr(item, "text", None)
            if text:
                payload = json.loads(text)
                break
    return payload or {}


def _line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(", ", ": "))


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay the last real client's clientInfo.")
    parser.add_argument("--url", required=True, help="the observatory's /mcp endpoint")
    parser.add_argument("--log", type=Path, default=None, help=f"default: {DEFAULT_LOG}")
    parser.add_argument("--from-page", default=None,
                        help="read the real record from a /observatory.json URL instead of the log")
    parser.add_argument("--match-user-agent", action="store_true",
                        help="also send the real client's User-Agent (itself only a string)")
    args = parser.parse_args()

    record = last_real(args.log, args.from_page)
    if record is None:
        sys.exit("No real client has been recorded yet. Connect one first, then replay.")

    ua = (record.get("headers") or {}).get("userAgent") if args.match_user_agent else None
    payload = asyncio.run(replay(args.url, record, ua))
    seen = (payload.get("asReceived") or {}).get("clientInfo")

    print(f"replaying clientInfo : {_line(record['clientInfo'])}")
    print(f"server recorded      : {_line(seen)}")


if __name__ == "__main__":
    main()
