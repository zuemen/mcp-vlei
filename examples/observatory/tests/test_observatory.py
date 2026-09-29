"""The observatory's acceptance, locally.

The headline test: two clients, one the SDK standing in for a real client and one the replay
script, send the same `clientInfo`; the comparison says *same* for it — and reports every field
that differs rather than hiding it.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
from pathlib import Path

import httpx2
import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import page  # noqa: E402
import replay_client  # noqa: E402
import server  # noqa: E402
from observations import ObservationLog, compare, summary, transport_records  # noqa: E402

CLAIM = {"name": "Claude", "version": "1.2.3"}


# ------------------------------------------------------------------------------------------- #
# A real server on a real port
# ------------------------------------------------------------------------------------------- #

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def running(tmp_path):
    import uvicorn

    log_path = tmp_path / "obs.jsonl"
    port = _free_port()
    app = server.build_app(log_path)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started, "server did not start"
    yield f"http://127.0.0.1:{port}", ObservationLog(log_path)
    srv.should_exit = True
    thread.join(timeout=10)


async def _call_as(url: str, claim: dict, mode: str = "legacy", headers: dict | None = None):
    from mcp.client.client import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client
    from mcp.types import Implementation

    http = create_mcp_http_client(headers=headers or {})
    async with http:
        async with Client(streamable_http_client(url + "/mcp", http_client=http),
                          client_info=Implementation(**claim), mode=mode) as client:
            tools = await client.list_tools()
            result = await client.call_tool("echo_identity", {})
    return tools, result


# ------------------------------------------------------------------------------------------- #
# Acceptance
# ------------------------------------------------------------------------------------------- #

def test_replay_is_indistinguishable_on_client_info(running):
    url, log = running
    asyncio.run(_call_as(url, CLAIM))                       # stands in for the real client

    real = replay_client.last_real(log.path, None)
    assert real["clientInfo"] == CLAIM
    payload = asyncio.run(replay_client.replay(url + "/mcp", real))
    assert payload["asReceived"]["clientInfo"] == CLAIM   # what the server says it saw

    s = summary(log)
    assert s["real"]["run"] is None and s["replay"]["run"] == "replay"
    rows = {r["key"]: r for r in s["rows"]}
    assert rows["clientInfo"]["verdict"] == "same"
    assert rows["clientInfo"]["real"] == rows["clientInfo"]["replay"] == CLAIM
    # Every compared field is present — including any that differ.
    assert [r["key"] for r in s["rows"]] == [k for k, _ in __import__("observations").ROWS]
    assert rows["protocolClientInfo"]["verdict"] == "same"
    assert rows["era"]["real"] == rows["era"]["replay"] == "legacy"


def test_both_layers_are_recorded(running):
    url, log = running
    asyncio.run(_call_as(url, CLAIM))
    records = list(log.newest_first())
    layers = {r["layer"] for r in records}
    assert layers == {"transport", "protocol"}
    protocol = next(r for r in records if r["layer"] == "protocol")
    assert protocol["clientInfo"] == CLAIM
    init = next(r for r in records if r["method"] == "initialize")
    assert init["era"] == "legacy" and init["clientInfo"] == CLAIM


def test_modern_envelope_is_recorded_and_replayed_in_the_same_era(running):
    url, log = running
    asyncio.run(_call_as(url, CLAIM, mode="2026-07-28"))
    modern = [r for r in log.newest_first() if r.get("era") == "modern"]
    assert modern and modern[0]["clientInfo"] == CLAIM
    assert modern[0]["protocolVersion"] == "2026-07-28"

    real = replay_client.last_real(log.path, None)
    assert replay_client._mode(real) == "2026-07-28"
    asyncio.run(replay_client.replay(url + "/mcp", real))
    rows = {r["key"]: r for r in summary(log)["rows"]}
    for key in ("clientInfo", "protocolVersion", "era", "protocolClientInfo"):
        assert rows[key]["verdict"] == "same", key


def test_only_two_read_only_tools(running):
    url, _ = running
    tools, _ = asyncio.run(_call_as(url, CLAIM))
    names = sorted(t.name for t in tools.tools)
    assert names == ["echo_identity", "ping"]
    for tool in tools.tools:
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False


def test_authorization_value_and_arguments_never_reach_the_log(running):
    url, log = running
    secret = "Bearer sk-live-DO-NOT-LOG-0123456789"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo_identity", "arguments": {"note": "private conversation"}}}
    httpx2.post(url + "/mcp", json=body,
                headers={"Authorization": secret, "Accept": "application/json, text/event-stream"})
    raw = log.path.read_text(encoding="utf-8")
    assert "sk-live" not in raw and "private conversation" not in raw
    record = next(log.newest_first())
    assert record["headers"]["authorization"] is True
    assert record["tool"] == "echo_identity"


# ------------------------------------------------------------------------------------------- #
# Surface: nothing writable, limits hold
# ------------------------------------------------------------------------------------------- #

def test_surface_is_read_only(running):
    url, _ = running
    assert httpx2.get(url + "/observatory").status_code == 200
    assert httpx2.get(url + "/observatory.json").status_code == 200
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        assert httpx2.request(m, url + "/observatory").status_code == 405
        assert httpx2.request(m, url + "/observatory.json").status_code == 405
    assert httpx2.request("PUT", url + "/mcp").status_code == 405
    assert httpx2.request("PATCH", url + "/mcp").status_code == 405
    for path in ("/admin", "/log", "/data/observations.jsonl", "/.env", "/mcp/../server.py"):
        assert httpx2.get(url + path).status_code in (404, 421)


def test_body_over_64kb_is_refused(running):
    url, log = running
    big = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * 70_000}}
    r = httpx2.post(url + "/mcp", json=big, headers={"Accept": "application/json"})
    assert r.status_code == 413
    assert not log.path.exists() or "x" * 1000 not in log.path.read_text(encoding="utf-8")


def test_unknown_host_is_refused(running):
    url, _ = running
    r = httpx2.get(url + "/observatory", headers={"Host": "evil.example"})
    assert r.status_code == 421


def test_rate_limit():
    now = [0.0]
    limiter = server.RateLimiter(per_minute=60, clock=lambda: now[0])
    assert all(limiter.allow("a") for _ in range(60))
    assert limiter.allow("a") is False
    assert limiter.allow("b") is True
    now[0] = 60.0
    assert limiter.allow("a") is True


def test_rate_limit_answers_429(tmp_path):
    import uvicorn

    port = _free_port()
    app = server.build_app(tmp_path / "o.jsonl", limiter=server.RateLimiter(per_minute=3))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    while not srv.started:
        time.sleep(0.05)
    try:
        codes = [httpx2.get(f"http://127.0.0.1:{port}/observatory").status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
    finally:
        srv.should_exit = True
        t.join(timeout=10)


# ------------------------------------------------------------------------------------------- #
# Units
# ------------------------------------------------------------------------------------------- #

def test_page_escapes_client_supplied_values(tmp_path):
    log = ObservationLog(tmp_path / "o.jsonl")
    hostile = {"name": "<script>alert(1)</script>", "version": "1",
               "websiteUrl": "javascript:alert(1)",
               "icons": [{"src": "data:text/html,<img src=x onerror=alert(1)>"}]}
    for record in transport_records(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": hostile}}).encode(), {"host": "x"}):
        log.append(record)
    html = page.render(summary(log))
    assert "<script>alert" not in html
    assert "<img" not in html
    assert 'href="javascript' not in html
    assert "&lt;script&gt;" in html
    assert "script-src" not in page.CSP and "default-src 'none'" in page.CSP


def test_oversized_claims_are_clipped():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"clientInfo": {"name": "A" * 200_000, "version": "1"}}}).encode()
    (record,) = transport_records(body, {})
    assert len(record["clientInfo"]["name"]) <= 301
    assert record["truncated"] is True


def test_client_replies_and_bad_json_are_handled():
    assert transport_records(b'{"jsonrpc":"2.0","id":3,"result":{}}', {}) == []
    (odd,) = transport_records(b"not json", {})
    assert odd["method"] is None


def test_run_marker_is_sanitised():
    (r,) = transport_records(b'{"jsonrpc":"2.0","method":"ping","id":1}',
                             {"x-observatory-run": "<b>Replay</b>"})
    assert r["run"] == "breplayb"
    (r,) = transport_records(b'{"jsonrpc":"2.0","method":"ping","id":1}',
                             {"x-observatory-run": "replay"})
    assert r["run"] == "replay"


def test_log_rotates(tmp_path):
    log = ObservationLog(tmp_path / "o.jsonl", max_bytes=400, backups=2)
    for i in range(40):
        log.append({"i": i, "pad": "y" * 50})
    assert (tmp_path / "o.jsonl.1").exists() and (tmp_path / "o.jsonl.2").exists()
    assert not (tmp_path / "o.jsonl.3").exists()
    assert (tmp_path / "o.jsonl").stat().st_size <= 400
    assert next(log.newest_first())["i"] == 39


def test_compare_marks_differences_and_hides_none():
    real = {"clientInfo": CLAIM, "protocolVersion": "2025-11-25", "capabilities": {},
            "era": "legacy", "headers": {"userAgent": "claude-user", "mcpProtocolVersion": None,
                                         "origin": None, "authorization": False}}
    replay = dict(real, headers=dict(real["headers"], userAgent="python-httpx/1.0"))
    rows = {r["key"]: r["verdict"] for r in compare(real, replay)}
    assert rows["clientInfo"] == "same"
    assert rows["userAgent"] == "different"
    assert len(rows) == 9
    assert {r["verdict"] for r in compare(real, None)} == {"pending"}


# ------------------------------------------------------------------------------------------- #
# A comparison that stays put: records named by timestamp
# ------------------------------------------------------------------------------------------- #

def _record(ts: str, name: str, *, run: str | None = None, layer: str = "transport",
            method: str = "tools/call", ua: str = "Claude-User") -> dict:
    return {"ts": ts, "layer": layer, "run": run, "session": None, "method": method,
            "era": "modern", "protocolVersion": "2026-07-28",
            "clientInfo": {"name": name, "version": "1.0.0"}, "capabilities": {},
            "headers": {"userAgent": ua, "mcpProtocolVersion": "2026-07-28", "origin": None,
                        "authorization": False},
            "truncated": False}


@pytest.fixture()
def experiment(tmp_path):
    """The shape of 2026-09-29: claude.ai at 04:10, the replay at 04:13, claude-code at 04:17."""
    log = ObservationLog(tmp_path / "o.jsonl")
    for record in (
        _record("2026-09-29T04:10:48.905Z", "Anthropic/ClaudeAI"),
        _record("2026-09-29T04:10:48.949Z", "Anthropic/ClaudeAI", layer="protocol"),
        _record("2026-09-29T04:13:30.707Z", "Anthropic/ClaudeAI", run="replay", ua="python-httpx2/2.13.0"),
        _record("2026-09-29T04:13:30.723Z", "Anthropic/ClaudeAI", run="replay", layer="protocol",
                ua="python-httpx2/2.13.0"),
        _record("2026-09-29T04:17:30.387Z", "claude-code", method="server/discover"),
        _record("2026-09-29T04:17:31.997Z", "claude-code", method="tools/list"),
    ):
        log.append(record)
    return log


def test_without_parameters_the_newest_pair_is_compared(experiment):
    s = summary(experiment)
    assert s["real"]["clientInfo"]["name"] == "claude-code"
    assert s["selected"] == {"real": None, "replay": None}


def test_a_timestamp_or_its_prefix_pins_each_side(experiment):
    s = summary(experiment, real="2026-09-29T04:10", replay="2026-09-29T04:13:30.707Z")
    assert s["real"]["ts"] == "2026-09-29T04:10:48.905Z"        # transport preferred
    assert s["replay"]["ts"] == "2026-09-29T04:13:30.707Z"
    assert s["selected"] == {"real": "2026-09-29T04:10", "replay": "2026-09-29T04:13:30.707Z"}
    rows = {r["key"]: r for r in s["rows"]}
    assert rows["clientInfo"]["verdict"] == "same"
    assert rows["userAgent"]["verdict"] == "different"
    # The tool row is the same request's protocol record, not the newest one on that side.
    assert rows["protocolClientInfo"]["real"] == {"name": "Anthropic/ClaudeAI", "version": "1.0.0"}


def test_a_selector_that_matches_nothing_never_falls_back_to_the_newest(experiment):
    s = summary(experiment, real="2026-09-29T05")
    assert s["real"] is None
    assert {r["verdict"] for r in s["rows"]} == {"pending"}
    html = page.render(s)
    assert "No real-client record matches" in html and "2026-09-29T05" in html


def test_a_selector_names_only_its_own_side(experiment):
    """A replay's timestamp given as ?real= matches nothing: the sides never swap."""
    assert summary(experiment, real="2026-09-29T04:13")["real"] is None


@pytest.mark.parametrize("bad", ["<script>", "04:10", "2026-09-29T04:10'", "x" * 50, ""])
def test_only_timestamps_are_selectors(bad):
    from observations import valid_selector

    assert not valid_selector(bad)


def test_the_page_says_which_two_records_it_compares_and_when(experiment):
    html = page.render(summary(experiment, real="2026-09-29T04:10", replay="2026-09-29T04:13"))
    assert "2026-09-29T04:10:48.905Z" in html and "2026-09-29T04:13:30.707Z" in html
    assert "12:10:48" in html and "12:13:30" in html                  # Taipei time, beside UTC
    assert "?real=2026-09-29T04:10" in html                            # how it was pinned


def test_every_real_client_is_listed_once_with_its_newest_record(experiment):
    s = summary(experiment)
    names = [c["name"] for c in s["clients"]]
    assert names == ["claude-code", "Anthropic/ClaudeAI"]              # newest first; no replay
    code = s["clients"][0]
    assert code["ts"] == "2026-09-29T04:17:31.997Z" and code["userAgent"] == "Claude-User"
    assert code["protocolVersion"] == "2026-07-28"
    assert "name, version" in s["clientsNote"]
    assert "legal entity" in s["clientsNote"] and "法人" in s["clientsNote"]
    html = page.render(s)
    assert "All real clients" in html and "claude-code" in html


def test_the_server_pins_by_query_and_refuses_anything_else(running):
    url, log = running
    for record in (_record("2026-09-29T04:10:48.905Z", "Anthropic/ClaudeAI"),
                   _record("2026-09-29T04:13:30.707Z", "Anthropic/ClaudeAI", run="replay"),
                   _record("2026-09-29T04:17:30.387Z", "claude-code")):
        log.append(record)
    data = httpx2.get(url + "/observatory.json?real=2026-09-29T04:10&replay=2026-09-29T04:13").json()
    assert data["real"]["ts"] == "2026-09-29T04:10:48.905Z"
    page_ = httpx2.get(url + "/observatory?real=2026-09-29T04:10&replay=2026-09-29T04:13")
    assert page_.status_code == 200 and "2026-09-29T04:10:48.905Z" in page_.text
    assert httpx2.get(url + "/observatory?real=%3Cscript%3E").status_code == 400
    assert "claude-code" in httpx2.get(url + "/observatory").text     # no parameters: the newest

