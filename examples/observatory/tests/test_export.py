"""Evidence export: only whitelisted fields, and nothing leaves if anything forbidden is present."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import export_evidence  # noqa: E402
from observations import ObservationLog  # noqa: E402
from test_observatory import _record  # noqa: E402

PICKS = ["claude.ai=real:2026-09-29T04:10:48.9", "replay=replay:2026-09-29T04:13:30.7",
         "claude-code=real:2026-09-29T04:17:30"]


@pytest.fixture()
def log(tmp_path):
    log = ObservationLog(tmp_path / "o.jsonl")
    for record in (_record("2026-09-29T04:10:48.905Z", "Anthropic/ClaudeAI"),
                   _record("2026-09-29T04:13:30.707Z", "Anthropic/ClaudeAI", run="replay",
                           ua="python-httpx2/2.13.0"),
                   _record("2026-09-29T04:17:30.387Z", "claude-code", method="server/discover")):
        log.append(dict(record, session="ab12cd34"))
    return log


def test_the_three_records_are_exported_with_only_the_listed_fields(log, tmp_path):
    out = tmp_path / "evidence.json"
    assert export_evidence.main(["--log", str(log.path), "--out", str(out), *sum(
        (["--pick", p] for p in PICKS), [])]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert [r["label"] for r in doc["records"]] == ["claude.ai", "replay", "claude-code"]
    assert [r["ts"] for r in doc["records"]] == ["2026-09-29T04:10:48.905Z",
                                                 "2026-09-29T04:13:30.707Z",
                                                 "2026-09-29T04:17:30.387Z"]
    for record in doc["records"]:
        assert set(record) <= set(export_evidence.FIELDS) | {"label", "side", "selector"}
        assert "session" not in record
        assert isinstance(record["headers"]["authorizationPresent"], bool)
    assert doc["records"][0]["clientInfo"] == doc["records"][1]["clientInfo"]


@pytest.mark.parametrize("poison", [
    {"headers": {"userAgent": "x", "authorization": "Bearer abc.def.ghi"}},   # a value, not a flag
    {"clientInfo": {"name": "203.0.113.7", "version": "1"}},                    # an IPv4 address
    {"clientInfo": {"name": "2001:db8:0:1::7", "version": "1"}},                # an IPv6 address
    {"clientInfo": {"name": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "version": "1"}},  # a JWT
    {"arguments": {"q": "hello"}},                                              # conversation
    {"messages": [{"role": "user", "content": "hi"}]},
    {"cf-connecting-ip": "198.51.100.2"},
    {"clientInfo": {"name": "proxy 203.0.113.7:443", "version": "1"}},          # with a port
    {"clientInfo": {"name": "via [2001:db8::1]:8443", "version": "1"}},
])
def test_anything_forbidden_stops_the_export_and_is_reported(log, tmp_path, poison, capsys):
    bad = ObservationLog(tmp_path / "bad.jsonl")
    for record in reversed(list(log.newest_first())):
        bad.append({**record, **poison} if record["ts"].startswith("2026-09-29T04:10") else record)
    out = tmp_path / "evidence.json"
    code = export_evidence.main(["--log", str(bad.path), "--out", str(out), *sum(
        (["--pick", p] for p in PICKS), [])])
    assert code == 1
    assert not out.exists()
    assert "stopped" in capsys.readouterr().out


def test_a_pick_that_matches_nothing_stops_the_export(log, tmp_path, capsys):
    out = tmp_path / "evidence.json"
    code = export_evidence.main(["--log", str(log.path), "--out", str(out),
                                 "--pick", "nobody=real:2026-09-29T09"])
    assert code == 1 and not out.exists()
    assert "matches no" in capsys.readouterr().out
