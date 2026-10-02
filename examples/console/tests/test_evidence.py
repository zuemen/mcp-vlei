"""The evidence panel's data: the gateway's decision log, reduced to what may be shown."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CONSOLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONSOLE))

import evidence  # noqa: E402
from test_interactive import _client, _load  # noqa: E402

from mcp_vlei.chain import VLEI_SCHEMAS  # noqa: E402

RECORD = {
    "at": "2026-10-01T06:59:06+00:00", "decision": "deny", "tool": "enroll_employee",
    "layer": "missing_credential", "message": "no credential", "via": "public", "wire": "grpc",
    "metaKeys": [], "argumentNames": ["person_ref", "salary_grade", "start_date"],
    "schemas": [{"said": "E1", "schema": VLEI_SCHEMAS["ECR"], "type": "ECR", "extra": "x"}],
    "witnessReads": [{"typ": "kel", "aid": "EA", "witness": "witness-demo:5642", "status": 200,
                      "ms": 3.1, "events": 4, "anchors": [["E1", "0"]], "body": "KEL BYTES"}],
    "report": {"allowed": False, "layer": "missing_credential", "totalMs": 1.2, "tool": "enroll_employee",
               "identity": {"lei": "984500DEMOSTAFF00178", "secret": "s"},
               "checks": [{"name": "credential_present", "label": "a credential", "passed": False,
                           "skipped": False, "layer": "missing_credential", "detail": "none",
                           "durationMs": 0.1, "key": "k"}]},
    # Never written by vlei-authz; dropped here if anything ever does write them.
    "credential": "{\"v\":\"ACDC...\"}", "arguments": {"person_ref": "EMP-0001"}, "signature": "0B...",
}


def test_a_record_keeps_only_what_may_be_shown():
    shown = evidence.sanitize(RECORD)
    text = json.dumps(shown)
    for never in ("ACDC", "EMP-0001", "0B...", "KEL BYTES", "\"secret\"", "\"key\"", "\"extra\""):
        assert never not in text, never
    assert shown["argumentNames"] == ["person_ref", "salary_grade", "start_date"]
    assert shown["report"]["checks"][0]["name"] == "credential_present"
    assert shown["report"]["identity"] == {"lei": "984500DEMOSTAFF00178"}
    assert shown["witnessReads"][0]["anchors"] == [["E1", "0"]]
    assert shown["schemas"][0] == {"said": "E1", "schema": VLEI_SCHEMAS["ECR"], "type": "ECR",
                                   "official": True}


def test_a_schema_outside_the_published_set_is_not_official():
    record = {**RECORD, "schemas": [{"said": "E2", "schema": "EForgedSchemaSaid", "type": None}]}
    assert evidence.sanitize(record)["schemas"][0]["official"] is False


def test_the_newest_records_come_first_and_broken_lines_are_skipped(tmp_path):
    log = tmp_path / "decisions.jsonl"
    lines = [json.dumps({**RECORD, "at": f"2026-10-01T07:00:0{i}+00:00", "tool": f"t{i}"}) for i in range(3)]
    log.write_text("\n".join([lines[0], "{not json", lines[1], lines[2]]) + "\n", encoding="utf-8")
    shown = evidence.read_evidence(log, limit=2)
    assert [r["tool"] for r in shown] == ["t2", "t1"]
    assert evidence.read_evidence(tmp_path / "missing.jsonl") == []


async def test_the_page_serves_the_log_and_the_official_schemas(tmp_path, monkeypatch):
    log = tmp_path / "decisions.jsonl"
    log.write_text(json.dumps(RECORD) + "\n", encoding="utf-8")
    monkeypatch.setenv("VLEI_AUDIT_FILE", str(log))
    module = _load()
    async with _client(module) as client:
        data = (await client.get("/api/evidence")).json()
        page = await client.get("/evidence")
        script = await client.get("/app/evidence.js")
    assert [r["tool"] for r in data["records"]] == ["enroll_employee"]
    assert {s["type"]: s["said"] for s in data["officialSchemas"]}["ECR"] == VLEI_SCHEMAS["ECR"]
    assert "ACDC" not in json.dumps(data)
    assert page.status_code == 200 and "evidence.js" in page.text
    assert script.status_code == 200
