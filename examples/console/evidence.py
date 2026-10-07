"""The evidence panel's data: the gateway's own decision log, reduced to what may be shown.

vlei-authz writes one JSON line per decision (deploy/agentgateway/audit/decisions.jsonl), whichever
client sent the call — claude.ai through the public tunnel, Claude Desktop or Claude Code through
the credential proxy, or this console. Each line holds:

- the tool, and the decision and its layer;
- which keys the call's ``_meta`` carried, and the argument names;
- every check with its detail;
- whose key event logs were read, and the anchors in them that decide revocation;
- the schemas of the presented chain.

Nothing here can show a credential, a key or an argument's value. vlei-authz does not write them,
and every field is passed through an allow-list, so anything else that ever appears in the log is
dropped here rather than sent to a browser.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp_vlei.chain import VLEI_SCHEMAS

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG = ROOT / "deploy" / "agentgateway" / "audit" / "decisions.jsonl"
#: Where the schema SAIDs come from: GLEIF's published vLEI schemas.
SCHEMA_SOURCE = "https://github.com/WebOfTrust/vLEI/tree/main/schema/acdc"

RECORD_FIELDS = ("at", "decision", "tool", "layer", "message", "via", "wire", "metaKeys",
                 "argumentNames", "revocationChecked", "lei", "role", "holderAid", "delegateAid",
                 "credentialSaid", "note", "declaredClient")
REPORT_FIELDS = ("allowed", "layer", "totalMs", "tool", "caveats")
IDENTITY_FIELDS = ("lei", "role", "holderAid", "delegateAid", "credentialSaid", "rootAid")
CHECK_FIELDS = ("name", "label", "passed", "skipped", "layer", "detail", "durationMs")
READ_FIELDS = ("typ", "witness", "status", "ms", "aid", "said", "state", "events", "anchors")
SCHEMA_FIELDS = ("said", "schema", "type")

_OFFICIAL = {said: name for name, said in VLEI_SCHEMAS.items()}


def log_path() -> Path:
    return Path(os.environ.get("VLEI_AUDIT_FILE", "").strip() or DEFAULT_LOG)


def official_schemas() -> list[dict[str, str]]:
    return [{"type": name, "said": said, "source": SCHEMA_SOURCE} for name, said in VLEI_SCHEMAS.items()]


def _pick(source: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: source[k] for k in fields if isinstance(source, dict) and k in source}


def _list(source: Any, limit: int) -> list[Any]:
    return source[:limit] if isinstance(source, list) else []


def sanitize(record: dict[str, Any]) -> dict[str, Any]:
    """One decision, with only the fields the panel shows."""
    shown = _pick(record, RECORD_FIELDS)
    report = record.get("report")
    if isinstance(report, dict):
        shown["report"] = {
            **_pick(report, REPORT_FIELDS),
            "identity": _pick(report.get("identity"), IDENTITY_FIELDS),
            "checks": [_pick(c, CHECK_FIELDS) for c in _list(report.get("checks"), 12)],
        }
    shown["witnessReads"] = [_pick(r, READ_FIELDS) for r in _list(record.get("witnessReads"), 40)]
    shown["schemas"] = [
        {**_pick(s, SCHEMA_FIELDS), "official": isinstance(s, dict) and s.get("schema") in _OFFICIAL}
        for s in _list(record.get("schemas"), 8)
    ]
    return shown


def read_evidence(path: Path | None = None, limit: int = 40) -> list[dict[str, Any]]:
    """The newest ``limit`` decisions, newest first. A missing log is no decisions yet."""
    path = path or log_path()
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 2_000_000))
            tail = handle.read().decode("utf-8", "replace")
    except OSError:
        return []
    shown: list[dict[str, Any]] = []
    for line in reversed(tail.splitlines()):
        try:
            record = json.loads(line)
        except ValueError:
            continue  # a partial first line of the tail, or a broken one
        if isinstance(record, dict):
            shown.append(sanitize(record))
        if len(shown) >= limit:
            break
    return shown
