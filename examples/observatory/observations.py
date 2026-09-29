"""What the observatory records, where it keeps it, and how two records are compared.

Shared by `server.py` (writes), `replay_client.py` (reads the last real client) and the console's
scene 0 (reads the pair). One module, so the three can never disagree about what a field means.

What is recorded, and nothing else:

* the JSON-RPC `method` of each message, and for `tools/call` which of this server's two tools;
* `initialize` params: `protocolVersion`, `clientInfo`, `capabilities` (the legacy handshake);
* the three identity keys of `params._meta` in the 2026-07-28 envelope;
* four HTTP headers — `User-Agent`, `MCP-Protocol-Version`, `Origin` — and whether an
  `Authorization` header was present (never its value);
* `X-Observatory-Run`, the replay marker;
* a short hash of `Mcp-Session-Id`, so an `initialize` can be matched to the call that followed.

Never recorded: tool arguments, any other `_meta` key, message bodies, IP addresses, tokens.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY as CAPABILITIES_KEY,
    CLIENT_INFO_META_KEY as CLIENT_INFO_KEY,
    PROTOCOL_VERSION_META_KEY as PROTOCOL_VERSION_KEY,
)

RUN_HEADER = "x-observatory-run"
MODERN_FROM = "2026-07-28"
KNOWN_TOOLS = frozenset({"echo_identity", "ping"})

MAX_LOG_BYTES = 10 * 1024 * 1024
LOG_BACKUPS = 3

#: Self-reported strings can be anything — the impersonation example accepted a 200,000-character
#: name. Everything recorded is clipped so one request cannot fill the log or the page.
_MAX_STR = 300
_MAX_KEYS = 40
_MAX_ITEMS = 20
_MAX_DEPTH = 6

FOOTER = (
    "On clientInfo, the server cannot tell the replay from the real client. "
    "Fields that differ — such as User-Agent — are also self-reported and carry no proof. "
    "Neither says which legal entity is acting, which agent, or what it is authorised to do."
)

#: A record is named by its `ts`, or by any prefix of it down to the month:
#: `2026-09-29T04:10:48.905Z`, `2026-09-29T04:10`. Nothing else, so a query string that names a
#: record cannot carry anything else onto the page.
_SELECTOR = re.compile(r"[0-9]{4}-[0-9]{2}(-[0-9]{2}(T[0-9]{2}(:[0-9]{2}(:[0-9]{2}(\.[0-9]{1,3})?)?)?Z?)?)?")


# ------------------------------------------------------------------------------------------- #
# Clipping
# ------------------------------------------------------------------------------------------- #

class _Clip:
    def __init__(self) -> None:
        self.truncated = False

    def value(self, v: Any, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            self.truncated = True
            return None
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
            return v
        if isinstance(v, Mapping):
            out: dict[str, Any] = {}
            for i, (k, item) in enumerate(v.items()):
                if i >= _MAX_KEYS:
                    self.truncated = True
                    break
                out[self.text(str(k), 100)] = self.value(item, depth + 1)
            return out
        if isinstance(v, (list, tuple)):
            if len(v) > _MAX_ITEMS:
                self.truncated = True
            return [self.value(item, depth + 1) for item in list(v)[:_MAX_ITEMS]]
        return self.text(repr(v))

    def text(self, s: str, limit: int = _MAX_STR) -> str:
        if len(s) > limit:
            self.truncated = True
            return s[:limit] + "…"
        return s


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run_marker(raw: str | None) -> str | None:
    """`X-Observatory-Run`, reduced to something safe to store and show."""
    if raw is None:
        return None
    cleaned = re.sub(r"[^a-z0-9-]", "", raw.strip().lower())[:32]
    return cleaned or "other"


def session_hash(session_id: str | None) -> str | None:
    """A session id is a bearer handle for that session; store only enough to correlate."""
    if not session_id:
        return None
    return hashlib.sha256(session_id.encode()).hexdigest()[:8]


def header_fields(headers: Mapping[str, str], clip: _Clip) -> dict[str, Any]:
    """The four headers the page compares. `headers` must be keyed in lower case."""
    def get(name: str, limit: int) -> str | None:
        v = headers.get(name)
        return clip.text(v, limit) if v is not None else None

    return {
        "userAgent": get("user-agent", _MAX_STR),
        "mcpProtocolVersion": get("mcp-protocol-version", 40),
        "origin": get("origin", 200),
        "authorization": "authorization" in headers,
    }


# ------------------------------------------------------------------------------------------- #
# Extraction
# ------------------------------------------------------------------------------------------- #

def transport_records(body: bytes, headers: Mapping[str, str]) -> list[dict[str, Any]]:
    """One record per JSON-RPC request or notification in a POST body.

    `headers` keyed in lower case. A body that is not JSON-RPC still yields one record, with
    `method` null, so an odd request is visible rather than silently absent.
    """
    try:
        parsed = json.loads(body) if body else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    messages: list[Any] = parsed if isinstance(parsed, list) else [parsed]

    records = []
    for msg in messages[:_MAX_ITEMS]:
        if isinstance(msg, Mapping) and "method" not in msg and ("result" in msg or "error" in msg):
            continue  # a client's reply to a server request: carries no identity
        clip = _Clip()
        record: dict[str, Any] = {
            "ts": _now(),
            "layer": "transport",
            "run": run_marker(headers.get(RUN_HEADER)),
            "session": session_hash(headers.get("mcp-session-id")),
            "method": None,
            "era": None,
            "protocolVersion": None,
            "clientInfo": None,
            "capabilities": None,
        }
        if isinstance(msg, Mapping) and isinstance(msg.get("method"), str):
            method = msg["method"]
            record["method"] = clip.text(method, 80)
            params = msg.get("params") if isinstance(msg.get("params"), Mapping) else {}
            meta = params.get("_meta") if isinstance(params.get("_meta"), Mapping) else {}
            if method == "initialize":
                record["era"] = "legacy"
                record["protocolVersion"] = clip.value(params.get("protocolVersion"))
                record["clientInfo"] = clip.value(params.get("clientInfo"))
                record["capabilities"] = clip.value(params.get("capabilities"))
            elif PROTOCOL_VERSION_KEY in meta:
                record["era"] = "modern"
                record["protocolVersion"] = clip.value(meta.get(PROTOCOL_VERSION_KEY))
                record["clientInfo"] = clip.value(meta.get(CLIENT_INFO_KEY))
                record["capabilities"] = clip.value(meta.get(CAPABILITIES_KEY))
            if method == "tools/call":
                name = params.get("name")
                record["tool"] = name if name in KNOWN_TOOLS else "other"
        record["headers"] = header_fields(headers, clip)
        record["truncated"] = clip.truncated
        records.append(record)
    return records


def protocol_record(
    client_params: Any,
    negotiated_version: str | None,
    headers: Mapping[str, str] | None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """What the SDK hands a tool: `ctx.session.client_params`, after its own parsing."""
    clip = _Clip()
    lowered = {k.lower(): v for k, v in (headers or {}).items()}

    def dump(v: Any) -> Any:
        if v is None:
            return None
        if hasattr(v, "model_dump"):
            v = v.model_dump(by_alias=True, exclude_none=True, mode="json")
        return clip.value(v)

    return {
        "ts": _now(),
        "layer": "protocol",
        "run": run_marker(lowered.get(RUN_HEADER)),
        "session": session_hash(session_id or lowered.get("mcp-session-id")),
        "method": "tools/call",
        "tool": "echo_identity",
        # Dated version strings order lexically; 2026-07-28 is the first per-request era.
        "era": (None if not isinstance(negotiated_version, str)
                else "modern" if negotiated_version >= MODERN_FROM else "legacy"),
        "protocolVersion": clip.value(
            getattr(client_params, "protocol_version", None) or negotiated_version
        ),
        "negotiatedVersion": clip.value(negotiated_version),
        "clientInfo": dump(getattr(client_params, "client_info", None)),
        "capabilities": dump(getattr(client_params, "capabilities", None)),
        "headers": header_fields(lowered, clip),
        "truncated": clip.truncated,
    }


# ------------------------------------------------------------------------------------------- #
# Storage
# ------------------------------------------------------------------------------------------- #

class ObservationLog:
    """Append-only JSON Lines, rotated at 10 MB into `.1`, `.2`, `.3`."""

    def __init__(self, path: Path, max_bytes: int = MAX_LOG_BYTES, backups: int = LOG_BACKUPS):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()

    def append(self, record: Mapping[str, Any]) -> None:
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            size = self.path.stat().st_size if self.path.exists() else 0
            if size and size + len(line) > self.max_bytes:
                self._rotate()
            with self.path.open("ab") as f:
                f.write(line)

    def _rotate(self) -> None:
        for i in range(self.backups, 0, -1):
            src = self.path if i == 1 else self._backup(i - 1)
            if src.exists():
                src.replace(self._backup(i))

    def _backup(self, i: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{i}")

    def newest_first(self) -> Iterator[dict[str, Any]]:
        for path in [self.path] + [self._backup(i) for i in range(1, self.backups + 1)]:
            if not path.exists():
                continue
            with self._lock:
                lines = path.read_bytes().splitlines()
            for raw in reversed(lines):
                try:
                    yield json.loads(raw)
                except ValueError:
                    continue


# ------------------------------------------------------------------------------------------- #
# The pair and the comparison
# ------------------------------------------------------------------------------------------- #

def _is_replay(record: Mapping[str, Any]) -> bool:
    return record.get("run") == "replay"


def latest_identity(records: Iterable[Mapping[str, Any]], replay: bool,
                    layer: str | None = "transport") -> dict[str, Any] | None:
    """The newest record, of one side, that carries a `clientInfo`.

    Real means no `X-Observatory-Run` header at all; replay means `X-Observatory-Run: replay`.
    Any other marker belongs to neither side. The transport layer is preferred — it is what came
    over the wire — and the protocol layer is the fallback, for a client seen only through a tool.
    """
    records = list(records)
    for wanted in ([layer, None] if layer else [None]):
        for record in records:
            run = record.get("run")
            if replay and run != "replay":
                continue
            if not replay and run is not None:
                continue
            if wanted and record.get("layer") != wanted:
                continue
            if record.get("clientInfo") is not None:
                return dict(record)
    return None


def valid_selector(spec: str) -> bool:
    """Whether `spec` can name a record: a timestamp, or a prefix of one."""
    return bool(spec) and len(spec) <= 24 and bool(_SELECTOR.fullmatch(spec))


def _on_side(record: Mapping[str, Any], replay: bool) -> bool:
    run = record.get("run")
    return run == "replay" if replay else run is None


def select(records: Iterable[Mapping[str, Any]], spec: str | None, replay: bool,
           layer: str | None = "transport") -> dict[str, Any] | None:
    """The record of one side named by `spec` — its `ts`, or a prefix of it — newest first, the
    transport layer preferred. With no `spec`, the newest (`latest_identity`).

    `None` when nothing matches: a comparison someone pinned never falls back to the newest
    record, which would put a pair on screen that nobody asked for.
    """
    if spec is None:
        return latest_identity(records, replay, layer)
    records = list(records)
    for wanted in ([layer, None] if layer else [None]):
        for record in records:
            if not _on_side(record, replay) or record.get("clientInfo") is None:
                continue
            if wanted and record.get("layer") != wanted:
                continue
            if str(record.get("ts", "")).startswith(spec):
                return dict(record)
    return None


def _instant(ts: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def same_request_protocol(records: Iterable[Mapping[str, Any]], anchor: Mapping[str, Any] | None,
                          replay: bool, window: float = 5.0) -> dict[str, Any] | None:
    """The protocol-layer record of the request `anchor` was: same side, the nearest within a few
    seconds. What the tool was handed for *that* call, not for the newest one."""
    if anchor is None:
        return None
    if anchor.get("layer") == "protocol":
        return dict(anchor)
    at = _instant(anchor.get("ts"))
    if at is None:
        return None
    best: tuple[float, Mapping[str, Any]] | None = None
    for record in records:
        if record.get("layer") != "protocol" or not _on_side(record, replay):
            continue
        when = _instant(record.get("ts"))
        if when is None:
            continue
        gap = abs((when - at).total_seconds())
        if gap <= window and (best is None or gap < best[0]):
            best = (gap, record)
    return dict(best[1]) if best else None


def pair(log: ObservationLog, real: str | None = None,
         replay: str | None = None) -> dict[str, dict[str, Any] | None]:
    return _pair(list(log.newest_first()), real, replay)


def _pair(records: list[dict[str, Any]], real: str | None,
          replay: str | None) -> dict[str, dict[str, Any] | None]:
    left, right = select(records, real, False), select(records, replay, True)
    return {"real": left,
            "replay": right,
            "realProtocol": (latest_identity(records, replay=False, layer="protocol") if real is None
                             else same_request_protocol(records, left, False)),
            "replayProtocol": (latest_identity(records, replay=True, layer="protocol")
                               if replay is None else same_request_protocol(records, right, True))}


def clients(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Every real client, once: grouped by `clientInfo.name`, each with its newest record. Newest
    first. A replay is not a client and is not listed."""
    newest: dict[str, dict[str, Any]] = {}
    for record in records:  # newest first
        info = record.get("clientInfo")
        if record.get("run") is not None or not isinstance(info, Mapping):
            continue
        name = str(info.get("name"))
        if name in newest:
            newest[name]["seen"] += 1
            continue
        newest[name] = {"name": name, "clientInfo": dict(info),
                        "protocolVersion": record.get("protocolVersion"),
                        "userAgent": (record.get("headers") or {}).get("userAgent"),
                        "ts": record.get("ts"), "method": record.get("method"),
                        "layer": record.get("layer"), "seen": 1}
    return list(newest.values())


def clients_note(listed: list[Mapping[str, Any]]) -> str:
    """What the list shows, stated from the list: the fields every client filled in itself."""
    fields = sorted({str(k) for c in listed for k in (c.get("clientInfo") or {})})
    seen = ", ".join(fields) if fields else "none"
    return ("Every real client identified itself only with fields it fills in itself "
            f"(clientInfo: {seen}). None of them expresses a legal entity, an agent, or the scope "
            "of its authority. 每一個真實 client 都只帶自行填報的欄位；沒有任何一個表達法人、agent "
            "或授權範圍。")


def _canonical(v: Any) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


#: (key, label, how to read it from a record). Every row is shown; none is hidden for differing.
ROWS: list[tuple[str, str]] = [
    ("clientInfo", "clientInfo"),
    ("protocolVersion", "protocolVersion"),
    ("capabilities", "capabilities"),
    ("userAgent", "User-Agent"),
    ("mcpProtocolVersion", "MCP-Protocol-Version header"),
    ("origin", "Origin"),
    ("authorization", "Authorization header present"),
    ("era", "Handshake"),
    ("protocolClientInfo", "clientInfo as handed to the tool"),
]


def _field(record: Mapping[str, Any] | None, key: str,
           protocol: Mapping[str, Any] | None = None) -> Any:
    if key == "protocolClientInfo":
        # Only a protocol-layer record has this; a client that never called echo_identity has none.
        return None if protocol is None or protocol.get("layer") != "protocol"             else protocol.get("clientInfo")
    if record is None:
        return None
    if key in ("userAgent", "mcpProtocolVersion", "origin", "authorization"):
        return (record.get("headers") or {}).get(key)
    return record.get(key)


def compare(real: Mapping[str, Any] | None, replay: Mapping[str, Any] | None,
            real_protocol: Mapping[str, Any] | None = None,
            replay_protocol: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    rows = []
    for key, label in ROWS:
        left = _field(real, key, real_protocol)
        right = _field(replay, key, replay_protocol)
        if real is None or replay is None:
            verdict = "pending"
        else:
            verdict = "same" if _canonical(left) == _canonical(right) else "different"
        rows.append({"key": key, "label": label, "real": left, "replay": right,
                     "verdict": verdict})
    return rows


def summary(log: ObservationLog, real: str | None = None,
            replay: str | None = None) -> dict[str, Any]:
    """Everything the page and the console show, as data. `real` and `replay` pin each side to a
    record by its timestamp (or a prefix); left out, each side is its newest record."""
    records = list(log.newest_first())
    p = _pair(records, real, replay)
    listed = clients(records)
    return {"real": p["real"], "replay": p["replay"],
            "selected": {"real": real, "replay": replay},
            "rows": compare(p["real"], p["replay"], p["realProtocol"], p["replayProtocol"]),
            "note": FOOTER,
            "clients": listed,
            "clientsNote": clients_note(listed)}
