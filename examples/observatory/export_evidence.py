"""Export chosen observatory records as evidence — only listed fields, and only if nothing forbidden
is present.

    python examples/observatory/export_evidence.py \
        --pick "claude.ai=real:2026-09-29T04:10:48.9" \
        --pick "replay=replay:2026-09-29T04:13:30.7" \
        --pick "claude-code=real:2026-09-29T04:17:30" \
        --out docs/evidence/observatory-2026-09-29.json

A pick is `label=side:selector`: `side` is `real` or `replay`, and `selector` names a record by its
timestamp or a prefix of it, exactly as `?real=` and `?replay=` do on the page (the transport-layer
record is preferred). A pick that matches nothing stops the export.

The server never records IP addresses, tokens, the value of an Authorization header, or
conversation content. This checks anyway, over each chosen record as stored and over the file it
would write: an IP address, a bearer token or JWT, an `Authorization` value (the log keeps only
whether the header was present), or a key that carries conversation — `arguments`, `messages`,
`content` and the like. Any one of them stops the export, names what it found and where, and
writes nothing.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from observations import ObservationLog, select, valid_selector  # noqa: E402

DEFAULT_LOG = HERE / "data" / "observations.jsonl"

#: What leaves: a record's identity fields and the headers the page compares. Not `session` (a hash
#: of a bearer handle), nothing else.
FIELDS = ("ts", "layer", "run", "method", "tool", "era", "protocolVersion", "negotiatedVersion",
          "clientInfo", "capabilities", "headers", "truncated")
HEADER_FIELDS = ("userAgent", "mcpProtocolVersion", "origin")

#: Keys that would carry an address, a secret or a conversation, wherever they appear.
FORBIDDEN_KEYS = {
    "ip", "ipaddress", "remoteaddr", "remote_addr", "clientip", "client_ip", "x-forwarded-for",
    "x-real-ip", "cf-connecting-ip", "true-client-ip", "forwarded",
    "token", "access_token", "refresh_token", "id_token", "bearer", "password", "secret",
    "cookie", "set-cookie", "api_key", "apikey",
    "arguments", "messages", "message", "content", "prompt", "text", "body", "result", "input",
    "output", "conversation", "transcript",
}
#: Runs of characters an address can be written with; each is then parsed, not pattern-matched.
ADDRESS_LIKE = re.compile(r"[0-9A-Fa-f:.%]{3,45}")
BEARER = re.compile(r"\bbearer\s+\S", re.I)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
OPAQUE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")


def findings(value: Any, where: str = "") -> list[str]:
    """Everything in `value` that must not leave: `where: what`."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            here = f"{where}.{key}" if where else str(key)
            lowered = str(key).lower()
            if lowered in FORBIDDEN_KEYS:
                found.append(f"{here}: a key that may carry an address, a secret or conversation")
            if lowered == "authorization" and not isinstance(item, bool):
                found.append(f"{here}: an Authorization value, not only whether one was present")
            found += findings(item, here)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found += findings(item, f"{where}[{i}]")
    elif isinstance(value, str):
        address = _address_in(value)
        if address:
            found.append(f"{where}: an IP{address} address")
        for name, pattern in (("a bearer token", BEARER), ("a JWT", JWT),
                              ("an opaque token-like string", OPAQUE)):
            if pattern.search(value):
                found.append(f"{where}: {name}")
    return found


def _address_in(value: str) -> str | None:
    """`v4` or `v6` if `value` contains an IP address anywhere, else `None`. Parsed with
    `ipaddress`, so `2001:db8::7` is caught and `04:10:48.905Z` or `2.1.284` is not."""
    for run in ADDRESS_LIKE.findall(value):
        # The run itself (IPv6), without edge punctuation or a zone, and each colon-separated
        # piece — an IPv4 address followed by a port.
        candidates = {run, run.strip(".:"), run.split("%")[0], *run.split(":")}
        for candidate in candidates:
            try:
                return f"v{ipaddress.ip_address(candidate).version}"
            except ValueError:
                continue
    return None


def evidence_record(record: Mapping[str, Any], label: str, side: str, spec: str) -> dict[str, Any]:
    out: dict[str, Any] = {"label": label, "side": side, "selector": spec}
    for key in FIELDS:
        if key == "headers":
            headers = record.get("headers") or {}
            out["headers"] = {k: headers.get(k) for k in HEADER_FIELDS}
            out["headers"]["authorizationPresent"] = headers.get("authorization") is True
        elif key in record:
            out[key] = record[key]
    return out


def parse_pick(text: str) -> tuple[str, str, str]:
    label, _, rest = text.partition("=")
    side, _, spec = rest.partition(":")
    if not label or side not in ("real", "replay") or not valid_selector(spec):
        raise ValueError(f"a pick is label=real|replay:<timestamp or prefix>; got {text!r}")
    return label, side, spec


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--log", default=str(DEFAULT_LOG))
    parser.add_argument("--out", required=True)
    parser.add_argument("--pick", action="append", required=True, metavar="LABEL=SIDE:TIMESTAMP")
    parser.add_argument("--server", default="https://mcp.zuemen.net/mcp",
                        help="where the records were received, stated in the file")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        picks = [parse_pick(p) for p in args.pick]
    except ValueError as exc:
        print(f"  stopped: {exc}")
        return 1
    records = list(ObservationLog(Path(args.log)).newest_first())

    chosen, problems = [], []
    for label, side, spec in picks:
        record = select(records, spec, replay=(side == "replay"))
        if record is None:
            problems.append(f"{label}: {spec} matches no {side} record in {args.log}")
            continue
        problems += [f"{label} (as stored) {f}" for f in findings(record)]
        chosen.append(evidence_record(record, label, side, spec))

    document = {
        "_about": ("Records from the MCP observatory (examples/observatory): what a server received "
                   "from real MCP clients and from a replay of one. Every value is as the client "
                   "sent it, self-reported and unverified."),
        "server": args.server,
        "exportedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "fields": list(FIELDS),
        "neverRecorded": ("IP addresses, tokens, the value of an Authorization header (only whether "
                          "one was present), tool arguments, conversation content; checked again "
                          "before export by examples/observatory/export_evidence.py"),
        "records": chosen,
    }
    problems += [f"(file) {f}" for f in findings({k: v for k, v in document.items()
                                                  if k == "records"})]
    if problems:
        print("  stopped — nothing was written:")
        for line in problems:
            print(f"  ! {line}")
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
                   newline="\n")
    for record in chosen:
        print(f"  {record['label']:<12} {record['side']:<7} {record['ts']}  "
              f"{(record.get('clientInfo') or {}).get('name')}")
    print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
