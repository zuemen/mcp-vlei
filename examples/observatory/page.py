"""`GET /observatory`: two records side by side, and every real client once, as plain text.

`?real=<ts>&replay=<ts>` pins each side to a record by its timestamp, or a prefix of it; without
them each side is its newest record. The page says which two it is comparing, and when they were
recorded, in UTC and in Taipei time.

Every value on this page was written by a client, and the impersonation example showed what the
fields accept — `javascript:` URLs, `data:text/html` icons, `file://` paths. So nothing here is a
link, an image or markup: each value is escaped and set in `<code>`. The page carries no script,
and its only style is the inline block below, allowed by hash in the Content-Security-Policy.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any

#: The experiment's own clock, shown beside UTC so "12:10" on the page is "12:10" in the notes.
TAIPEI = timezone(timedelta(hours=8))

STYLE = """
:root{--bg:#F7F5EF;--panel:#FFFFFF;--ink:#1B2330;--ink-2:#5B6472;--muted:#8A93A0;
--pass:#2E5D89;--fail:#C0392B;--code-bg:#EFEDE6;--rule:#D8D3C8;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
-webkit-font-smoothing:antialiased}
main{max-width:1280px;margin:0 auto;padding:40px 32px 56px}
h1{font-size:28px;font-weight:600;margin:0 0 6px;letter-spacing:-.01em}
.sub{color:var(--ink-2);margin:0 0 28px;font-size:15px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--rule);
table-layout:fixed}
th,td{text-align:left;vertical-align:top;padding:14px 16px;border-bottom:1px solid var(--rule)}
thead th{font-size:13px;font-weight:600;color:var(--ink);background:transparent;border-bottom:1px solid var(--ink)}
thead th small{display:block;font-weight:400;color:var(--muted);margin-top:4px}
col.f{width:210px}col.v{width:160px}
td.field{font-size:15px;font-weight:600}
code{font-family:var(--mono);font-size:14px;white-space:pre-wrap;word-break:break-word;
background:transparent;display:block;padding:2px 0;border-radius:0}
.none{color:var(--muted);font-style:italic;font-size:13px}
.verdict{font-size:14px;font-weight:600;letter-spacing:.02em}
.same{color:var(--pass)}.different{color:var(--fail)}.pending{color:var(--muted)}
tr.clientInfo td.field{color:var(--ink)}
.note{margin:28px 0 0;padding:18px 20px;border-left:3px solid var(--pass);background:var(--panel);
font-size:15px;line-height:1.6;max-width:900px}
.meta{margin-top:18px;color:var(--muted);font-size:13px;line-height:1.6}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:0 0 20px}
.pair div{background:var(--panel);border:1px solid var(--rule);padding:12px 16px;font-size:14px;
line-height:1.55}
.pair b{display:block;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-2)}
.pair .missing{color:var(--fail)}
.pair code{display:inline;padding:1px 6px}
.when{white-space:nowrap}
h2{font-size:21px;font-weight:600;margin:44px 0 12px}
col.n{width:190px}col.p{width:130px}col.t{width:270px}
"""

STYLE_HASH = "sha256-" + base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()

CSP = (
    "default-src 'none'; "
    f"style-src '{STYLE_HASH}'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_VERDICT = {
    "same": "Same · 相同",
    "different": "Different · 不同",
    "pending": "—",
}


def _value(v: Any) -> str:
    if v is None:
        return '<span class="none">not sent</span>'
    if isinstance(v, bool):
        return f"<code>{'yes' if v else 'no'}</code>"
    if isinstance(v, str):
        return f"<code>{escape(v)}</code>"
    return f"<code>{escape(json.dumps(v, indent=2, ensure_ascii=False, sort_keys=True))}</code>"


def _when(record: dict[str, Any] | None, empty: str) -> str:
    if record is None:
        return f"<small>{escape(empty)}</small>"
    method = record.get("method") or "?"
    return (f"<small>{escape(str(record.get('ts', '')))} · {escape(str(method))} "
            f"· {escape(str(record.get('layer', '')))} layer</small>")


def _time(ts: Any) -> str:
    """`2026-09-29T04:10:48.905Z` -> `2026-09-29T04:10:48.905Z · 12:10:48 Taipei`."""
    try:
        at = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(TAIPEI)
    except ValueError:
        return escape(str(ts))
    return f"{escape(str(ts))} · {at:%H:%M:%S} Taipei"


def _taipei(ts: Any) -> str:
    """`2026-09-29T04:10:48.905Z` -> `2026-09-29 12:10:48 Taipei`."""
    try:
        at = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(TAIPEI)
    except ValueError:
        return escape(str(ts))
    return f'<span class="when">{at:%Y-%m-%d %H:%M:%S} Taipei</span>'


def _side(label: str, record: dict[str, Any] | None, spec: str | None, param: str) -> str:
    how = (f"pinned by <code>?{param}={escape(spec)}</code>" if spec
           else "the newest — pin it with <code>?" + param + "=&lt;timestamp&gt;</code>")
    if record is None:
        noun = "real-client" if param == "real" else "replay"
        what = (f'<span class="missing">No {noun} record matches '
                f"<code>{escape(spec)}</code>.</span>" if spec
                else f'<span class="missing">No {noun} record yet.</span>')
        return f"<div><b>{escape(label)}</b>{what}<br>{how}</div>"
    return (f"<div><b>{escape(label)}</b>{_time(record.get('ts'))}<br>"
            f"{escape(str(record.get('method') or '?'))} · {escape(str(record.get('layer', '')))} "
            f"layer<br>{how}</div>")


def _clients(summary: dict[str, Any]) -> str:
    rows = []
    for c in summary.get("clients") or []:
        rows.append(
            f"<tr><td class=\"field\">{escape(c['name'])}</td><td>{_value(c.get('clientInfo'))}</td>"
            f"<td>{_value(c.get('protocolVersion'))}</td><td>{_value(c.get('userAgent'))}</td>"
            f"<td>{_taipei(c.get('ts'))}<br><small class=\"when\">{escape(str(c.get('ts')))}</small>"
            f"<br><small>{escape(str(c.get('method') or '?'))} · seen {int(c.get('seen', 1))}×"
            f"</small></td></tr>"
        )
    body = "\n".join(rows) or '<tr><td colspan="5"><span class="none">No real client yet.</span></td></tr>'
    return f"""<h2 id="clients">All real clients · 所有真實 client</h2>
<table>
<colgroup><col class="n"><col><col class="p"><col><col class="t"></colgroup>
<thead><tr><th>clientInfo.name</th><th>clientInfo<small>newest record of each</small></th>
<th>protocolVersion</th><th>User-Agent</th><th>Time</th></tr></thead>
<tbody>
{body}
</tbody></table>
<p class="note">{escape(summary.get("clientsNote") or "")}</p>"""


def render(summary: dict[str, Any], host: str | None = None) -> str:
    real, replay = summary["real"], summary["replay"]
    selected = summary.get("selected") or {}
    rows = []
    for row in summary["rows"]:
        rows.append(
            f'<tr class="{escape(row["key"])}"><td class="field">{escape(row["label"])}</td>'
            f"<td>{_value(row['real'])}</td><td>{_value(row['replay'])}</td>"
            f'<td class="verdict {escape(row["verdict"])}">{_VERDICT[row["verdict"]]}</td></tr>'
        )
    where = f" at {escape(host)}" if host else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>MCP Observatory</title>
<style>{STYLE}</style></head>
<body><main>
<h1>MCP Observatory</h1>
<p class="sub">What this MCP server{where} received from two clients. Read-only; every value is
shown exactly as sent, as text.</p>
<section class="pair" aria-label="The two records compared">
{_side("Real client", real, selected.get("real"), "real")}
{_side("Replay", replay, selected.get("replay"), "replay")}
</section>
<table>
<colgroup><col class="f"><col><col><col class="v"></colgroup>
<thead><tr><th>Field</th>
<th>Real client{_when(real, "No record matches the selector." if selected.get("real")
                  else "No real client has connected yet.")}</th>
<th>Replay — X-Observatory-Run: replay{_when(replay, "No record matches the selector."
                  if selected.get("replay") else "No replay has run yet.")}</th>
<th>Compared</th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody></table>
<p class="note">{escape(summary["note"])}</p>
{_clients(summary)}
<p class="meta">Real client: a request carrying clientInfo with no X-Observatory-Run header.
Replay: one with X-Observatory-Run: replay. Each side is the newest unless pinned with
?real= and ?replay=, which take a record's timestamp or a prefix of it (2026-09-29T04:10). That header is not an MCP identity field; it
exists only so this page can tell the two records apart. Recorded: method, the identity fields of
initialize and of the 2026-07-28 request envelope, User-Agent, MCP-Protocol-Version and Origin,
and whether an Authorization header was present. Not recorded: conversation content, tool
arguments, tokens, IP addresses.</p>
</main></body></html>
"""
