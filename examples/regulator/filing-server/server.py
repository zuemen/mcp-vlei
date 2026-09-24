"""A regulatory filing MCP server that knows nothing about vLEI.

This file is the point of the government scenario. Search it for "vlei" and you will find the
header names it reads and nothing else: no credential parsing, no chain validation, no revocation
check, no signature verification, no dependency on ``mcp_vlei``.

The gateway in front of it does all of that and passes down the established facts as ordinary
request headers, exactly as an institution's existing systems already consume headers from whatever
authentication sits in front of them today.

That is the claim stage 3 of ``docs/GOVERNMENT.md`` makes: **an institution does not modify its
existing systems.** This server is what "not modified" looks like.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from datetime import date
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

mcp = MCPServer(name="filing-server", version="0.1.0")

# The regulator's own Legal Entity credential, published for passive verification. Mode (a) of
# `spec/SPEC.md` is a MUST, and it applies to a regulator as much as to anyone: an agent about to
# file a return should be able to establish who operates the endpoint *before* sending it.
#
# Note what this does not do. The file is served as published; nothing here parses or verifies a
# credential, which is the whole claim of this example.
LE_CREDENTIAL = Path(
    os.environ.get("VLEI_LE_CREDENTIAL", Path(__file__).resolve().parents[3] / "credentials" / "le.cesr")
)
ACCEPTED_ROOTS = [r for r in os.environ.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r]

#: The headers the gateway sets. This tuple is the server's entire vLEI surface.
IDENTITY_HEADERS = ("x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid")
REPORT_HEADER = "x-vlei-report"
#: Where the gateway's verification record is handed back to the caller, decoded.
REPORT_META = "org.gleif.vlei/report"

FORMS = [
    {"id": "A1", "title": "Quarterly capital adequacy return", "periods": ["2026Q1", "2026Q2"]},
    {"id": "B3", "title": "Annual beneficial ownership declaration", "periods": ["2025", "2026"]},
]

FILINGS: dict[str, list[dict[str, Any]]] = {}


class Refused(ToolError):
    """An anticipated refusal. The SDK shows a `ToolError`'s text to the caller; any other
    exception reaches them only as "Error executing tool", which would hide why."""


def _header(headers: Any, name: str) -> str:
    """One value, or a refusal. Two values for an identity header means two writers disagreed."""
    values = headers.getlist(name) if hasattr(headers, "getlist") else [headers.get(name)]
    values = [v for v in values if v is not None]
    if len(values) > 1:
        raise Refused(f"{name} arrived {len(values)} times; refusing an ambiguous identity")
    return values[0] if values else ""


def _caller(ctx: Context) -> dict[str, str]:
    """Read what the gateway established. No verification happens here — that already happened.

    If these headers are absent, the request did not come through the gateway. The server refuses
    rather than guessing, because a deployment where this server is reachable directly is a
    misconfiguration, not a fallback.
    """
    headers = ctx.headers or {}
    received = {name: _header(headers, name) for name in (*IDENTITY_HEADERS, REPORT_HEADER)}
    if not received["x-vlei-lei"]:
        raise Refused(
            "no x-vlei-lei header: this server must be reached through the authorization gateway"
        )
    return received


def _report(encoded: str) -> dict[str, Any] | None:
    """The gateway's record, decoded for the caller. Decoding is all that happens to it here."""
    if not encoded:
        return None
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        report = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    return report if isinstance(report, dict) else None


@mcp.custom_route("/.well-known/vlei", methods=["GET"])
async def well_known(request: Request) -> JSONResponse:
    """Who operates this endpoint, fetchable without a session."""
    if not LE_CREDENTIAL.exists():
        return JSONResponse({"error": "no LE credential configured"}, status_code=404)
    return JSONResponse(
        {
            "extension": "org.gleif.vlei/identity",
            "credential": LE_CREDENTIAL.read_text(encoding="utf-8").strip(),
            "acceptedRoots": ACCEPTED_ROOTS,
            "signatureAlgs": ["Ed25519"],
        }
    )


@mcp.tool()
def list_forms() -> list[dict[str, Any]]:
    """List the filing forms this regulator accepts."""
    return FORMS


@mcp.tool()
def get_filing_status(lei: str, ctx: Context) -> dict[str, Any]:
    """Return the filing status for a legal entity.

    The `lei` argument is a request, not an authorization. It is honoured only when it matches the
    LEI the gateway established for the caller — an entity may read its own filings and no one
    else's. Without the verified header there would be nothing to compare it against, and this
    tool would be an enumeration endpoint for every filing the regulator holds.
    """
    caller = _caller(ctx)
    if lei != caller["x-vlei-lei"]:
        raise Refused(
            f"caller is {caller['x-vlei-lei']}; filings for {lei} are not theirs to read"
        )
    return {"lei": lei, "filings": FILINGS.get(lei, [])}


@mcp.tool()
def submit_filing(form: str, period: str, payload: dict[str, Any], ctx: Context) -> CallToolResult:
    """Submit a periodic regulatory filing on behalf of the legal entity in the caller's credential.

    Note what is *not* a parameter: which entity is filing. It is not the caller's to assert — it
    comes from the verified credential, via the gateway. That removes a whole class of impersonation
    without this file containing a line of identity code.

    The receipt lists the identity headers exactly as they arrived, so a caller can see what the
    server was told — and the gateway's verification report comes back in `_meta`.
    """
    caller = _caller(ctx)
    record = {
        "form": form,
        "period": period,
        "submittedAt": date.today().isoformat(),
        "submittedBy": {
            "lei": caller["x-vlei-lei"],
            "role": caller["x-vlei-role"],
            "holderAid": caller["x-vlei-holder-aid"],
            "agentAid": caller["x-vlei-delegate-aid"],
        },
        "fields": len(payload),
        "status": "ACCEPTED",
    }
    FILINGS.setdefault(caller["x-vlei-lei"], []).append(record)

    receipt = {
        **record,
        "receivedHeaders": {name: caller[name] for name in IDENTITY_HEADERS if caller[name]},
        "reportReceived": bool(caller[REPORT_HEADER]),
    }
    report = _report(caller[REPORT_HEADER])
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(receipt, indent=2))],
        structured_content=receipt,
        meta={REPORT_META: report} if report is not None else None,
    )


def create_app(*, host: str | None = None) -> Starlette:
    """The streamable-HTTP app.

    The SDK's DNS-rebinding protection is kept on, with the gateway's view of this server added to
    the allowed hosts: agentgateway reaches it as ``filing-server:8081``, and a default that only
    admits ``localhost`` would answer the gateway with 421.
    """
    allowed = [
        h.strip()
        for h in os.environ.get(
            "FILING_ALLOWED_HOSTS",
            "filing-server,filing-server:*,localhost,localhost:*,127.0.0.1,127.0.0.1:*",
        ).split(",")
        if h.strip()
    ]
    return mcp.streamable_http_app(
        host=host or os.environ.get("HOST", "0.0.0.0"),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"http://{h}" for h in allowed],
        ),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8081")),
    )
