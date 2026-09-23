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

import os
from datetime import date
from typing import Any

from pathlib import Path

from mcp.server.mcpserver import MCPServer
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

FORMS = [
    {"id": "A1", "title": "Quarterly capital adequacy return", "periods": ["2026Q1", "2026Q2"]},
    {"id": "B3", "title": "Annual beneficial ownership declaration", "periods": ["2025", "2026"]},
]

FILINGS: dict[str, list[dict[str, Any]]] = {}


def _caller(ctx: Any) -> dict[str, str]:
    """Read what the gateway established. No verification happens here — that already happened.

    If these headers are absent, the request did not come through the gateway. The server refuses
    rather than guessing, because a deployment where this server is reachable directly is a
    misconfiguration, not a fallback.
    """
    headers = getattr(ctx, "headers", None) or {}
    lei = headers.get("x-vlei-lei")
    if not lei:
        raise PermissionError(
            "no x-vlei-lei header: this server must be reached through the authorization gateway"
        )
    return {
        "lei": lei,
        "role": headers.get("x-vlei-role", ""),
        "holder": headers.get("x-vlei-holder-aid", ""),
        "agent": headers.get("x-vlei-delegate-aid", ""),
    }


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
def get_filing_status(lei: str, ctx: Any = None) -> dict[str, Any]:
    """Return the filing status for a legal entity.

    The `lei` argument is a request, not an authorization. It is honoured only when it matches the
    LEI the gateway established for the caller — an entity may read its own filings and no one
    else's. Without the verified header there would be nothing to compare it against, and this
    tool would be an enumeration endpoint for every filing the regulator holds.
    """
    caller = _caller(ctx)
    if lei != caller["lei"]:
        raise PermissionError(
            f"caller is {caller['lei']}; filings for {lei} are not theirs to read"
        )
    return {"lei": lei, "filings": FILINGS.get(lei, [])}


@mcp.tool()
def submit_filing(form: str, period: str, payload: dict[str, Any], ctx: Any = None) -> dict[str, Any]:
    """Submit a periodic regulatory filing on behalf of the legal entity in the caller's credential.

    Note what is *not* a parameter: which entity is filing. It is not the caller's to assert — it
    comes from the verified credential, via the gateway. That removes a whole class of impersonation
    without this file containing a line of identity code.
    """
    caller = _caller(ctx)
    record = {
        "form": form,
        "period": period,
        "submittedAt": date.today().isoformat(),
        "submittedBy": {
            "lei": caller["lei"],
            "role": caller["role"],
            "holderAid": caller["holder"],
            "agentAid": caller["agent"],
        },
        "fields": len(payload),
        "status": "ACCEPTED",
    }
    FILINGS.setdefault(caller["lei"], []).append(record)
    return record


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        mcp.streamable_http_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8081"))
    )
