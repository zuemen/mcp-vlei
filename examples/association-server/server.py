"""The association's public MCP server.

Taiwan Blockchain Enthusiasts Association, as a legal entity presenting an LE credential and
requiring an ECR credential for anything that changes its membership records.

Run::

    pip install -e packages/mcp-vlei
    python examples/association-server/server.py

Two things this file demonstrates by what it does *not* contain:

* No verification logic. Tools declare what they require; ``mcp_vlei`` decides what valid means.
* No special case for any client. ``list_events`` works for every caller including an unmodified
  Claude Desktop, because it declares no requirement. That is what "additive" means in practice.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_vlei import VleiIdentity

ROOT = Path(__file__).resolve().parents[2]
CREDENTIALS = ROOT / "credentials"
DASHBOARD = Path(__file__).parent / "dashboard"
ENV = json.loads((CREDENTIALS / "env.json").read_text()) if (CREDENTIALS / "env.json").exists() else {}

# Machine-local ports (gitignored) — the same file the scripts and docker compose read.
_LOCAL = ROOT / "scripts" / ".env"
if _LOCAL.is_file():
    for _line in _LOCAL.read_text(encoding="utf-8").splitlines():
        if _line.strip() and not _line.lstrip().startswith("#") and "=" in _line:
            _key, _value = _line.split("=", 1)
            os.environ.setdefault(_key.strip(), _value.strip())

VERIFIER_URL = os.environ.get("VLEI_VERIFIER_URL", ENV.get("verifierUrl", "http://localhost:7676"))
ACCEPTED_ROOTS = ENV.get("acceptedRoots") or [os.environ["VLEI_ROOT_AID"]]
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080")
WITNESS_URL = os.environ.get("VLEI_WITNESS_URL", "http://localhost:5642")

# ------------------------------------------------------------------------------------------- #
# In-memory state. A real deployment would have a database; the point here is the identity path.
# ------------------------------------------------------------------------------------------- #

EVENTS = [
    {"id": "ev-2026-10", "title": "vLEI and agent identity, monthly meetup", "date": "2026-10-08"},
    {"id": "ev-2026-11", "title": "KERI workshop", "date": "2026-11-12"},
]
MEMBERS: list[dict[str, Any]] = []

#: Every decision the extension makes, for the dashboard. Bounded so a long demo cannot grow it
#: without limit.
AUDIT: list[dict[str, Any]] = []


def record(decision: dict[str, Any]) -> None:
    decision["at"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
    AUDIT.append(decision)
    del AUDIT[:-200]


def _witness_urls() -> list[str] | None:
    """VLEI_WITNESS_URLS, comma-separated: every caller's key log is compared across them, and a
    fork refused. Unset, the one VLEI_WITNESS_URL is asked and nothing is compared."""
    urls = [u.strip() for u in os.environ.get("VLEI_WITNESS_URLS", "").split(",") if u.strip()]
    return urls or None


# ------------------------------------------------------------------------------------------- #

vlei = VleiIdentity(
    le_credential=CREDENTIALS / "le.cesr",
    requires="ECR",
    accepted_roots=ACCEPTED_ROOTS,
    # Revocation is read from the issuer's transaction event log, served by a witness, rather than
    # from a verification service. Same authority, one fewer moving part — and it sidesteps an
    # upstream defect in vlei-verifier 1.0.0/0.1.5 that takes the service down on this exact path
    # (docs/upstream/issue.md). Set revocation_source="verifier" to use the service instead.
    revocation_source="tel",
    witness_url=WITNESS_URL,
    witness_urls=_witness_urls(),
    well_known=f"{PUBLIC_URL}/.well-known/vlei",
    on_decision=record,
)

mcp = MCPServer(name="association-server", version="0.1.0", extensions=[vlei])

# An extension is constructed before the server that holds it, so it learns the tool registry
# afterwards. This is what lets each tool keep its requirement in its own `_meta`.
vlei.bind(mcp)


@mcp.tool()
def list_events(limit: int = 10) -> list[dict[str, Any]]:
    """List the association's upcoming public events.

    Public on purpose. An unmodified client with no vLEI support can call this, which is the
    backward-compatibility claim made executable.
    """
    return EVENTS[:limit]


# The role is the one the demo environment issues. In a real association it would be
# `member-registration`; here there is a single engagement context, and naming a role the
# credential does not carry would demonstrate `role_mismatch` rather than the happy path.
@mcp.tool(meta={"org.gleif.vlei/requires": {"credential": "ECR", "role": "regulatory-filing"}})
def register_member(name: str, email: str) -> dict[str, Any]:
    """Register a new member. Requires an ECR credential carrying the member-registration role.

    The requirement in the decorator is the entire authorization statement. This function body
    contains no identity code, and it is reached only after the extension has verified the chain,
    the revocation state, the root, the signature, and the role.
    """
    member = {"name": name, "email": email, "joined": date.today().isoformat()}
    MEMBERS.append(member)
    return {"registered": member, "totalMembers": len(MEMBERS)}


# ------------------------------------------------------------------------------------------- #
# HTTP surface: the well-known document, the dashboard, and the dashboard's data
# ------------------------------------------------------------------------------------------- #


@mcp.custom_route("/.well-known/vlei", methods=["GET"])
async def well_known(request: Request) -> JSONResponse:
    """Mode (a), passive verification.

    Published separately from the session so a counterparty can check who operates this server
    *before* connecting to it.
    """
    return JSONResponse(vlei.well_known_document())


@mcp.custom_route("/api/audit", methods=["GET"])
async def audit(request: Request) -> JSONResponse:
    return JSONResponse({"decisions": list(reversed(AUDIT)), "members": len(MEMBERS)})


@mcp.custom_route("/dashboard/", methods=["GET"])
async def dashboard(request: Request) -> Any:
    from starlette.responses import HTMLResponse

    return HTMLResponse((DASHBOARD / "index.html").read_text(encoding="utf-8"))


@mcp.custom_route("/api/revoke", methods=["POST"])
async def revoke(request: Request) -> JSONResponse:
    """The dashboard's revoke button.

    Revocation itself happens in the LE's TEL, through ``kli vc revoke`` — this endpoint runs that
    and drops the cached verification so the next call reflects it immediately. The revocation is
    real; only the button is a demo affordance.
    """
    import asyncio

    # Re-read rather than trusting what was loaded at startup: the bootstrap re-issues the ECR
    # after its own checks, so a server started before that would try to revoke a credential that
    # is already revoked and report a duplicitous event.
    env = json.loads((CREDENTIALS / "env.json").read_text())
    said = env.get("ecrSaid")
    ecr_aid = env.get("ecrAid")
    compose = str(ROOT / "scripts" / "docker-compose.yml")
    proc = await asyncio.create_subprocess_exec(
        "docker", "compose", "-f", compose, "exec", "-T", "keri-cli",
        "kli", "vc", "revoke", "--name", "le", "--alias", "le",
        "--registry-name", "leRegistry", "--said", said, "--send", ecr_aid,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    if vlei.verifier is not None:
        vlei.verifier.invalidate(env.get("agentAid") or ecr_aid)
    record({"tool": "(dashboard)", "allowed": True, "note": "ECR revoked in the LE's TEL"})
    return JSONResponse({"ok": proc.returncode == 0, "output": out.decode()[-500:]})


if __name__ == "__main__":
    import uvicorn

    print(f"association-server on {PUBLIC_URL}")
    print(f"  revocation via: {WITNESS_URL} (transaction event log)")
    print(f"  accepted roots: {ACCEPTED_ROOTS}")
    print(f"  dashboard:      {PUBLIC_URL}/dashboard/")
    # Loopback by default: `/api/revoke` withdraws a credential and has no authentication of its own —
    # it is a demo control, and on 0.0.0.0 it was reachable from the network the laptop was on.
    uvicorn.run(
        mcp.streamable_http_app(),
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
    )
