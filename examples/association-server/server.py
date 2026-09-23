"""The association's public MCP server.

Taiwan Blockchain Enthusiasts Association, as a legal entity presenting an LE credential and
requiring an ECR credential for anything that changes its membership records.

Run::

    python examples/association-server/server.py

Two things this file demonstrates by what it does *not* contain:

* No verification logic. Tools declare what they require; ``mcp_vlei`` decides what valid means.
* No special case for any client. ``list_events`` works for every caller including an unmodified
  Claude Desktop, because it declares no requirement. That is what "additive" means in practice.
"""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.http import create_http_app

from mcp_vlei import VleiIdentity

ROOT = Path(__file__).resolve().parents[2]
CREDENTIALS = ROOT / "credentials"
ENV = json.loads((CREDENTIALS / "env.json").read_text()) if (CREDENTIALS / "env.json").exists() else {}

VERIFIER_URL = os.environ.get("VLEI_VERIFIER_URL", ENV.get("verifierUrl", "http://localhost:7676"))
ACCEPTED_ROOTS = ENV.get("acceptedRoots") or [os.environ["VLEI_ROOT_AID"]]
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080")

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
    decision["at"] = _now()
    AUDIT.append(decision)
    del AUDIT[:-200]


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%H:%M:%S")


# ------------------------------------------------------------------------------------------- #

vlei = VleiIdentity(
    le_credential=CREDENTIALS / "le.cesr",
    requires="ECR",
    verifier_url=VERIFIER_URL,
    accepted_roots=ACCEPTED_ROOTS,
    well_known=f"{PUBLIC_URL}/.well-known/vlei",
    # Zero TTL: this server exists to demonstrate revocation, and a cached "valid" would make
    # revocation look slower than it is. A production deployment would trade this off per tool.
    ttl_ms=0,
    on_decision=record,
)

mcp = MCPServer(name="association-server", version="0.1.0", extensions=[vlei])


@mcp.tool()
def list_events(limit: int = 10) -> list[dict[str, Any]]:
    """List the association's upcoming public events.

    Public on purpose. An unmodified client with no vLEI support can call this, which is the
    backward-compatibility claim made executable.
    """
    return EVENTS[:limit]


@mcp.tool(
    meta={
        "org.gleif.vlei/requires": {
            "credential": "ECR",
            "role": "member-registration",
        }
    }
)
def register_member(name: str, email: str) -> dict[str, Any]:
    """Register a new member. Requires an ECR credential carrying the member-registration role.

    The requirement above is the entire authorization statement. This function body contains no
    identity code, and it is reached only after the extension has verified the chain, the
    revocation state, the root, the signature, and the role.
    """
    member = {"name": name, "email": email, "joined": date.today().isoformat()}
    MEMBERS.append(member)
    return {"registered": member, "totalMembers": len(MEMBERS)}


# ------------------------------------------------------------------------------------------- #
# HTTP surface: the MCP endpoint, the well-known document, and the dashboard's data
# ------------------------------------------------------------------------------------------- #

app = create_http_app(mcp)


@app.get("/.well-known/vlei")
async def well_known() -> dict[str, Any]:
    """Mode (a), passive verification.

    Published separately from ``discover`` so a counterparty can check who operates this server
    *before* connecting to it.
    """
    return vlei.well_known_document()


@app.get("/api/audit")
async def audit() -> dict[str, Any]:
    return {"decisions": list(reversed(AUDIT)), "members": len(MEMBERS)}


@app.post("/api/revoke")
async def revoke() -> dict[str, Any]:
    """The dashboard's revoke button.

    Revocation itself happens in the LE's TEL, through ``kli vc revoke`` — this endpoint runs that
    and drops the cached verification so the next call reflects it immediately. The revocation is
    real; only the button is a demo affordance.
    """
    import asyncio

    said = ENV.get("ecrSaid")
    ecr_aid = ENV.get("ecrAid")
    proc = await asyncio.create_subprocess_exec(
        "docker", "compose", "-f", str(ROOT / "scripts" / "docker-compose.yml"),
        "exec", "-T", "keri-cli",
        "kli", "vc", "revoke", "--name", "le", "--alias", "le",
        "--registry-name", "leRegistry", "--said", said, "--send", ecr_aid,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    vlei.verifier.invalidate(ENV.get("agentAid") or ecr_aid)
    record({"tool": "(dashboard)", "allowed": True, "note": f"ECR revoked in the LE's TEL"})
    return {"ok": proc.returncode == 0, "output": out.decode()[-500:]}


if __name__ == "__main__":
    import uvicorn

    print(f"association-server on {PUBLIC_URL}")
    print(f"  verifier:       {VERIFIER_URL}")
    print(f"  accepted roots: {ACCEPTED_ROOTS}")
    print(f"  dashboard:      {PUBLIC_URL}/dashboard/")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
