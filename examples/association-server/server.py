"""A legal entity's public MCP server.

Demo Staffing Co., Ltd. — fictional, like every identity in this repository — as a legal entity
presenting an LE credential and requiring an ECR credential for anything that changes its
membership records.

Run::

    pip install -e packages/mcp-vlei
    python examples/association-server/server.py

Two things this file demonstrates by what it does *not* contain:

* No verification logic. Tools declare what they require; ``mcp_vlei`` decides what valid means.
* No special case for any client. ``list_events`` works for every caller including an unmodified
  Claude Desktop, because it declares no requirement. That is what "additive" means in practice.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

import sys

import anyio

from mcp_vlei import SqliteReplayStore, VleiIdentity

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
#: The nonces of calls already accepted, kept across restarts. The very first start refuses calls
#: for a minute (nothing could have been accepted before, but the server cannot know that).
REPLAY_DB = Path(os.environ.get("VLEI_REPLAY_DB", str(Path(__file__).parent / ".state" / "replay.sqlite3")))

sys.path.insert(0, str(ROOT / "examples" / "my-agent"))
from kli_signer import LazyKeystoreSigner  # noqa: E402  - the LE's key stays in its KERI keystore

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
    # (docs/upstream/issue-final.md). Set revocation_source="verifier" to use the service instead.
    revocation_source="tel",
    witness_url=WITNESS_URL,
    witness_urls=_witness_urls(),
    well_known=f"{PUBLIC_URL}/.well-known/vlei",
    on_decision=record,
    # v0.3: calls are signed for this server at this URL, each once; and it proves, when a client
    # challenges it, that it holds the LE's key — signed in the `le` keystore with `kli sign`.
    audience_urls=[f"{PUBLIC_URL}/mcp"],
    replay_store=SqliteReplayStore(REPLAY_DB),
    pop_signer=LazyKeystoreSigner("le", "le"),
)

mcp = MCPServer(name="association-server", version="0.1.0", extensions=[vlei])

# An extension is constructed before the server that holds it, so it learns the tool registry
# afterwards. This is what lets each tool keep its requirement in its own `_meta`.
vlei.bind(mcp)


@mcp.tool()
def list_events(limit: int = 10) -> list[dict[str, Any]]:
    """List the legal entity's upcoming public events.

    Public on purpose. An unmodified client with no vLEI support can call this, which is the
    backward-compatibility claim made executable.
    """
    return EVENTS[:limit]


# The role is the one the demo environment issues (credentials/env.json). In a real association it
# would be `member-registration`; here there is a single engagement context, and naming a role the
# credential does not carry would demonstrate `role_mismatch` rather than the happy path.
ISSUED_ROLE = ENV.get("role", "labor-insurance-filing")


@mcp.tool(meta={vlei.keys.requires: {"credential": "ECR", "role": ISSUED_ROLE}})
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


#: Unauthenticated and internet-facing, and each challenge answered ends in a `kli sign` subprocess
#: (seconds, through LazyKeystoreSigner/Docker) — the same two limits
#: examples/regulator/vlei-pop/service.py uses, for the same reason. This file stays self-contained
#: rather than importing from it.
#: A challenge is a handful of short fields; nothing legitimate is anywhere near this large. Bounds
#: both a reported Content-Length and a chunked body that carries none.
MAX_POP_BODY_BYTES = 4096
_TOO_LARGE_MESSAGE = f"a challenge is at most {MAX_POP_BODY_BYTES} bytes"
#: An oversize body is read and discarded up to this much, so a sender that sent a little too much
#: reads its 413 rather than a reset; beyond it nothing more is read. Either way the 413 says
#: ``Connection: close``: no unread remainder is left on a connection the next request would share.
_MAX_DRAIN_BYTES = 64 * 1024
#: Challenges are signed one at a time; a short queue beyond that is 503 rather than a pile of
#: requests waiting on a lock no one is told about.
_POP_GATE = asyncio.Semaphore(1)
_POP_WAITING = {"n": 0}
_POP_MAX_WAITING = 4


async def _read_pop_challenge(request: Request) -> tuple[Any, JSONResponse | None]:
    """The parsed body, or the refusal for it: oversize (413 — a reported ``Content-Length``
    checked up front, a chunked body with none bounded as it is read; drained up to
    ``_MAX_DRAIN_BYTES``, and the connection closed) or not JSON, including JSON nested deep enough
    to exhaust the recursion limit (400, the same refusal as any other malformed challenge — never
    an unhandled crash)."""
    too_large = JSONResponse({"layer": None, "message": _TOO_LARGE_MESSAGE}, status_code=413,
                             headers={"Connection": "close"})
    content_length = request.headers.get("content-length", "").strip()
    declared = int(content_length) if content_length.isdigit() else None
    if declared is not None and declared > _MAX_DRAIN_BYTES:
        return None, too_large  # not worth reading; closed with the answer
    oversize = declared is not None and declared > MAX_POP_BODY_BYTES
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        oversize = oversize or total > MAX_POP_BODY_BYTES
        if oversize:
            if total > _MAX_DRAIN_BYTES:
                break  # stop reading: the connection closes with the 413
            continue  # drained, not kept
        chunks.append(chunk)
    if oversize:
        return None, too_large
    try:
        return json.loads(b"".join(chunks)), None
    except (ValueError, RecursionError):
        return None, JSONResponse({"layer": None, "message": "a challenge is JSON"}, status_code=400)


@mcp.custom_route("/.well-known/vlei/pop", methods=["POST"])
async def proof_of_possession(request: Request) -> JSONResponse:
    """A client's challenge, answered with this server's LE key (`mcp_vlei.pop`).

    A slot is claimed before anything that can await — including reading the body — so a client
    cannot hold one open merely by sending slowly; signing itself is serialised, one challenge at
    a time, since it runs through a single keystore.
    """
    if _POP_WAITING["n"] >= _POP_MAX_WAITING:
        return JSONResponse({"layer": None, "message": "busy: try again in a few seconds"},
                            status_code=503)
    _POP_WAITING["n"] += 1
    try:
        body, refusal = await _read_pop_challenge(request)
        if refusal is not None:
            return refusal
        async with _POP_GATE:
            status, payload = await anyio.to_thread.run_sync(vlei.pop_response, body)
        return JSONResponse(payload, status_code=status)
    finally:
        _POP_WAITING["n"] -= 1


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
