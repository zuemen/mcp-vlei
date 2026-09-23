"""End-to-end acceptance tests against a live association-server.

Each test prints its layer-by-layer outcome, because these are also the demo: the recording in
``docs/DEMO.md`` shows this output. A test that only asserted "refused" would pass while the thing
being demonstrated — that the *reason* is legible and specific — was broken.

Prerequisites::

    bash scripts/bootstrap-credentials.sh
    python examples/association-server/server.py

Run::

    pytest examples/association-server/tests -v -s
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.client.client import Client

from mcp_vlei import VleiCapability, VleiClient
from mcp_vlei.signing import sign_request

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "my-agent"))
from kli_signer import agent_signer  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
CREDENTIALS = ROOT / "credentials"
SERVER = os.environ.get("MCP_SERVER_URL", "http://localhost:8080")
MCP_URL = f"{SERVER}/mcp"


def _server_up() -> bool:
    try:
        return httpx.get(f"{SERVER}/.well-known/vlei", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


requires_stack = pytest.mark.skipif(
    not (CREDENTIALS / "env.json").exists() or not _server_up(),
    reason="run scripts/bootstrap-credentials.sh and start association-server first",
)


@pytest.fixture(scope="module")
def env() -> dict[str, Any]:
    return json.loads((CREDENTIALS / "env.json").read_text())


@pytest.fixture(autouse=True)
def presented(env: dict[str, Any]) -> None:
    """Present the ECR credential to the verifier before each test.

    Presentation is the **holder's** step — the verifier requires headers signed by the AID the
    credential was issued to, which a relying party cannot produce. The server then only reads
    back what that established.

    It runs before every test rather than once because vlei-verifier 1.0.0 crashes on its own
    revocation path and comes back with an empty database (see scripts/README.md), and a test that
    silently depended on a previous test's presentation would fail in a way that looks like a
    credential problem.
    """
    import subprocess

    compose = str(ROOT / "scripts" / "docker-compose.yml")
    subprocess.run(
        ["docker", "compose", "-f", compose, "exec", "-T", "keri-cli",
         "python", "/keri-config/present.py", "present", "ecr", "ecr", env["ecrSaid"],
         "/credentials/ecr.cesr", "http://vlei-verifier:7676", "http://witness-demo:5642"],
        capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV="1"), timeout=180,
    )


def show_report(result: Any) -> None:
    """Print the layer-by-layer report the server attached to its answer.

    This is the recording: a viewer sees which checks ran, which one stopped the call, and that the
    ones before it passed. A single line saying `revoked` is correct and unconvincing.
    """
    report = (getattr(result, "meta", None) or {}).get("org.gleif.vlei/report")
    if not report:
        return
    marks = {True: "+", False: "x", None: "-"}
    print(f"
  verifying {report['tool']}")
    for check in report["checks"]:
        mark = marks[check["passed"]]
        tail = check["layer"] or f"{check['durationMs']:6.1f} ms"
        print(f"    {mark} {check['label']:<44} {tail}")
        if check["passed"] is False and check["detail"]:
            print(f"      {check['detail']}")
    for caveat in report["caveats"]:
        print(f"    ! {caveat}")
    verdict = f"REFUSED: {report['layer']}" if report["layer"] else "ALLOWED"
    identity = report["identity"]
    suffix = " ".join(filter(None, [identity["lei"], identity["role"]]))
    print(f"  {verdict}{'  ' + suffix if suffix and not report['layer'] else ''}")


def show(title: str, **fields: Any) -> None:
    print(f"\n  {title}")
    for key, value in fields.items():
        print(f"    {key:<16} {value}")


@asynccontextmanager
async def vlei_session(env: dict[str, Any], **overrides: Any):
    """A VleiClient over a real streamable-HTTP session."""
    # `Client`, not a bare `ClientSession`: extensions are only active at protocol 2026-07-28,
    # which the high-level client negotiates and the bare handshake does not.
    async with Client(MCP_URL, extensions=[VleiCapability()]) as raw:
        kwargs: dict[str, Any] = dict(
            credential=CREDENTIALS / "ecr.cesr",
            credential_said=env["ecrSaid"],
            # The key stays in the KERI keystore; this signer asks it for signatures.
            signer=agent_signer(),
            delegated_aid=env.get("agentAid") or env["ecrAid"],
            accepted_roots=env["acceptedRoots"],
            verifier_url=env["verifierUrl"],
            role=env.get("role"),
            # Mode (a): the client checks the server's LE credential itself — chain, SAIDs and
            # root — because a relying party cannot present a counterparty's credential to the
            # holder-facing `/presentations` API.
            verify_server=True,
            on_unverified_server="stop",
        )
        kwargs.update(overrides)
        yield VleiClient(raw, **kwargs)


# --------------------------------------------------------------------------------------------- #
# 1. With a credential, the protected tool succeeds
# --------------------------------------------------------------------------------------------- #

@requires_stack
@pytest.mark.anyio
async def test_1_register_member_with_credential(env):
    async with vlei_session(env) as session:
        identity = await session.connect()
        show(
            "stage 2 — server LE verified offline",
            lei=identity.lei,
            root=identity.root_aid,
            source=identity.source,
            revocationChecked=identity.revocation_checked,
            signaturesChecked=identity.signatures_checked,
        )
        assert identity.lei

        await session.list_tools()
        entitlement = session.entitlement_for("register_member")
        show("stage 4 — entitlement", verdict=str(entitlement), role=session.role)
        assert entitlement, entitlement.reason

        result = await session.call_tool(
            "register_member", {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
        )
        show_report(result)
        show("stage 6 — result", isError=result.is_error, text=_text(result)[:120])
        assert not result.is_error


# --------------------------------------------------------------------------------------------- #
# 2. Without a credential, the protected tool is refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
@pytest.mark.anyio
async def test_2_register_member_without_credential(env):
    async with vlei_session(env) as session:
        await session.connect()
        await session.list_tools()

        # present=False suppresses the credential while leaving everything else identical.
        result = await session.call_tool(
            "register_member", {"name": "Nobody", "email": "nobody@example.org"}, present=False
        )
        show_report(result)
        show_report(result)
    show("refused", layer=_layer(result), text=_text(result)[:120])
        assert result.is_error
        assert _layer(result) == "missing_credential"


@requires_stack
@pytest.mark.anyio
async def test_2b_public_tool_needs_no_credential(env):
    async with vlei_session(env) as session:
        await session.connect()
        await session.list_tools()

        result = await session.call_tool("list_events", {}, present=False)
        show("public tool", isError=result.is_error)
        assert not result.is_error


# --------------------------------------------------------------------------------------------- #
# 3. After revocation from the dashboard, the same call is refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
@pytest.mark.anyio
async def test_3_revoked_credential_is_refused(env):
    async with httpx.AsyncClient(timeout=120) as http:
        revoke = await http.post(f"{SERVER}/api/revoke")
    show("dashboard", revoked=revoke.json().get("ok"))
    assert revoke.json().get("ok"), revoke.text

    async with vlei_session(env) as session:
        await session.connect()
        await session.list_tools()
        result = await session.call_tool(
            "register_member", {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
        )
        show_report(result)
        show_report(result)
    show("refused", layer=_layer(result), text=_text(result)[:120])
        assert result.is_error
        assert _layer(result) == "revoked"


# --------------------------------------------------------------------------------------------- #
# 4. Arguments altered after signing are refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
@pytest.mark.anyio
async def test_4_tampered_arguments_are_refused(env):
    """Sign one set of arguments, send another — the gap the digest exists to close."""
    signer = agent_signer()
    honest = {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
    signature = sign_request(
        signer, "tools/call", {"name": "register_member", "arguments": honest}
    )
    meta = {
        "org.gleif.vlei/credential": (CREDENTIALS / "ecr.cesr").read_text().strip(),
        "org.gleif.vlei/delegatedAid": env.get("agentAid") or env["ecrAid"],
        "org.gleif.vlei/signature": signature,
        "org.gleif.vlei/verkey": signer.verkey,
        "org.gleif.vlei/credentialSaid": env["ecrSaid"],
    }

    async with Client(MCP_URL, extensions=[VleiCapability()]) as raw:
        result = await raw.call_tool(
            "register_member",
            {"name": "Someone Else", "email": "attacker@example.org"},
            meta=meta,
        )
    show_report(result)
    show("refused", layer=_layer(result), text=_text(result)[:120])
    assert _layer(result) == "digest_mismatch"


# --------------------------------------------------------------------------------------------- #
# 5. An unmodified host connects to the same server — the backward-compatibility claim
# --------------------------------------------------------------------------------------------- #

@requires_stack
@pytest.mark.anyio
async def test_5_unmodified_client_is_additive(env):
    """No vLEI support at all: connects, lists tools, public tool works, protected one does not.

    This is the executable form of the Backward Compatibility section of the specification, and the
    same sequence Claude Desktop performs in the recording.
    """
    # No extensions declared at all — an ordinary client that knows nothing about vLEI.
    async with Client(MCP_URL) as plain:
        tools = await plain.list_tools()
        names = [t.name for t in tools.tools]
        show("unmodified client", connected=True, tools=names)
        assert "list_events" in names and "register_member" in names

        public = await plain.call_tool("list_events", {})
        assert not public.is_error

        protected = await plain.call_tool(
            "register_member", {"name": "X", "email": "x@example.org"}
        )
        show_report(protected)
        show("protected tool", layer=_layer(protected))
        assert protected.is_error
        assert _layer(protected) == "missing_credential"


# --------------------------------------------------------------------------------------------- #

def _text(result: Any) -> str:
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            return text
    return ""


def _layer(result: Any) -> str:
    return _text(result).split(":", 1)[0].strip()
