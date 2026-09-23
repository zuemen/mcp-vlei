"""End-to-end acceptance tests against a live association-server.

Each test prints its layer-by-layer outcome, because these are also the demo: the recording in
``docs/DEMO.md`` shows this output. A test that only asserted "refused" would pass while the thing
being demonstrated — that the *reason* is legible and specific — was broken.

Prerequisites::

    bash scripts/bootstrap-credentials.sh
    python examples/association-server/server.py &

Run::

    pytest examples/association-server/tests -v -s
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_vlei import VleiClient
from mcp_vlei.signing import Signer, sign_request

ROOT = Path(__file__).resolve().parents[3]
CREDENTIALS = ROOT / "credentials"
KEYS = ROOT / "examples" / "my-agent" / "keys"
SERVER = os.environ.get("MCP_SERVER_URL", "http://localhost:8080")

pytestmark = pytest.mark.anyio


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


def show(title: str, **fields: Any) -> None:
    print(f"\n  {title}")
    for key, value in fields.items():
        print(f"    {key:<16} {value}")


async def make_session(env: dict[str, Any], **overrides: Any) -> VleiClient:
    from mcp.client.http import http_client
    from mcp.client.session import ClientSession

    read, write = await http_client(f"{SERVER}/mcp").__aenter__()
    raw = await ClientSession(read, write).__aenter__()
    kwargs = dict(
        credential=CREDENTIALS / "ecr.cesr",
        key_store=KEYS,
        delegated_aid=env.get("agentAid") or env["ecrAid"],
        accepted_roots=env["acceptedRoots"],
        verifier_url=env["verifierUrl"],
        role=env.get("role"),
    )
    kwargs.update(overrides)
    return VleiClient(raw, **kwargs)


# --------------------------------------------------------------------------------------------- #
# 1. With a credential, the protected tool succeeds
# --------------------------------------------------------------------------------------------- #

@requires_stack
async def test_1_register_member_with_credential(env):
    session = await make_session(env)
    identity = await session.connect()
    show("stage 2 — server LE verified",
         lei=identity.lei, source=identity.source, root=identity.root_aid)

    await session.list_tools()
    entitlement = session.entitlement_for("register_member")
    show("stage 4 — entitlement", verdict=str(entitlement), role=session.role)
    assert entitlement, entitlement.reason

    result = await session.call_tool(
        "register_member", {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
    )
    show("stage 6 — result", isError=_is_error(result), text=_text(result)[:120])
    assert not _is_error(result)


# --------------------------------------------------------------------------------------------- #
# 2. Without a credential, the protected tool is refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
async def test_2_register_member_without_credential(env):
    session = await make_session(env)
    await session.connect()
    await session.list_tools()

    # present=False suppresses the credential while leaving everything else identical.
    result = await session.call_tool(
        "register_member", {"name": "Nobody", "email": "nobody@example.org"}, present=False
    )
    show("refused", layer=_layer(result), text=_text(result)[:120])
    assert _is_error(result)
    assert _layer(result) == "missing_credential"


@requires_stack
async def test_2b_public_tool_needs_no_credential(env):
    session = await make_session(env)
    await session.connect()
    await session.list_tools()

    result = await session.call_tool("list_events", {}, present=False)
    show("public tool", isError=_is_error(result))
    assert not _is_error(result)


# --------------------------------------------------------------------------------------------- #
# 3. After revocation from the dashboard, the same call is refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
async def test_3_revoked_credential_is_refused(env):
    async with httpx.AsyncClient(timeout=60) as http:
        revoke = await http.post(f"{SERVER}/api/revoke")
    show("dashboard", revoked=revoke.json().get("ok"))
    assert revoke.json().get("ok"), revoke.text

    session = await make_session(env)
    await session.connect()
    await session.list_tools()
    result = await session.call_tool(
        "register_member", {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
    )
    show("refused", layer=_layer(result), text=_text(result)[:120])
    assert _is_error(result)
    assert _layer(result) == "revoked"


# --------------------------------------------------------------------------------------------- #
# 4. Arguments altered after signing are refused
# --------------------------------------------------------------------------------------------- #

@requires_stack
async def test_4_tampered_arguments_are_refused(env):
    """Sign one set of arguments, send another — the gap the digest exists to close."""
    session = await make_session(env)
    await session.connect()
    await session.list_tools()

    signer = Signer.from_key_store(str(KEYS), env.get("agentAid") or env["ecrAid"])
    honest = {"name": "Chen Wei-Ting", "email": "weiting@example.org.tw"}
    signature = sign_request(signer, "tools/call", {"name": "register_member", "arguments": honest})

    tampered = {"name": "Someone Else", "email": "attacker@example.org"}
    result = await session._session.call_tool(
        "register_member",
        tampered,
        meta={
            "org.gleif.vlei/credential": (CREDENTIALS / "ecr.cesr").read_text().strip(),
            "org.gleif.vlei/delegatedAid": env.get("agentAid") or env["ecrAid"],
            "org.gleif.vlei/signature": signature,
        },
    )
    show("refused", layer=_layer(result), text=_text(result)[:120])
    assert _layer(result) == "digest_mismatch"


# --------------------------------------------------------------------------------------------- #
# 5. An unmodified host connects to the same server — the backward-compatibility claim
# --------------------------------------------------------------------------------------------- #

@requires_stack
async def test_5_unmodified_client_is_additive(env):
    """No vLEI support at all: connects, lists tools, public tool works, protected one does not.

    This is the executable form of the Backward Compatibility section of the specification, and
    the same sequence Claude Desktop performs in the recording.
    """
    from mcp.client.http import http_client
    from mcp.client.session import ClientSession

    async with http_client(f"{SERVER}/mcp") as (read, write):
        async with ClientSession(read, write) as plain:
            await plain.initialize()

            tools = await plain.list_tools()
            names = [getattr(t, "name", None) or t["name"] for t in getattr(tools, "tools", tools)]
            show("unmodified client", connected=True, tools=names)
            assert "list_events" in names and "register_member" in names

            public = await plain.call_tool("list_events", {})
            assert not _is_error(public)

            protected = await plain.call_tool(
                "register_member", {"name": "X", "email": "x@example.org"}
            )
            show("protected tool", layer=_layer(protected))
            assert _is_error(protected)
            assert _layer(protected) == "missing_credential"


# --------------------------------------------------------------------------------------------- #

def _is_error(result: Any) -> bool:
    return bool(getattr(result, "isError", None) or (isinstance(result, dict) and result.get("isError")))


def _text(result: Any) -> str:
    content = getattr(result, "content", None) or (result.get("content") if isinstance(result, dict) else [])
    for item in content:
        text = getattr(item, "text", None) or (item.get("text") if isinstance(item, dict) else None)
        if text:
            return text
    return ""


def _layer(result: Any) -> str:
    return _text(result).split(":", 1)[0].strip()
