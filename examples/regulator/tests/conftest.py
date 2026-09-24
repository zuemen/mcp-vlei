"""Shared harness for the regulator scenario — no Docker, no network beyond 127.0.0.1.

The KERI world is real: ``mcp_vlei.testing.World`` mints key event logs, transaction event logs and
chained ACDCs, and serves them over an ``httpx.MockTransport`` shaped like a witness. vlei-authz
runs the package's own verification against that witness; nothing in the decision path is stubbed.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, AsyncIterator

import httpx
import pytest

REGULATOR = Path(__file__).resolve().parents[1]
ROOT = REGULATOR.parents[1]

sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))
sys.path.insert(0, str(REGULATOR))

from mcp_vlei import Signer, VleiIdentity  # noqa: E402
from mcp_vlei.extension import (  # noqa: E402
    META_CREDENTIAL,
    META_CREDENTIAL_SAID,
    META_DELEGATED_AID,
    META_SIGNATURE,
)
from mcp_vlei.signing import sign_request  # noqa: E402
from mcp_vlei.testing import Controller, World  # noqa: E402

ARGS = {"form": "A1", "period": "2026Q2", "payload": {"totalAssets": 84_200_000}}


def load(name: str, path: Path) -> ModuleType:
    """Import a file whose directory is not a package (``vlei-authz``, ``filing-server``)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


authz = load("regulator_vlei_authz", REGULATOR / "vlei-authz" / "service.py")
filing = load("regulator_filing_server", REGULATOR / "filing-server" / "server.py")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if inspect.iscoroutinefunction(getattr(item, "function", None)):
            item.add_marker(pytest.mark.anyio)


# ------------------------------------------------------------------------------------------- #
# A world, and a vlei-authz verifying against it
# ------------------------------------------------------------------------------------------- #

@pytest.fixture
def world() -> World:
    return World(role="regulatory-filing", label="regulator")


def identity_for(
    world: World, tmp_path: Path, *, client: httpx.AsyncClient | None = None
) -> VleiIdentity:
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    return VleiIdentity(
        le_credential=le,
        accepted_roots=[world.root.pre],
        witness_url="http://witness",
        witness_client=client or world.witness_client(),
        revocation_source="tel",
    )


def authz_app(world: World, tmp_path: Path, **kwargs: Any):
    policy = authz.load_policy(authz.HERE / "policy.json")
    audit = authz.Audit(path=tmp_path / "audit" / "decisions.jsonl")
    return authz.create_app(
        identity=identity_for(world, tmp_path, **kwargs), policy=policy, audit=audit
    )


def signer_for(controller: Controller) -> Signer:
    return Signer.from_seed(controller.pre, controller.seed)


def signed_meta(
    world: World,
    tool: str = "submit_filing",
    arguments: dict[str, Any] | None = None,
    *,
    signer: Signer | None = None,
    delegated: str | None = "agent",
    stream: str | None = None,
) -> dict[str, Any]:
    """What an agent puts in ``params._meta``: by default the holder's delegate presenting the ECR."""
    signer = signer or signer_for(world.agent)
    arguments = ARGS if arguments is None else arguments
    meta: dict[str, Any] = {
        META_CREDENTIAL: world.ecr_stream if stream is None else stream,
        META_SIGNATURE: sign_request(signer, "tools/call", {"name": tool, "arguments": arguments}),
        META_CREDENTIAL_SAID: world.ecr_credential.said,
    }
    if delegated == "agent":
        meta[META_DELEGATED_AID] = world.agent.pre
    elif delegated:
        meta[META_DELEGATED_AID] = delegated
    return meta


def rpc(tool: str, arguments: dict[str, Any], meta: dict[str, Any] | None = None, id: int = 1) -> bytes:
    params: dict[str, Any] = {"name": tool, "arguments": arguments}
    if meta is not None:
        params["_meta"] = meta
    return json.dumps({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}).encode()


# ------------------------------------------------------------------------------------------- #
# Real servers on 127.0.0.1, in the test's own event loop
# ------------------------------------------------------------------------------------------- #

@asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    """Run an ASGI app under uvicorn on a free port; yield its base URL."""
    import uvicorn

    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning", lifespan="on",
        timeout_graceful_shutdown=2,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        if task.done():
            task.result()
            raise RuntimeError("server exited before it started")
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)
