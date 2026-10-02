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

from datetime import date  # noqa: E402

#: An enrolment filed on the start date. Simulated — not connected to the Bureau of Labor Insurance.
ARGS = {"person_ref": "EMP-0001", "start_date": date.today().isoformat(), "salary_grade": 3}


def load(name: str, path: Path) -> ModuleType:
    """Import a file whose directory is not a package (``vlei-authz``, ``labor-insurance-sim``)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


authz = load("regulator_vlei_authz", REGULATOR / "vlei-authz" / "service.py")
labor = load("regulator_labor_insurance_sim", REGULATOR / "labor-insurance-sim" / "server.py")


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
    return World(role="labor-insurance-filing", label="regulator")


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
    tool: str = "enroll_employee",
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

# ------------------------------------------------------------------------------------------- #
# A stand-in for agentgateway — also used by examples/credential-proxy/tests
# ------------------------------------------------------------------------------------------- #

from starlette.applications import Starlette  # noqa: E402
from starlette.background import BackgroundTask  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse, Response, StreamingResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

INCLUDE_RESPONSE_HEADERS = (
    "x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid", "x-vlei-report",
    "x-vlei-namespace",
)


def stand_in_gateway(authz, upstream: str, published: dict | None = None) -> Starlette:
    """agentgateway's extAuthz flow, as deploy/agentgateway/config.yaml sets it up. With
    ``published``, also its public ``/.well-known/vlei`` route, which no authorizer sees."""
    decide = httpx.AsyncClient(transport=httpx.ASGITransport(app=authz), base_url="http://vlei-authz")
    forward = httpx.AsyncClient(base_url=upstream, timeout=30)

    async def route(request: Request) -> Response:
        body = await request.body()
        decision = await decide.request(request.method, "/auth/mcp", content=body)
        if decision.status_code != 200:
            keep = {k: decision.headers[k] for k in ("content-type", "x-vlei-failure") if k in decision.headers}
            return Response(decision.content, status_code=decision.status_code, headers=keep)
        headers = [
            (k, v) for k, v in request.headers.items()
            if k not in ("host", "content-length", *INCLUDE_RESPONSE_HEADERS)
        ]
        headers += [(k, decision.headers.get(k, "")) for k in INCLUDE_RESPONSE_HEADERS]
        response = await forward.send(
            forward.build_request(request.method, "/mcp", headers=headers, content=body), stream=True
        )
        passed = {
            k: v for k, v in response.headers.items()
            if k in ("content-type", "mcp-session-id", "cache-control")
        }
        return StreamingResponse(
            response.aiter_raw(), status_code=response.status_code, headers=passed,
            background=BackgroundTask(response.aclose),
        )

    async def well_known(_: Request) -> Response:
        return JSONResponse(published)

    routes = [Route("/mcp", route, methods=["GET", "POST", "DELETE"])]
    if published is not None:
        routes.append(Route("/.well-known/vlei", well_known, methods=["GET"]))
    return Starlette(routes=routes)
