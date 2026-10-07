"""The credential proxy against the regulator scenario's own harness — no Docker.

The KERI world is real (``mcp_vlei.testing.World``): the proxy verifies the gateway's published LE
against the world's witness, signs with the world's agent key, and the stand-in gateway runs
vlei-authz's actual decision over every call before the labour-insurance simulator sees it.
"""

from __future__ import annotations

import importlib.util
import inspect
import io
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

PROXY_DIR = Path(__file__).resolve().parents[1]
ROOT = PROXY_DIR.parents[1]
sys.path.insert(0, str(PROXY_DIR))

# As deploy/agentgateway/docker-compose.yml sets it: without a namespace the simulator publishes no
# requirement, and the proxy would rightly present nothing. Read when the simulator is imported.
os.environ.setdefault("MCP_VLEI_NAMESPACE", "org.gleif.vlei")

# The regulator harness under a name of its own: its conftest.py is not this one.
_spec = importlib.util.spec_from_file_location(
    "regulator_harness", ROOT / "examples" / "regulator" / "tests" / "conftest.py"
)
assert _spec and _spec.loader
harness = importlib.util.module_from_spec(_spec)
sys.modules["regulator_harness"] = harness
_spec.loader.exec_module(harness)

import proxy  # noqa: E402
from mcp_vlei import Signer  # noqa: E402
from mcp_vlei.testing import LEI, World  # noqa: E402


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if inspect.iscoroutinefunction(getattr(item, "function", None)):
            item.add_marker(pytest.mark.anyio)


@pytest.fixture
def world() -> World:
    return World(role="labor-insurance-filing", label="proxy")


def write_profile(root: Path, world: World, name: str = "demo", **extra: Any) -> proxy.Profile:
    """A credentials folder under ``root`` as the bootstrap scripts leave it, for ``world``'s agent."""
    folder = proxy.profile_folders(root)[name]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "ecr.cesr").write_text(world.ecr_stream, encoding="utf-8")
    env = {
        "agentAid": world.agent.pre, "ecrSaid": world.ecr_credential.said, "lei": LEI,
        "leName": "Demo Staffing Co., Ltd. (fictional)", "role": world.role,
        "acceptedRoots": [world.root.pre], **extra,
    }
    (folder / "env.json").write_text(json.dumps(env), encoding="utf-8")
    return proxy.load_profile(name, root)


def relay_for(world: World, profile: proxy.Profile, gateway: Any, log_path: Path,
              *, signer_world: World | None = None, **kwargs: Any) -> proxy.Relay:
    """A relay signing as ``signer_world``'s agent (default ``world``'s), reading ``world``'s witness
    (one, unless ``kwargs`` names ``witness_url``/``witness_client`` of its own — a test with its own
    multi-witness setup), and trusting ``world``'s root for the gateway's LE."""
    signer_world = signer_world or world
    kwargs.setdefault("witness_url", "http://witness")
    kwargs.setdefault("witness_client", world.witness_client())
    return proxy.Relay(
        profile, gateway,
        signer=Signer.from_seed(signer_world.agent.pre, signer_world.agent.seed),
        accepted_roots=[world.root.pre],
        log=proxy.RelayLog(log_path, stream=io.StringIO()),
        reload=lambda: profile,
        **kwargs,
    )


@asynccontextmanager
async def stand_in(world: World, tmp_path: Path, *, published: World | None = None,
                   pop_signer: Any = None, document: dict | None = None) -> AsyncIterator[str]:
    """The stand-in gateway in front of the simulator. Its vlei-pop publishes ``published``'s LE
    (default ``world``'s) and answers challenges as that operator's delegated gateway AID, or as
    ``pop_signer``. With ``document``, a v0.2 gateway instead: that document at /.well-known/vlei,
    and no proof of possession. Yields the MCP endpoint URL."""
    harness.labor.INSURED.clear()
    authz = harness.authz_app(world, tmp_path)
    pop = None if document is not None else harness.pop_app(published or world, signer=pop_signer)
    async with harness.serve(harness.labor.create_app()) as upstream:
        app = harness.stand_in_gateway(authz, upstream, published=document, pop=pop)
        async with harness.serve(app) as base:
            harness.answer_at(authz, f"{base}/mcp")
            if pop is not None:
                pop.state.set_audience_urls([f"{base}/mcp"])
            yield f"{base}/mcp"
