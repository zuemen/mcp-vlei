"""The namespace is configuration: the same verification under another name, and a clear refusal
when the two parties do not share one.

`org.gleif.vlei` is a provisional, demonstration namespace (see `mcp_vlei.namespace`). Everything
the extension puts on the wire is built from `MCP_VLEI_NAMESPACE`, so a change of name is a change
of configuration — and these tests hold that to be true of the verification itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from mcp.shared.exceptions import MCPError

from conftest import Ctx, make_params  # noqa: E402
from mcp_vlei import namespace
from mcp_vlei.namespace import DEFAULT, keys, valid
from mcp_vlei.testing import World
from test_extension import ARGS, REQUIRES_FILING, REQUIRES_REGISTRATION, build, call_next, layer_of, present

OTHER = "net.zuemen.vlei"
SRC = Path(__file__).resolve().parents[1] / "src" / "mcp_vlei"
EXAMPLES = Path(__file__).resolve().parents[3] / "examples"


# --------------------------------------------------------------------------------------------- #
# The name itself
# --------------------------------------------------------------------------------------------- #

def test_the_default_is_provisional_and_the_environment_overrides_it(monkeypatch):
    monkeypatch.delenv(namespace.ENV, raising=False)
    assert namespace.current() == DEFAULT == "org.gleif.vlei"
    monkeypatch.setenv(namespace.ENV, OTHER)
    assert namespace.current() == OTHER
    assert keys().extension == "net.zuemen.vlei/identity"


def test_every_name_on_the_wire_is_built_from_the_namespace():
    k = keys(OTHER)
    names = [k.extension, k.credential, k.credential_said, k.delegated_aid, k.signature,
             k.attestation, k.requires, k.failure, k.report]
    assert all(n.startswith(OTHER + "/") for n in names)
    assert len(set(names)) == len(names)


@pytest.mark.parametrize("name", ["io.modelcontextprotocol", "dev.mcp", "org.mcp.tools",
                                  "com.modelcontextprotocol.api"])
def test_prefixes_mcp_reserves_are_refused(name):
    """MCP 2026-07-28: any prefix whose second label is `modelcontextprotocol` or `mcp`."""
    assert not valid(name)


@pytest.mark.parametrize("name", ["vlei", "org..vlei", "1org.vlei", "org.vlei-", "org.vlei/x", ""])
def test_a_namespace_must_be_a_reverse_domain_name(name, monkeypatch):
    assert not valid(name)
    if name:
        monkeypatch.setenv(namespace.ENV, name)
        with pytest.raises(ValueError, match=namespace.ENV):
            namespace.current()


def test_com_example_mcp_is_not_reserved():
    assert valid("com.example.mcp")


# --------------------------------------------------------------------------------------------- #
# The same verification, under another name
# --------------------------------------------------------------------------------------------- #

def _renamed(params, ns: str):
    """The same call with its `_meta` keys moved to `ns` — values, signature and all, unchanged."""
    meta = {k.replace(DEFAULT + "/", ns + "/", 1): v for k, v in (params.meta or {}).items()}
    return make_params(params.name, params.arguments or {}, meta)


async def _outcomes(ns: str, tmp_path: Path) -> list[tuple]:
    """The main flow, in one namespace: allowed, tampered, wrong role, no credential, revoked."""
    results = []
    tmp_path.mkdir(parents=True, exist_ok=True)
    k = keys(ns)
    ctx = Ctx(declared=[k.extension])
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION,
                                  "submit_filing": REQUIRES_FILING}, namespace=ns)

    async def run(params):
        result = await ext.intercept_tool_call(_renamed(params, ns), ctx, call_next)
        report = (result.meta or {}).get(k.report) or {}
        checks = tuple((c["name"], c.get("passed")) for c in report.get("checks", []))
        return (result.is_error, layer_of(result) if result.is_error else "ran", checks)

    results.append(await run(present(world, "register_member", ARGS)))
    signed = present(world, "register_member", ARGS)
    results.append(await run(make_params("register_member", {"name": "B", "email": "b@example.org"},
                                         signed.meta)))
    results.append(await run(present(world, "submit_filing", {"form": "A1"})))
    results.append(await run(make_params("register_member", ARGS)))
    world.le_registry.revoke(world.ecr_credential.said)
    results.append(await run(present(world, "register_member", ARGS)))
    return results


async def test_the_main_flow_gives_the_same_results_under_another_namespace(tmp_path):
    default = await _outcomes(DEFAULT, tmp_path / "a")
    other = await _outcomes(OTHER, tmp_path / "b")

    assert [o[:2] for o in default] == [
        (False, "ran"), (True, "digest_mismatch"), (True, "role_mismatch"),
        (True, "missing_credential"), (True, "revoked"),
    ]
    assert other == default


async def test_the_server_advertises_and_answers_under_its_own_namespace(tmp_path):
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, namespace=OTHER)
    assert ext.identifier == "net.zuemen.vlei/identity"
    assert ext.keys.report == "net.zuemen.vlei/report"
    result = await ext.intercept_tool_call(
        make_params("register_member", ARGS), Ctx(declared=[keys(OTHER).extension]), call_next)
    assert set(result.meta or {}) <= {keys(OTHER).failure, keys(OTHER).report}


# --------------------------------------------------------------------------------------------- #
# Two parties, two names: not declared, so -32021
# --------------------------------------------------------------------------------------------- #

async def test_a_client_that_declared_another_namespace_gets_32021(tmp_path):
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, namespace=OTHER)
    with pytest.raises(MCPError) as caught:
        await ext.intercept_tool_call(
            _renamed(present(world, "register_member", ARGS), DEFAULT),
            Ctx(declared=[keys(DEFAULT).extension]), call_next)

    assert caught.value.error.code == -32021
    required = caught.value.error.data["requiredCapabilities"]
    assert required == {"extensions": {"net.zuemen.vlei/identity": {}}}


async def test_a_client_that_declared_nothing_gets_32021_for_a_protected_tool(tmp_path):
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    with pytest.raises(MCPError) as caught:
        await ext.intercept_tool_call(make_params("register_member", ARGS), Ctx(declared=[]),
                                      call_next)
    assert caught.value.error.code == -32021


async def test_a_public_tool_needs_no_declaration_in_any_namespace(tmp_path):
    """Additive: a client that has never heard of the extension still reaches public tools."""
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, namespace=OTHER)
    result = await ext.intercept_tool_call(make_params("list_events", {}), Ctx(declared=[]),
                                           call_next)
    assert result.is_error is False


# --------------------------------------------------------------------------------------------- #
# A requirement written under another namespace is a misconfiguration, never a public tool
# --------------------------------------------------------------------------------------------- #

class _Registry:
    """A server's tool registry, as `requirement_for` reads it."""

    def __init__(self, tools):
        self._tools = tools

    async def list_tools(self):
        return self._tools


async def test_a_requirement_under_another_namespace_is_refused_not_served_as_public(tmp_path):
    """A tool copied from an example that names the default namespace, on a server configured with
    another: the requirement is not found under the server's name — and the tool must not run."""
    from types import SimpleNamespace

    world = World()
    ext = build(world, tmp_path, None, namespace=OTHER)
    ext._server = _Registry([SimpleNamespace(
        name="register_member",
        meta={keys(DEFAULT).requires: {"credential": "ECR", "role": "member-registration"}})])

    result = await ext.intercept_tool_call(make_params("register_member", ARGS),
                                           Ctx(declared=[]), call_next)
    assert result.is_error is True
    assert "TOOL RAN" not in result.content[0].text
    assert keys(DEFAULT).requires in result.content[0].text and OTHER in result.content[0].text


async def test_the_whoami_fallback_names_the_servers_own_namespace(tmp_path):
    world = World()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, namespace=OTHER)
    assert keys(OTHER).requires in ext._whoami_tool()


def test_a_bad_environment_does_not_stop_the_package_importing():
    """An invalid MCP_VLEI_NAMESPACE is an error where the namespace is used — constructing a
    server without one — not an import failure for everyone who passes their own."""
    import os
    import subprocess
    import sys

    code = ("import mcp_vlei, mcp_vlei.extension, mcp_vlei.client; "
            "from mcp_vlei.namespace import keys; print(keys('net.zuemen.vlei').extension)")
    env = {**os.environ, "MCP_VLEI_NAMESPACE": "dev.mcp"}
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr[-400:]
    assert done.stdout.strip() == "net.zuemen.vlei/identity"


# --------------------------------------------------------------------------------------------- #
# No name written into the code
# --------------------------------------------------------------------------------------------- #

def _literals(path: Path) -> list[str]:
    """String constants in `path`, docstrings excepted."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def test_no_code_writes_the_namespace_itself():
    """Only `namespace.py` names it. Tests and example JSON are exempt; everything else builds
    names from `mcp_vlei.namespace`."""
    offenders = []
    files = [p for p in SRC.rglob("*.py") if p.name != "namespace.py"]
    files += [p for p in EXAMPLES.rglob("*.py") if "tests" not in p.parts]
    for path in files:
        for literal in _literals(path):
            if DEFAULT in literal:  # the bare name too: NS + "/requires" is the same constant
                offenders.append(f"{path.relative_to(SRC.parents[3])}: {literal[:60]!r}")
    for path in EXAMPLES.rglob("*.js"):
        if DEFAULT in path.read_text(encoding="utf-8"):
            offenders.append(f"{path.relative_to(SRC.parents[3])}: names the namespace")
    assert not offenders, "\n".join(offenders)


# --------------------------------------------------------------------------------------------- #
# Through a real server: near-miss keys, the diagnostic tool, the module's names
# --------------------------------------------------------------------------------------------- #

def _real_server(tmp_path: Path, namespace: str | None = None):
    from mcp.server.mcpserver import MCPServer

    world = World()
    ext = build(world, tmp_path, None, namespace=namespace)
    server = MCPServer(name="probe", version="0.0.1", extensions=[ext])
    ext.bind(server)
    return server, ext


@pytest.mark.parametrize("key", [DEFAULT + "/Requires", DEFAULT + "/requires ", "requires",
                                 "NET.ZUEMEN.VLEI/REQUIRES", " net.zuemen.vlei/requires"])
async def test_a_near_miss_requirement_key_is_refused_not_public(tmp_path, key):
    """A requirement key that is not exactly the server's — another case, a stray space, no
    prefix — is still a requirement someone meant. Read as none, the tool would be public."""
    from mcp.client.client import Client

    from mcp_vlei import VleiCapability

    server, _ = _real_server(tmp_path, OTHER)

    @server.tool(meta={key: {"credential": "ECR", "role": "member-registration"}})
    def guarded() -> str:
        return "GUARDED RAN"

    async with Client(server, extensions=[VleiCapability(namespace=OTHER)]) as client:
        result = await client.call_tool("guarded", {})
    assert result.is_error is True
    assert "GUARDED RAN" not in result.content[0].text


async def test_whoami_answers_through_the_real_sdk(tmp_path):
    """The diagnostic tool returns text; the SDK must not expect structured output from it."""
    from mcp.client.client import Client

    server, _ = _real_server(tmp_path)
    async with Client(server) as client:
        result = await client.call_tool("vlei_whoami", {})
    assert result.is_error is False
    assert result.content[0].text.startswith("unverified")


def test_the_module_lists_its_names():
    import mcp_vlei.extension as module

    assert {"EXTENSION_ID", "META_REQUIRES"} <= set(dir(module))


async def test_a_misnamed_tool_is_warned_about_once(tmp_path, caplog):
    from types import SimpleNamespace

    world = World()
    ext = build(world, tmp_path, None, namespace=OTHER)
    ext._server = _Registry([SimpleNamespace(name="t", meta={keys(DEFAULT).requires: {}}),
                             SimpleNamespace(name="public", meta={})])
    with caplog.at_level("WARNING", logger="mcp_vlei.extension"):
        for _ in range(3):
            await ext.requirement_for("public")
    assert sum("declares" in r.getMessage() for r in caplog.records) == 1
