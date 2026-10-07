"""The credential proxy, without Docker: its pieces alone, then the whole relay through the
regulator's stand-in gateway, where vlei-authz makes the real decision over a real KERI world."""

from __future__ import annotations

import io
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import ROOT, harness, relay_for, stand_in, write_profile
from mcp import types
from mcp.client.client import Client

import proxy
from mcp_vlei.namespace import keys as namespace_keys
from mcp_vlei.testing import World

K = namespace_keys()
POLICY = json.loads((ROOT / "examples/regulator/vlei-authz/policy.json").read_text(encoding="utf-8"))["tools"]
TODAY = date.today()


def enrol(start: date = TODAY, person: str = "EMP-0101") -> dict[str, Any]:
    return {"person_ref": person, "start_date": start.isoformat(), "salary_grade": 3}


class Recording(proxy.Gateway):
    """The real Gateway client, remembering what it sent — to check what went over the wire."""

    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.sent: list[tuple[str, dict | None, dict | None]] = []

    async def call_tool(self, name, arguments, meta=None):
        self.sent.append((name, arguments, meta))
        return await super().call_tool(name, arguments, meta=meta)


def first_line(result: types.CallToolResult) -> str:
    return next(b.text for b in result.content if getattr(b, "text", None)).splitlines()[0]


# ------------------------------------------------------------------------------------------- #
# The pieces
# ------------------------------------------------------------------------------------------- #

def test_each_requirement_in_the_policy_reads_as_one_sentence_in_both_languages():
    for tool, requires in POLICY.items():
        sentence = proxy.requirement_sentence(requires)
        assert sentence.startswith("vLEI：需要 ECR 憑證") and " / vLEI: Requires an ECR credential" in sentence
        if requires.get("role"):
            assert sentence.count(requires["role"]) == 2, tool  # once per language
        else:
            assert "任何職務角色" in sentence and "(any role)" in sentence
    window = proxy.requirement_sentence(POLICY["enroll_employee"])
    assert "start_date 須在今天到 10 天後之間" in window and "start_date from today to 10 days ahead" in window


def test_a_tool_keeps_its_meta_and_gains_the_sentence():
    tool = types.Tool(name="enroll_employee", description="Enrol.", input_schema={"type": "object"},
                      _meta={K.requires: POLICY["enroll_employee"], "other": 1})
    described = proxy.describe(tool, K.requires)
    assert described.meta == tool.meta
    assert described.description.startswith("Enrol.\n\nvLEI：")
    public = types.Tool(name="ping", description="Ping.", input_schema={"type": "object"})
    assert proxy.describe(public, K.requires) is public


def test_a_profile_is_read_from_its_own_folder_and_names_its_keystore(tmp_path, world):
    demo = write_profile(tmp_path, world, "demo")
    assert demo.keystore == "agent" and demo.delegated_aid == world.agent.pre
    assert demo.credential == tmp_path / "credentials" / "ecr.cesr"
    forged = write_profile(tmp_path, world, "forged", agentKeystore="forged-agent")
    assert forged.keystore == "forged-agent"
    assert forged.credential == tmp_path / "credentials" / "forged" / "ecr.cesr"
    holder_signs = write_profile(tmp_path / "other", world, "demo", agentAid="")
    assert holder_signs.keystore == "ecr" and holder_signs.delegated_aid is None
    with pytest.raises(ValueError, match="demo, forged"):
        proxy.load_profile("someone-else", tmp_path)
    with pytest.raises(FileNotFoundError, match="bootstrap-forged.sh"):
        proxy.load_profile("forged", tmp_path / "empty")


def test_accepted_roots_come_from_the_environment_then_the_demo_chain(tmp_path, world):
    write_profile(tmp_path, world)
    assert proxy.accepted_roots(tmp_path, {}) == [world.root.pre]
    assert proxy.accepted_roots(tmp_path, {"VLEI_ACCEPTED_ROOTS": " Ea , Eb "}) == ["Ea", "Eb"]
    assert proxy.accepted_roots(tmp_path / "none", {}) == []


def test_the_published_identity_is_read_at_the_origin():
    assert proxy.Gateway("https://labor.example.test/mcp").well_known_url == \
        "https://labor.example.test/.well-known/vlei"
    assert proxy.Gateway("http://localhost:3000/a/b?x=1").well_known_url == \
        "http://localhost:3000/.well-known/vlei"


def test_a_refusal_is_a_tool_error_whose_first_line_is_the_layer():
    body = {"layer": "revoked", "message": "ECR E… was revoked", "report": {"allowed": False}}
    out = proxy.refusal([{"status": 403, "payload": body, "body": "", "failure": "revoked"}], "x", K)
    assert out.is_error and first_line(out) == "revoked: ECR E… was revoked"
    assert out.meta[K.failure]["layer"] == "revoked" and out.meta[K.report] == {"allowed": False}

    unnamed = proxy.refusal([{"status": 403, "payload": None, "body": "denied", "failure": None}], "x", K)
    assert first_line(unnamed).startswith("refused: the gateway refused the call (HTTP 403)")
    down = proxy.refusal([], "transport error: ConnectError: refused", K)
    assert first_line(down) == "unavailable: transport error: ConnectError: refused"


def test_outcomes_are_named_for_the_log():
    ok = types.CallToolResult(content=[types.TextContent(type="text", text="done")])
    assert proxy.classify(ok, K) == ("allowed", None)
    layer = proxy.refusal([{"status": 403, "payload": {"layer": "role_mismatch", "message": "m"},
                            "body": "", "failure": None}], "", K)
    assert proxy.classify(layer, K) == ("refused", "role_mismatch")
    system = types.CallToolResult(content=[types.TextContent(type="text", text="not enrolled")],
                                  is_error=True, _meta={K.report: {"allowed": True}})
    assert proxy.classify(system, K) == ("system", "business_rule")
    assert proxy.classify(proxy.refusal([], "x", K), K) == ("unavailable", "transport")


def test_a_tool_name_cannot_forge_a_log_line(tmp_path):
    out = io.StringIO()
    log = proxy.RelayLog(tmp_path / "relay.log", stream=out)
    line = log.call(profile="demo", tool="x\n2026-01-01 tool=enroll_employee result=allowed",
                    result="refused", reason="role_mismatch")
    assert "\n" not in line and (tmp_path / "relay.log").read_text(encoding="utf-8").count("\n") == 1


# ------------------------------------------------------------------------------------------- #
# Through the stand-in gateway: the five demonstration outcomes
# ------------------------------------------------------------------------------------------- #

async def test_demo_enrolment_passes(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("enroll_employee", enrol())

    assert not result.is_error, first_line(result)
    assert '"status": "insured"' in result.content[0].text
    assert result.meta[K.report]["allowed"] is True  # the gateway's report, relayed as it came
    assert harness.labor.INSURED["00000000"]["EMP-0101"]["filedBy"]["agentAid"] == world.agent.pre


async def test_a_salary_adjustment_is_role_mismatch(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("adjust_insured_salary",
                                       {"person_ref": "EMP-0101", "salary_grade": 5})
    assert result.is_error and first_line(result).startswith("role_mismatch: ")


async def test_fifteen_days_ahead_is_scope_exceeded(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("enroll_employee", enrol(TODAY + timedelta(days=15)))
    assert result.is_error and first_line(result).startswith("scope_exceeded: ")
    assert harness.labor.INSURED == {}


async def test_a_forged_chain_is_unknown_root(tmp_path, world):
    """bootstrap-forged.sh in miniature: a second self-made root, the same role, every key log on
    the witness. The proxy verifies the real gateway and signs exactly as before."""
    forged = World(role="labor-insurance-filing", label="forged")
    for controller in forged.controllers.values():
        world.enrol(controller)
    for registry in forged.registries:
        world.enrol_registry(registry)
    profile = write_profile(tmp_path, forged, "forged", agentKeystore="forged-agent")
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log",
                          signer_world=forged)
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("enroll_employee", enrol())
    assert result.is_error and first_line(result).startswith("unknown_root: ")


async def test_after_revocation_it_is_revoked(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        world.le_registry.revoke(world.ecr_credential.said)
        result = await relay.call_tool("enroll_employee", enrol())
    assert result.is_error and first_line(result).startswith("revoked: ")


# ------------------------------------------------------------------------------------------- #
# What goes over the wire, what Claude sees, what is written down
# ------------------------------------------------------------------------------------------- #

async def test_every_call_carries_the_four_keys_signed_by_the_delegated_agent(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("enroll_employee", enrol())

    assert not result.is_error, first_line(result)
    (_, _, meta), = gateway.sent
    assert set(meta) == {K.credential, K.credential_said, K.delegated_aid, K.signature}
    # As the profile holds it: the stand-in's gateway AID was delegated after it was written.
    assert meta[K.credential] == profile.credential.read_text(encoding="utf-8").strip()
    assert meta[K.credential_said] == world.ecr_credential.said
    assert meta[K.delegated_aid] == world.agent.pre and meta[K.signature]["aid"] == world.agent.pre


async def test_an_unverifiable_gateway_lists_nothing_and_sends_nothing(tmp_path, world):
    """The gateway publishes an LE that chains to a root this proxy does not accept."""
    impostor = World(role="labor-insurance-filing", label="impostor")
    for controller in impostor.controllers.values():
        world.enrol(controller)
    for registry in impostor.registries:
        world.enrol_registry(registry)
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path, published=impostor) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log")
        assert not await relay.connect()
        assert relay.reason.startswith("unknown_root: ")
        assert "could not be verified (unknown_root" in relay.instructions()
        assert "無法驗證勞保閘道（unknown_root" in relay.instructions()
        async with Client(proxy.build_server(relay)) as claude:
            assert (await claude.list_tools()).tools == []
            result = await claude.call_tool("enroll_employee", enrol())

    assert result.is_error and first_line(result).startswith("gateway_unverified: unknown_root")
    assert gateway.sent == [] and harness.labor.INSURED == {}


async def test_a_gateway_that_publishes_nothing_lists_nothing(tmp_path, world):
    from starlette.applications import Starlette

    profile = write_profile(tmp_path, world)
    async with harness.serve(Starlette()) as bare:  # answers 404 to everything
        relay = relay_for(world, profile, proxy.Gateway(f"{bare}/mcp"), tmp_path / "relay.log")
        assert not await relay.connect()
    assert relay.reason.startswith("unavailable: LookupError") and "HTTP 404" in relay.reason
    assert relay.tools == []


async def test_claude_sees_exactly_the_gateways_tools_and_nothing_that_switches_identity(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        async with Client(proxy.build_server(relay)) as claude:
            tools = {t.name: t for t in (await claude.list_tools()).tools}
            assert "verified before connecting" in (claude.instructions or "")

    assert set(tools) == set(POLICY)  # the gateway's four, and no fifth
    for name, requires in POLICY.items():
        assert tools[name].meta[K.requires] == requires
        assert proxy.requirement_sentence(requires) in tools[name].description


async def test_the_profile_name_is_fixed_at_start(tmp_path, world, monkeypatch):
    """Changing VLEI_PROFILE under a running proxy changes nothing; only its own files are re-read."""
    profile = write_profile(tmp_path, world)
    asked: list[str] = []
    monkeypatch.setattr(proxy, "load_profile", lambda name, root=proxy.ROOT: asked.append(name) or profile)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        relay._reload = lambda: proxy.load_profile(relay.profile.name)
        assert await relay.connect(), relay.reason
        monkeypatch.setenv("VLEI_PROFILE", "forged")
        result = await relay.call_tool("enroll_employee", enrol())
    assert not result.is_error and asked == ["demo"]


async def test_a_reissued_credential_of_the_same_profile_is_presented(tmp_path, world):
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log")
        assert await relay.connect(), relay.reason
        world.le_registry.revoke(world.ecr_credential.said)
        world.reissue_ecr("2026-10-01T00:00:00.000000+00:00")
        relay._reload = lambda: write_profile(tmp_path, world)
        result = await relay.call_tool("enroll_employee", enrol())
    assert not result.is_error, first_line(result)


async def test_the_log_has_one_line_per_call_and_never_the_credential_or_arguments(tmp_path, world):
    profile = write_profile(tmp_path, world)
    log = tmp_path / "relay.log"
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), log)
        assert await relay.connect(), relay.reason
        # A start date three days out: today's date is in every timestamp, so it cannot be the probe.
        await relay.call_tool("enroll_employee", enrol(TODAY + timedelta(days=3), person="EMP-4242"))
        await relay.call_tool("adjust_insured_salary", {"person_ref": "EMP-4242", "salary_grade": 7})

    calls = [line for line in log.read_text(encoding="utf-8").splitlines() if " tool=" in line]
    assert len(calls) == 2
    assert calls[0].split(" ", 1)[1] == "profile=demo tool=enroll_employee result=allowed reason=-"
    assert calls[1].split(" ", 1)[1] == \
        "profile=demo tool=adjust_insured_salary result=refused reason=role_mismatch"
    text = log.read_text(encoding="utf-8")
    probes = ("EMP-4242", (TODAY + timedelta(days=3)).isoformat(), world.ecr_credential.said,
              world.ecr_stream[:40])
    for secret in probes:
        assert secret not in text


def test_the_witness_is_where_the_scripts_put_it(tmp_path):
    assert proxy.witness_url(tmp_path, {}) == proxy.DEFAULT_WITNESS
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / ".env").write_text(
        "OTHER=x\nVLEI_WITNESS_URL=http://localhost:15642\n", encoding="utf-8")
    assert proxy.witness_url(tmp_path, {}) == "http://localhost:15642"
    assert proxy.witness_url(tmp_path, {"VLEI_WITNESS_URL": "http://w:1"}) == "http://w:1"


def test_docker_can_find_its_compose_plugin_under_a_small_environment(monkeypatch):
    monkeypatch.setattr(proxy.os, "name", "nt")
    env = {"SYSTEMDRIVE": "D:"}
    proxy.docker_can_find_compose(env)
    assert env["ProgramFiles"] == r"D:\Program Files"
    kept = {"ProgramFiles": r"E:\Apps"}
    proxy.docker_can_find_compose(kept)
    assert kept["ProgramFiles"] == r"E:\Apps"


def test_kli_never_reads_the_stdin_the_mcp_client_writes_to(monkeypatch):
    # The proxy's stdin is the MCP channel. `docker compose exec` forwards stdin into the
    # container by default, so a kli started with the inherited stdin swallows whatever the client
    # sent meanwhile — Claude Desktop's initialize, and it times out waiting for the answer.
    import subprocess

    import kli_signer

    seen: list[dict] = []

    def fake_run(args, **kwargs):
        seen.append(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(kli_signer.subprocess, "run", fake_run)
    kli_signer._run(["kli", "aid", "--name", "x", "--alias", "x"])
    assert seen and seen[0].get("stdin") is subprocess.DEVNULL


def test_the_keystore_is_read_when_something_is_signed_not_at_startup():
    # Each kli run goes through Docker: seconds on a busy machine. Read at startup, they kept the
    # proxy from answering initialize in time, and Claude gave up on it ("Request timed out").
    from types import SimpleNamespace

    import kli_signer

    made: list[tuple[str, str]] = []

    def make(keystore: str, alias: str) -> SimpleNamespace:
        made.append((keystore, alias))
        return SimpleNamespace(aid="EAID", verkey="DKEY", sign=lambda payload: "SIG")

    signer = kli_signer.LazyKeystoreSigner("agent", "agent", make=make)
    assert made == []
    assert signer.sign(b"x") == "SIG" and signer.aid == "EAID" and signer.verkey == "DKEY"
    assert made == [("agent", "agent")]


# ------------------------------------------------------------------------------------------- #
# VLEI_PROFILE=plain: MCP as it is today, for the before half of the comparison
# ------------------------------------------------------------------------------------------- #

async def test_plain_relays_with_nothing_attached_and_the_server_learns_only_a_name(tmp_path, monkeypatch):
    """Claude Desktop through the plain profile: the call reaches a before-mode server carrying no
    credential and no signature, and the only thing the server records is the name Claude gave."""
    import httpx2
    from mcp.types import Implementation

    from conftest import ROOT as _root  # noqa: F401  (the harness is already loaded)

    monkeypatch.setenv("LABOR_SIM_MODE", "before")
    sim = harness.load("proxy_before_sim", ROOT / "examples/regulator/labor-insurance-sim/server.py")
    sim.FILINGS.clear()
    async with harness.serve(sim.create_app()) as base:
        relay = proxy.PlainRelay(proxy.Gateway(f"{base}/mcp"),
                                 log=proxy.RelayLog(tmp_path / "relay.log", stream=io.StringIO()))
        assert await relay.connect()
        async with Client(proxy.build_server(relay),
                          client_info=Implementation(name="Claude Desktop", version="0.9")) as claude:
            names = {t.name for t in (await claude.list_tools()).tools}
            result = await claude.call_tool("enroll_employee", enrol())
            assert "verified" not in (claude.instructions or "").lower() or "nothing is verified" in (claude.instructions or "")
        async with httpx2.AsyncClient() as http:
            ledger = (await http.get(f"{base}/ledger")).json()

    assert names == set(POLICY) and not result.is_error
    assert ledger["filings"][-1]["filedBy"] == {"declaredClient": "Claude Desktop 0.9", "verified": False}
    line = (tmp_path / "relay.log").read_text(encoding="utf-8").splitlines()[-1]
    assert line.endswith("profile=plain tool=enroll_employee result=allowed reason=-")
