"""The credential proxy at v0.3: nothing is listed for a gateway that cannot prove its key or does
not speak v0.3, the witnesses are three, and the gateway is verified again when it is due."""

from __future__ import annotations

from typing import Any

from conftest import harness, relay_for, stand_in, write_profile

import proxy
from mcp_vlei import Signer
from mcp_vlei.testing import Controller, World
from test_proxy import Recording, enrol, first_line

#: Three named witnesses, the same way ``packages/mcp-vlei/tests/test_kel.py`` names them for its
#: own quorum and duplicity tests.
WITNESS_URLS = ["http://wan", "http://wil", "http://wes"]


def _witnesses(world: World, down: frozenset[str] = frozenset()) -> Any:
    """A client for :data:`WITNESS_URLS`, any of which can be taken down; the ones still up answer
    from ``world`` as usual."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host in down:
            raise httpx.ConnectError("connection refused", request=request)
        return world.witness_handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_a_gateway_that_cannot_prove_the_operators_key_lists_nothing(tmp_path, world):
    """It publishes the operator's real LE; it does not hold the operator's key."""
    stranger = world.enrol(Controller("copycat", witnesses=world.witnesses, toad=2))
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path, pop_signer=Signer.from_seed(stranger.pre, stranger.seed)) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log")
        assert not await relay.connect()
    assert relay.reason.startswith("invalid_signature: ") and "neither the server's LE" in relay.reason
    assert relay.tools == [] and gateway.sent == []


async def test_a_v02_gateway_is_unsupported_version_and_nothing_is_sent(tmp_path, world):
    profile = write_profile(tmp_path, world)
    v02 = {"extension": "org.gleif.vlei/identity", "credential": world.le_stream}
    async with stand_in(world, tmp_path, document=v02) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log")
        assert not await relay.connect()
        result = await relay.call_tool("enroll_employee", enrol())
    assert relay.reason.startswith("unsupported_version: ")
    assert first_line(result).startswith("gateway_unverified: unsupported_version")
    assert gateway.sent == [] and harness.labor.INSURED == {}


async def test_the_log_says_who_holds_the_key_and_how_many_witnesses_agreed(tmp_path, world):
    """Spec §6.2: at startup, which witness URLs and quorum are configured, with the one-witness
    caveat; after the proof, how many actually agreed."""
    profile = write_profile(tmp_path, world)
    log = tmp_path / "relay.log"
    async with stand_in(world, tmp_path) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), log)
        assert await relay.connect(), relay.reason
    lines = log.read_text(encoding="utf-8").splitlines()
    configured = next(line for line in lines if "witnesses:" in line)
    assert "http://witness" in configured and "quorum 1 of 1" in configured
    assert "one witness: duplicity not checked" in configured
    started = next(line for line in lines if "verified" in line)
    assert "delegated by the LE" in started and "witnesses 1/1 agree (quorum 1)" in started


async def test_one_witness_down_of_three_still_proves_two_down_refuses_nothing_sent(tmp_path, world):
    """Spec §6.2/D10: the client's own witness quorum, not just the server's."""
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log",
                          witness_url=WITNESS_URLS, witness_client=_witnesses(world, frozenset({"wes"})))
        assert await relay.connect(), relay.reason
        result = await relay.call_tool("enroll_employee", enrol())
    assert not result.is_error, first_line(result)
    lines = (tmp_path / "relay.log").read_text(encoding="utf-8").splitlines()
    configured = next(line for line in lines if "witnesses:" in line)
    assert "http://wan, http://wil, http://wes" in configured and "quorum 2 of 3" in configured
    proven = next(line for line in lines if "verified" in line)
    assert "witnesses 2/3 agree (quorum 2)" in proven

    two_down = tmp_path / "two-down"
    two_down.mkdir()
    profile2 = write_profile(two_down, world)
    async with stand_in(world, two_down) as url2:
        gateway2 = Recording(url2)
        relay2 = relay_for(world, profile2, gateway2, two_down / "relay.log",
                           witness_url=WITNESS_URLS,
                           witness_client=_witnesses(world, frozenset({"wil", "wes"})))
        assert not await relay2.connect()
        result2 = await relay2.call_tool("enroll_employee", enrol())
    assert gateway2.sent == [] and harness.labor.INSURED == {}
    assert first_line(result2).startswith("gateway_unverified: ")
    lines2 = (two_down / "relay.log").read_text(encoding="utf-8").splitlines()
    assert any(line for line in lines2 if "NOT verified" in line)


def test_a_witness_url_without_a_port_keeps_its_schemes_default_port(tmp_path):
    assert proxy.witness_urls(tmp_path, {"VLEI_WITNESS_URL": "https://witness.example"}) == [
        "https://witness.example:443", "https://witness.example:444", "https://witness.example:445"]
    assert proxy.witness_urls(tmp_path, {"VLEI_WITNESS_URL": "http://witness.example"}) == [
        "http://witness.example:80", "http://witness.example:81", "http://witness.example:82"]


def test_ipv6_witness_urls_keep_their_brackets(tmp_path):
    assert proxy.witness_urls(tmp_path, {"VLEI_WITNESS_URL": "http://[::1]:5642"}) == [
        "http://[::1]:5642", "http://[::1]:5643", "http://[::1]:5644"]


async def test_the_gateway_is_verified_again_before_each_call_when_due(tmp_path, world):
    """recheck_seconds=0: "re-check before every presentation" (spec §6.3) — every presentation
    is preceded by a fresh proof."""
    signed = []

    class Counting(Signer):
        def sign(self, payload: bytes) -> str:
            signed.append(payload)
            return super().sign(payload)

    gateway_aid = world.delegate("gateway", world.le)
    counting = Counting.from_seed(gateway_aid.pre, gateway_aid.seed)
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path, pop_signer=counting) as url:
        relay = relay_for(world, profile, proxy.Gateway(url), tmp_path / "relay.log", recheck_seconds=0)
        assert await relay.connect(), relay.reason
        result1 = await relay.call_tool("enroll_employee", enrol(person="EMP-0201"))
        result2 = await relay.call_tool("enroll_employee", enrol(person="EMP-0202"))
    assert not result1.is_error, first_line(result1)
    assert not result2.is_error, first_line(result2)
    assert len(signed) == 3, "one proof at connect, one before each call"


async def test_a_gateway_whose_le_was_withdrawn_loses_its_tools_at_the_recheck(tmp_path, world):
    """recheck_seconds=0: see the note above."""
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        gateway = Recording(url)
        relay = relay_for(world, profile, gateway, tmp_path / "relay.log", recheck_seconds=0)
        assert await relay.connect(), relay.reason
        world.qvi_registry.revoke(world.le_credential.said)
        result = await relay.call_tool("enroll_employee", enrol())
    assert first_line(result).startswith("revoked: ")
    assert relay.tools == [] and relay.verified is None and gateway.sent == []


def test_three_witnesses_by_default_from_the_first_ones_port(tmp_path):
    assert proxy.witness_urls(tmp_path, {"VLEI_WITNESS_URL": "http://localhost:15642"}) == [
        "http://localhost:15642", "http://localhost:15643", "http://localhost:15644"]
    assert proxy.witness_urls(tmp_path, {}) == [
        "http://localhost:5642", "http://localhost:5643", "http://localhost:5644"]


def test_one_witness_under_two_spellings_is_logged_and_counted_once(tmp_path, world):
    """The startup line states the quorum WitnessKeyStates computes — over distinct witnesses."""
    profile = write_profile(tmp_path, world)
    log = tmp_path / "relay.log"
    relay_for(world, profile, proxy.Gateway("http://gateway.test/mcp"), log,
              witness_url=["http://wan", "HTTP://WAN:80/", "http://wil"])
    configured = next(line for line in log.read_text(encoding="utf-8").splitlines()
                      if "witnesses:" in line)
    assert "http://wan, http://wil (quorum 2 of 2)" in configured, configured


def test_the_witness_list_can_be_given_outright(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / ".env").write_text(
        "VLEI_WITNESS_URLS=http://a:1, http://b:2\n", encoding="utf-8")
    assert proxy.witness_urls(tmp_path, {}) == ["http://a:1", "http://b:2"]
    assert proxy.witness_urls(tmp_path, {"VLEI_WITNESS_URLS": "http://c:3"}) == ["http://c:3"]


async def test_a_gateway_reached_under_a_url_it_does_not_answer_for_lists_nothing(tmp_path, world):
    """The proxy dials 127.0.0.1; the gateway lists only localhost. Named at connect, not at a call."""
    profile = write_profile(tmp_path, world)
    async with stand_in(world, tmp_path) as url:
        other = url.replace("127.0.0.1", "localhost")
        relay = relay_for(world, profile, proxy.Gateway(other), tmp_path / "relay.log")
        assert not await relay.connect()
    assert relay.reason.startswith("audience_mismatch: "), relay.reason


def test_credentials_can_live_elsewhere(tmp_path, world, monkeypatch):
    """The parallel v0.3 stack keeps its credentials in .v03/credentials, never in credentials/."""
    monkeypatch.setenv("VLEI_CREDENTIALS_DIR", str(tmp_path / "elsewhere"))
    assert proxy.profile_folders(tmp_path)["demo"] == tmp_path / "elsewhere"
    assert proxy.profile_folders(tmp_path)["forged"] == tmp_path / "elsewhere" / "forged"


def test_the_agents_signer_and_the_proxy_share_one_credentials_dir_rule(tmp_path, monkeypatch):
    """kli_signer.agent_signer() reads env.json from the same place the proxy reads profiles —
    one function, not a second copy of the VLEI_CREDENTIALS_DIR fallback."""
    import json

    import kli_signer

    assert proxy.credentials_dir is kli_signer.credentials_dir
    assert kli_signer.credentials_dir(tmp_path, {}) == tmp_path / "credentials"
    assert kli_signer.credentials_dir(tmp_path, {"VLEI_CREDENTIALS_DIR": ""}) == tmp_path / "credentials"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    picked: list[str] = []
    monkeypatch.setattr(kli_signer, "keystore_signer", lambda keystore, alias: picked.append(keystore))
    monkeypatch.setenv("VLEI_CREDENTIALS_DIR", str(elsewhere))
    kli_signer.agent_signer()  # no env.json there: the holder signs
    (elsewhere / "env.json").write_text(json.dumps({"agentAid": "E" + "A" * 43}), encoding="utf-8")
    kli_signer.agent_signer()  # a delegated agent recorded there: the agent signs
    assert picked == ["ecr", "agent"]


def test_the_signer_can_be_pointed_at_another_stacks_keri_cli(monkeypatch):
    import subprocess

    import kli_signer

    seen: list[list[str]] = []
    monkeypatch.setattr(kli_signer.subprocess, "run",
                        lambda args, **kw: seen.append(args) or subprocess.CompletedProcess(args, 0, "ok\n", ""))
    monkeypatch.setenv("VLEI_COMPOSE_CMD", "docker compose -p mcp-vlei-v03p -f a.yml -f b.yml")
    kli_signer._run(["kli", "aid"])
    assert seen[0][:7] == ["docker", "compose", "-p", "mcp-vlei-v03p", "-f", "a.yml", "-f"]
    assert seen[0][-5:] == ["exec", "-T", "keri-cli", "kli", "aid"][-5:]
