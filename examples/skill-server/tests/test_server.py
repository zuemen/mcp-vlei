"""Tests for the skill-written server's interception logic.

Every call goes through the real SDK: an in-process `mcp.Client` talks to the `MCPServer`, so the
capability negotiation, `-32021` and result `_meta` are exercised as a client would see them. The
KERI world is `mcp_vlei.testing.World`: real KELs, TELs and ACDCs, with a witness served over
`httpx.MockTransport`.

Every refusal test asserts the named failure layer AND the report check it stopped at.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

# Load server.py first: it puts packages/mcp-vlei/src on sys.path when mcp_vlei is not installed.
_SERVER_PATH = Path(__file__).resolve().parents[1] / "server.py"
_spec = importlib.util.spec_from_file_location("skill_server", _SERVER_PATH)
assert _spec and _spec.loader
skill_server = importlib.util.module_from_spec(_spec)
sys.modules["skill_server"] = skill_server
_spec.loader.exec_module(skill_server)

from mcp import Client  # noqa: E402
from mcp.client import advertise  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402
from mcp_vlei.audience import Audience  # noqa: E402
from mcp_vlei.errors import UnsupportedVersion  # noqa: E402
from mcp_vlei.kel import WitnessKeyStates  # noqa: E402
from mcp_vlei.pop import POP_PATH, prove_server  # noqa: E402
from mcp_vlei.pop import challenge as pop_challenge  # noqa: E402
from mcp_vlei.replay import MemoryReplayStore  # noqa: E402
from mcp_vlei.signing import Signer, sign_request  # noqa: E402
from mcp_vlei.testing import ECR_SCHEMA, LEI, Controller, World, export  # noqa: E402

EXT = skill_server.EXTENSION_ID
ROLE = "regulatory-filing"
WITNESS_URL = "http://witness.test"
ARGS = {"form": "CAP-1", "period": "2026-Q3", "payload": {"tier1Capital": 1250000, "currency": "EUR"}}
PERSON = "Bob"  # the natural person World puts in the ECR; must never leak into a report
PUBLIC_URL = "http://127.0.0.1:8082"
#: Before anything a test signs: these tests are about restarts only where they say so.
LONG_AGO = datetime(2026, 1, 1, tzinfo=timezone.utc)


def name_leaked(text: str, name: str) -> bool:
    """True if `name` appears in `text` as a whole word, outside any base64url-ish run of 20+
    characters (a SAID, AID or signature) where a short name could appear by chance."""
    cleaned = re.sub(r"[A-Za-z0-9_-]{20,}", "", text)
    return re.search(rf"\b{re.escape(name)}\b", cleaned) is not None


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------------------------- #

@dataclass
class Witness:
    """World's witness, with a request log and switchable faults."""

    world: World
    requests: list[str] = field(default_factory=list)
    down: bool = False
    tel_unreadable: bool = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.down:
            raise httpx.ConnectError("witness unreachable", request=request)
        if self.tel_unreadable and request.url.params.get("typ") == "tel":
            return httpx.Response(503)
        return self.world.witness_handler(request)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@dataclass
class Deployment:
    world: World
    witness: Witness
    server: Any


def deploy(world: World | None = None, *, roots: list[str] | None = None,
           replay_store: Any = None, pop_signer: Any = None) -> Deployment:
    global _server_aid
    world = world or World(role=ROLE)
    _server_aid = world.le.pre
    witness = Witness(world)
    server = skill_server.build_server(
        le_credential=world.le_stream,
        accepted_roots=roots or [world.root.pre],
        witness_url=WITNESS_URL,
        role=ROLE,
        public_url=PUBLIC_URL,
        http=witness.client(),
        replay_store=replay_store or MemoryReplayStore(memory_since=LONG_AGO),
        **({"pop_signer": pop_signer} if pop_signer is not None else {}),
    )
    return Deployment(world, witness, server)


def signer_for(controller: Controller) -> Signer:
    return Signer.from_seed(controller.pre, controller.seed)


def presentation(
    signer: Signer,
    *,
    stream: str,
    said: str,
    arguments: dict[str, Any] = ARGS,
    ts: str | None = None,
    delegated_aid: str | None = None,
    audience_aid: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """The four request `_meta` keys, signed (vlei-sig/0.3) for this server's LE at its URL."""
    return {
        "org.gleif.vlei/credential": stream,
        "org.gleif.vlei/credentialSaid": said,
        "org.gleif.vlei/delegatedAid": delegated_aid or signer.aid,
        "org.gleif.vlei/signature": sign_request(
            signer, "tools/call", {"name": "submit_filing", "arguments": arguments}, ts=ts,
            audience=Audience(audience_aid or _server_aid, f"{PUBLIC_URL}/mcp"),
            credential_said=said, nonce=nonce,
        ),
    }


#: The LE AID of the server `deploy` built last: the signing helpers sign for it unless told not to.
_server_aid = ""


def agent_presents_ecr(world: World, **kwargs: Any) -> dict[str, Any]:
    return presentation(signer_for(world.agent), stream=world.ecr_stream, said=world.ecr_credential.said, **kwargs)


async def call(
    dep: Deployment,
    meta: dict[str, Any] | None,
    arguments: dict[str, Any] = ARGS,
    *,
    tool: str = "submit_filing",
    declare: bool = True,
) -> Any:
    extensions = [advertise(EXT)] if declare else []
    async with Client(dep.server, extensions=extensions) as client:
        return await client.call_tool(tool, arguments, meta=meta)


def refused(result: Any) -> tuple[str, str]:
    """Assert the section-5 refusal shape; return (layer, report check that failed)."""
    assert result.is_error is True
    layer = result.meta["org.gleif.vlei/failure"]["layer"]
    assert result.content[0].text.startswith(f"{layer}: "), "layer must be first and unadorned"
    report = result.meta["org.gleif.vlei/report"]
    assert report["allowed"] is False
    assert report["layer"] == layer
    failed = [c["name"] for c in report["checks"] if c["passed"] is False]
    assert len(failed) == 1, failed
    assert not name_leaked(json.dumps(result.meta), PERSON), "the report must not carry the credential"
    return layer, failed[0]


def allowed(result: Any) -> dict[str, Any]:
    assert result.is_error is False, result.content
    report = result.meta["org.gleif.vlei/report"]
    assert report["allowed"] is True
    assert report["layer"] is None
    assert all(c["passed"] is True for c in report["checks"]), report["checks"]
    assert not name_leaked(json.dumps(result.meta), PERSON)
    return report


def check_passed(result: Any, name: str) -> bool | None:
    return next(c["passed"] for c in result.meta["org.gleif.vlei/report"]["checks"] if c["name"] == name)


# --------------------------------------------------------------------------------------------- #
# Declaration: capability, well-known, Tool._meta
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_declares_capability_and_per_tool_requirements() -> None:
    dep = deploy()
    async with Client(dep.server, extensions=[advertise(EXT)]) as client:
        assert client.protocol_version == "2026-07-28"
        settings = client.session.server_capabilities.extensions[EXT]
        tools = {t.name: t for t in (await client.list_tools()).tools}

    assert settings == {
        "presents": ["LE"],
        "requires": "ECR",
        "acceptedRoots": [dep.world.root.pre],
        "signatureAlgs": ["Ed25519"],
        "signatureFormats": ["vlei-sig/0.3"],
        "ttlMs": 0,
        "discovery": {"wellKnown": "http://127.0.0.1:8082/.well-known/vlei"},
    }
    assert tools["submit_filing"].meta == {"org.gleif.vlei/requires": {"credential": "ECR", "role": ROLE}}
    assert not (tools["list_events"].meta or {}).get("org.gleif.vlei/requires")


@pytest.mark.anyio
async def test_well_known_is_served_without_a_session() -> None:
    dep = deploy()
    app = dep.server.streamable_http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8082") as http:
        response = await http.get("/.well-known/vlei")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "extension": EXT,
        "credential": dep.world.le_stream,
        "acceptedRoots": [dep.world.root.pre],
        "signatureAlgs": ["Ed25519"],
        "signatureFormats": ["vlei-sig/0.3"],
    }


async def _prove(dep: Deployment):
    """What a v0.3 client does before presenting anything: challenge the server, and verify the
    answer under the responder's key state read from the witness."""
    app = dep.server.streamable_http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC_URL) as http:
        return await prove_server(http=http, pop_url=f"{PUBLIC_URL}{POP_PATH}",
                                  endpoint_url=f"{PUBLIC_URL}/mcp", holder=dep.world.le.pre,
                                  key_states=WitnessKeyStates(WITNESS_URL, client=dep.witness.client()))


@pytest.mark.anyio
async def test_given_a_signer_it_declares_pop_and_proves_it_holds_its_les_key() -> None:
    world = World(role=ROLE)
    dep = deploy(world, pop_signer=signer_for(world.le))
    async with Client(dep.server, extensions=[advertise(EXT)]) as client:
        settings = client.session.server_capabilities.extensions[EXT]
    assert settings["pop"] == POP_PATH

    proof = await _prove(dep)

    assert proof.responder_aid == dep.world.le.pre and proof.delegated is False


@pytest.mark.anyio
async def test_it_proves_itself_only_for_its_own_endpoint() -> None:
    world = World(role=ROLE)
    dep = deploy(world, pop_signer=signer_for(world.le))
    app = dep.server.streamable_http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC_URL) as http:
        response = await http.post(POP_PATH, json=pop_challenge("http://relay.test/mcp"))
        malformed = await http.post(POP_PATH, content=b"not json")
    assert response.status_code == 403 and response.json()["layer"] == "audience_mismatch"
    assert "8082" not in response.json()["message"]
    assert malformed.status_code == 400


# --------------------------------------------------------------------------------------------- #
# The optional PoP route has vlei-pop's abuse limits: a fake signer, never a keystore
# --------------------------------------------------------------------------------------------- #

class _FakeSigner:
    """Signs nothing real: counts calls, and how many ran at once. Never holds a key."""

    def __init__(self, aid: str, delay: float = 0.0) -> None:
        import threading

        self.aid, self.delay = aid, delay
        self.calls = self.running = self.most_at_once = 0
        self._lock = threading.Lock()

    def sign(self, payload: bytes) -> str:
        import time

        with self._lock:
            self.calls += 1
            self.running += 1
            self.most_at_once = max(self.most_at_once, self.running)
        time.sleep(self.delay)
        with self._lock:
            self.running -= 1
        return "0B" + "A" * 86


def _pop_client(signer: _FakeSigner, received: list[int] | None = None) -> httpx.AsyncClient:
    app = deploy(World(role=ROLE), pop_signer=signer).server.streamable_http_app()
    if received is not None:
        inner = app

        async def app(scope, receive, send):  # every request-body byte the server actually read
            async def counted():
                message = await receive()
                if message["type"] == "http.request":
                    received.append(len(message.get("body", b"")))
                return message
            await inner(scope, counted, send)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PUBLIC_URL)


async def _chunks(count: int, size: int = 1000):
    for _ in range(count):
        yield b"a" * size


@pytest.mark.anyio
async def test_an_oversize_challenge_is_413_whether_declared_or_streamed() -> None:
    signer = _FakeSigner("E" + "S" * 43)
    async with _pop_client(signer) as http:
        declared = await http.post(POP_PATH, content=b"a" * (skill_server.MAX_POP_BODY_BYTES + 1))
        streamed = await http.post(POP_PATH, content=_chunks(10))
    assert declared.status_code == 413 and streamed.status_code == 413
    assert declared.headers.get("connection") == "close" == streamed.headers.get("connection")
    assert signer.calls == 0


@pytest.mark.anyio
async def test_an_oversize_challenge_is_not_read_into_memory_whole() -> None:
    """The bound holds while streaming: a 200 KB body is not read to its end to be measured."""
    received: list[int] = []
    async with _pop_client(_FakeSigner("E" + "S" * 43), received) as http:
        response = await http.post(POP_PATH, content=_chunks(200))
    assert response.status_code == 413
    assert sum(received) <= skill_server.MAX_DRAIN_BYTES + 1000, "read far more than the bound"


async def _slow_challenge(url: str, chunk: int = 8, delay: float = 0.01):
    body = json.dumps(pop_challenge(url)).encode()
    for i in range(0, len(body), chunk):
        yield body[i: i + chunk]
        await anyio.sleep(delay)


@pytest.mark.anyio
async def test_challenges_beyond_the_admission_bound_are_503() -> None:
    """A slot is claimed before the body is read, so slow senders cannot all be admitted."""
    signer = _FakeSigner("E" + "S" * 43)
    attempts = skill_server.POP_MAX_WAITING + 4
    async with _pop_client(signer) as http:
        responses = await _gather(*(http.post(POP_PATH, content=_slow_challenge(f"{PUBLIC_URL}/mcp"))
                                    for _ in range(attempts)))
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) + statuses.count(503) == attempts
    assert 1 <= statuses.count(200) <= skill_server.POP_MAX_WAITING
    assert signer.calls == statuses.count(200)


@pytest.mark.anyio
async def test_challenges_are_signed_one_at_a_time() -> None:
    """One keystore behind the route: signing is serialised, not run in parallel threads."""
    signer = _FakeSigner("E" + "S" * 43, delay=0.05)
    async with _pop_client(signer) as http:
        responses = await _gather(*(http.post(POP_PATH, json=pop_challenge(f"{PUBLIC_URL}/mcp"))
                                    for _ in range(3)))
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert signer.most_at_once == 1


async def _gather(*coroutines):
    import asyncio

    return await asyncio.gather(*coroutines)


@pytest.mark.anyio
async def test_without_a_signer_it_offers_no_proof_and_a_v03_client_refuses_it() -> None:
    """Started from the command line no keystore is wired: verifier-side only."""
    dep = deploy()
    with pytest.raises(UnsupportedVersion, match="404"):
        await _prove(dep)


def test_empty_accepted_roots_is_refused_at_construction() -> None:
    world = World(role=ROLE)
    with pytest.raises(ValueError):
        skill_server.build_server(le_credential=world.le_stream, accepted_roots=[], witness_url=WITNESS_URL)
    env = {"VLEI_LE_CREDENTIAL": "le.cesr", "VLEI_ACCEPTED_ROOTS": " , ", "VLEI_WITNESS_URL": WITNESS_URL}
    with pytest.raises(skill_server.ConfigError):
        skill_server.Config.from_env(env)
    config = skill_server.Config.from_env({**env, "VLEI_ACCEPTED_ROOTS": "Eroot1, Eroot2"})
    assert config.accepted_roots == ["Eroot1", "Eroot2"] and config.role == ROLE and config.port == 8082


# --------------------------------------------------------------------------------------------- #
# Allowed
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_agent_with_delegated_aid_presenting_holders_ecr_is_allowed() -> None:
    dep = deploy()
    world = dep.world
    result = await call(dep, agent_presents_ecr(world))
    report = allowed(result)
    assert report["identity"] == {
        "lei": LEI,
        "role": ROLE,
        "credentialSaid": world.ecr_credential.said,
        "holderAid": world.holder.pre,
        "delegateAid": world.agent.pre,
    }
    receipt = result.structured_content
    assert receipt["form"] == "CAP-1" and receipt["filedBy"]["lei"] == LEI
    assert receipt["filedBy"]["delegateAid"] == world.agent.pre


@pytest.mark.anyio
async def test_holder_signing_as_the_issuee_is_allowed() -> None:
    dep = deploy()
    world = dep.world
    meta = presentation(signer_for(world.holder), stream=world.ecr_stream, said=world.ecr_credential.said)
    report = allowed(await call(dep, meta))
    assert report["identity"]["holderAid"] == world.holder.pre
    assert report["identity"]["delegateAid"] is None


# --------------------------------------------------------------------------------------------- #
# Checks 3 and 5: who signed
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_someone_elses_credential_signed_with_own_key_is_refused() -> None:
    """The test SKILL.md asks for: a copy of a real ECR, signed by the attacker's own, valid key."""
    dep = deploy()
    world = dep.world
    attacker = world.enrol(Controller("attacker", witnesses=world.witnesses, toad=2))
    meta = presentation(signer_for(attacker), stream=world.ecr_stream, said=world.ecr_credential.said)

    result = await call(dep, meta)

    assert refused(result) == ("invalid_signature", "delegation")
    assert check_passed(result, "signature") is True  # the attacker's own signature is fine...
    assert world.holder.pre in result.content[0].text  # ...but the attacker is not the holder


@pytest.mark.anyio
async def test_claiming_the_agents_aid_and_supplying_own_key_is_refused() -> None:
    """Sign as the agent's AID with the attacker's key, and put that key in the request. The key a
    request carries must be ignored: key state comes from the agent's KEL at the witness."""
    dep = deploy()
    world = dep.world
    attacker = Controller("attacker", witnesses=world.witnesses, toad=2)
    impostor = Signer.from_seed(world.agent.pre, attacker.seed)
    meta = presentation(impostor, stream=world.ecr_stream, said=world.ecr_credential.said)
    meta["org.gleif.vlei/signature"]["verkey"] = impostor.verkey
    meta["org.gleif.vlei/signature"]["k"] = [impostor.verkey]

    assert refused(await call(dep, meta)) == ("invalid_signature", "signature")


@pytest.mark.anyio
async def test_agent_delegated_by_someone_else_is_refused() -> None:
    dep = deploy()
    world = dep.world
    bob = Controller("bob", witnesses=world.witnesses, toad=2)
    bobs_agent = world.enrol(Controller("bob:agent", witnesses=world.witnesses, toad=2, delegator=bob))
    meta = presentation(signer_for(bobs_agent), stream=world.ecr_stream, said=world.ecr_credential.said)

    result = await call(dep, meta)

    assert refused(result) == ("invalid_signature", "delegation")
    assert check_passed(result, "signature") is True


@pytest.mark.anyio
async def test_claimed_delegation_the_holder_never_anchored_is_refused() -> None:
    """A `dip` naming the holder in `di` that the holder's own log never approved."""
    dep = deploy()
    world = dep.world
    rogue = world.enrol(
        Controller("rogue", witnesses=world.witnesses, toad=2, delegator=world.holder, approve=False)
    )
    meta = presentation(signer_for(rogue), stream=world.ecr_stream, said=world.ecr_credential.said)

    assert refused(await call(dep, meta)) == ("invalid_signature", "signature")


@pytest.mark.anyio
async def test_delegated_aid_that_is_not_the_signer_is_refused() -> None:
    dep = deploy()
    world = dep.world
    meta = agent_presents_ecr(world, delegated_aid=world.holder.pre)
    assert refused(await call(dep, meta)) == ("invalid_signature", "delegation")


@pytest.mark.anyio
async def test_key_rotated_away_no_longer_verifies() -> None:
    dep = deploy()
    world = dep.world
    old = signer_for(world.agent)
    world.agent.rotate()  # a drt, anchored by the holder; the witness now serves the new state

    stale_key = presentation(old, stream=world.ecr_stream, said=world.ecr_credential.said)
    assert refused(await call(dep, stale_key)) == ("invalid_signature", "signature")
    allowed(await call(dep, agent_presents_ecr(world)))


@pytest.mark.anyio
async def test_unreachable_witness_refuses_rather_than_skipping() -> None:
    dep = deploy()
    dep.witness.down = True
    assert refused(await call(dep, agent_presents_ecr(dep.world))) == ("invalid_signature", "signature")


# --------------------------------------------------------------------------------------------- #
# Checks 6-8: the chain
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_forged_credential_not_anchored_by_its_issuer_is_refused() -> None:
    """An ECR naming the real LE as issuer and the attacker as issuee; every SAID recomputes, but the
    LE's log never anchored the issuance."""
    dep = deploy()
    world = dep.world
    attacker = world.enrol(Controller("forger", witnesses=world.witnesses, toad=2))
    forged = world.issue(
        world.le_registry, ECR_SCHEMA, attacker.pre,
        {"LEI": LEI, "personLegalName": "Mallory", "engagementContextRole": ROLE},
        edge=("le", world.le_credential), anchor=False,
    )
    stream = export([forged, world.le_credential, world.qvi_credential])
    meta = presentation(signer_for(attacker), stream=stream, said=forged.said)

    result = await call(dep, meta)

    assert refused(result) == ("chain_invalid", "chain")
    assert "not anchored" in result.content[0].text
    assert check_passed(result, "delegation") is True  # the forger is the issuee of the forgery


@pytest.mark.anyio
async def test_altered_credential_is_refused() -> None:
    dep = deploy()
    world = dep.world
    ecr = world.ecr_credential.raw
    stream = world.ecr_stream.replace(ecr, ecr.replace('"engagementContextRole":"regulatory-filing"',
                                                        '"engagementContextRole":"regulatory-admins"'))
    assert stream != world.ecr_stream
    meta = presentation(signer_for(world.agent), stream=stream, said=world.ecr_credential.said)
    assert refused(await call(dep, meta)) == ("chain_invalid", "chain")


@pytest.mark.anyio
async def test_wrong_credential_type_is_refused() -> None:
    """The LE presents its own LE credential, correctly signed: valid, but not an ECR."""
    dep = deploy()
    world = dep.world
    meta = presentation(signer_for(world.le), stream=world.le_stream, said=world.le_credential.said)
    assert refused(await call(dep, meta)) == ("chain_invalid", "chain")


@pytest.mark.anyio
async def test_ecr_naming_a_different_lei_than_its_le_is_refused() -> None:
    dep = deploy()
    world = dep.world
    other = world.issue(
        world.le_registry, ECR_SCHEMA, world.holder.pre,
        {"LEI": "5299000000000000EVIL", "personLegalName": PERSON, "engagementContextRole": ROLE},
        edge=("le", world.le_credential),
    )
    stream = export([other, world.le_credential, world.qvi_credential])
    meta = presentation(signer_for(world.agent), stream=stream, said=other.said)
    assert refused(await call(dep, meta)) == ("chain_invalid", "chain")


@pytest.mark.anyio
async def test_ecr_issued_by_a_qvi_without_an_le_in_the_chain_is_refused() -> None:
    """Passes every check SKILL.md lists: a QVI mints an ECR for any LEI, edged to its own QVI
    credential. Anchored, unrevoked, continuous, rooted - and bound to no legal entity."""
    dep = deploy()
    world = dep.world
    ecr = world.issue(
        world.qvi_registry, ECR_SCHEMA, world.holder.pre,
        {"LEI": "5299000000000000EVIL", "personLegalName": PERSON, "engagementContextRole": ROLE},
        edge=("qvi", world.qvi_credential),
    )
    meta = presentation(signer_for(world.agent), stream=export([ecr, world.qvi_credential]), said=ecr.said)

    result = await call(dep, meta)

    assert refused(result) == ("chain_invalid", "chain")
    assert "not bound to any legal entity" in result.content[0].text


@pytest.mark.anyio
async def test_ecr_whose_issuer_is_an_accepted_root_is_allowed_with_a_caveat() -> None:
    world = World(role=ROLE)
    dep = deploy(world, roots=[world.le.pre])  # the operator trusts the LE directly
    report = allowed(await call(dep, agent_presents_ecr(world)))
    assert any("not cross-checked" in c for c in report["caveats"])


@pytest.mark.anyio
async def test_chain_to_a_root_we_do_not_accept_is_refused() -> None:
    dep = deploy(roots=["E" + "x" * 43])
    assert refused(await call(dep, agent_presents_ecr(dep.world))) == ("unknown_root", "chain")


# --------------------------------------------------------------------------------------------- #
# Check 9: revocation, for every link
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_revoked_ecr_is_refused() -> None:
    dep = deploy()
    world = dep.world
    allowed(await call(dep, agent_presents_ecr(world)))
    world.le_registry.revoke(world.ecr_credential.said)
    # Different arguments: `ts` has one-second resolution, so an identical call in the same second
    # is a replay by construction (see REPORT.md).
    second = {**ARGS, "period": "2026-Q4"}
    result = await call(dep, agent_presents_ecr(world, arguments=second), second)
    assert refused(result) == ("revoked", "revocation")


@pytest.mark.anyio
async def test_revoked_le_above_the_ecr_is_refused() -> None:
    dep = deploy()
    world = dep.world
    world.qvi_registry.revoke(world.le_credential.said)  # the ECR's own log still says "issued"
    result = await call(dep, agent_presents_ecr(world))
    assert refused(result) == ("revoked", "revocation")
    assert check_passed(result, "chain") is True


@pytest.mark.anyio
async def test_unreadable_transaction_event_log_refuses() -> None:
    dep = deploy()
    dep.witness.tel_unreadable = True
    assert refused(await call(dep, agent_presents_ecr(dep.world))) == ("chain_invalid", "revocation")


# --------------------------------------------------------------------------------------------- #
# Checks 1, 2 and 4: decided from the request
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_tampered_arguments_are_refused_without_a_round_trip() -> None:
    dep = deploy()
    meta = agent_presents_ecr(dep.world)
    tampered = {**ARGS, "payload": {**ARGS["payload"], "tier1Capital": 9_999_999}}

    result = await call(dep, meta, tampered)

    assert refused(result) == ("digest_mismatch", "digest")
    assert dep.witness.requests == []  # decided from the request alone


@pytest.mark.anyio
async def test_expired_signature_is_refused_without_a_round_trip() -> None:
    dep = deploy()
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = await call(dep, agent_presents_ecr(dep.world, ts=old))

    assert refused(result) == ("stale_signature", "freshness")
    assert dep.witness.requests == []


@pytest.mark.anyio
async def test_replayed_request_is_refused() -> None:
    dep = deploy()
    meta = agent_presents_ecr(dep.world)
    allowed(await call(dep, meta))

    result = await call(dep, meta)

    assert refused(result) == ("stale_signature", "freshness")
    assert check_passed(result, "signature") is True  # recorded only after the signature verified
    # This server's own nonce-spent message — not the package's memory-horizon refusal, which
    # also says "replay" and is what a server that forgot every claim would answer.
    assert "this signature was already presented: a replay" in result.content[0].text


@pytest.mark.anyio
async def test_the_claim_outlasts_the_time_window_by_one_skew() -> None:
    """The time check accepts until exp + skew and the claim is made a moment later; a claim that
    lapsed at exp + skew could be swept before a copy checked at the boundary is claimed."""

    class Recording(MemoryReplayStore):
        def claim(self, aid: str, nonce: str, expires_at: datetime) -> bool:
            self.last = expires_at
            return super().claim(aid, nonce, expires_at)

    seen = Recording(memory_since=LONG_AGO)
    dep = deploy(replay_store=seen)
    meta = agent_presents_ecr(dep.world)
    allowed(await call(dep, meta))

    exp = datetime.fromisoformat(meta["org.gleif.vlei/signature"]["exp"].replace("Z", "+00:00"))
    assert seen.last == exp + timedelta(seconds=2 * 60)


@pytest.mark.anyio
async def test_replay_is_not_burned_by_a_signature_that_does_not_verify() -> None:
    """Check 4 records only after check 3: a forged copy of a pending call must not consume it."""
    dep = deploy()
    world = dep.world
    genuine = agent_presents_ecr(world)
    forged = json.loads(json.dumps(genuine))
    attacker = Controller("attacker", witnesses=world.witnesses, toad=2)
    original = genuine["org.gleif.vlei/signature"]
    forged["org.gleif.vlei/signature"]["sig"] = sign_request(
        Signer.from_seed(world.agent.pre, attacker.seed), "tools/call",
        {"name": "submit_filing", "arguments": ARGS}, ts=original["ts"], nonce=original["nonce"],
        audience=Audience(**original["aud"]), credential_said=world.ecr_credential.said,
    )["sig"]

    assert refused(await call(dep, forged)) == ("invalid_signature", "signature")
    allowed(await call(dep, genuine))


# --------------------------------------------------------------------------------------------- #
# Check 10: authority
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_role_mismatch_is_refused() -> None:
    dep = deploy(World(role="member-registration"))
    assert refused(await call(dep, agent_presents_ecr(dep.world))) == ("role_mismatch", "authority")


def test_scope_comparison_follows_the_skill() -> None:
    covers = skill_server._scope_covers
    assert covers({"maxAmount": 1_000_000}, {"maxAmount": 5_000_000}) == (True, "")
    assert covers({"maxAmount": 1_000_000}, {"maxAmount": 10})[0] is False
    assert covers({"forms": ["CAP-1"]}, {"forms": ["CAP-1", "LIQ-2"]}) == (True, "")
    assert covers({"forms": ["CAP-1", "OWN-A"]}, {"forms": ["CAP-1"]})[0] is False
    assert covers({"maxAmount": 1}, {})[0] is False  # a key the credential does not carry: deny
    assert covers({"maxAmount": 1}, None)[0] is False
    assert covers(None, None) == (True, "")


# --------------------------------------------------------------------------------------------- #
# Section 5: missing extension, missing credential, public tools
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_protected_tool_without_the_extension_declared_is_32021() -> None:
    dep = deploy()
    async with Client(dep.server) as client:  # declares no extensions
        with pytest.raises(MCPError) as caught:
            await client.call_tool("submit_filing", ARGS, meta=agent_presents_ecr(dep.world))
    assert caught.value.code == -32021
    assert caught.value.data == {"requiredCapabilities": {"extensions": {EXT: {}}}}
    assert dep.witness.requests == []


@pytest.mark.anyio
async def test_declared_but_nothing_presented_is_missing_credential() -> None:
    dep = deploy()
    assert refused(await call(dep, None)) == ("missing_credential", "credential_present")


@pytest.mark.anyio
async def test_public_tool_needs_no_credential_and_no_extension() -> None:
    dep = deploy()
    for declare in (False, True):
        result = await call(dep, None, {}, tool="list_events", declare=declare)
        assert result.is_error is False
        assert "org.gleif.vlei/failure" not in (result.meta or {})
        assert {e["form"] for e in result.structured_content["result"]} >= {"CAP-1", "LIQ-2"}
    assert dep.witness.requests == []


# --------------------------------------------------------------------------------------------- #
# v0.3: the recipient, the format, the named credential
# --------------------------------------------------------------------------------------------- #

@pytest.mark.anyio
async def test_a_call_signed_for_another_server_is_audience_mismatch() -> None:
    dep = deploy()
    meta = agent_presents_ecr(dep.world, audience_aid="E" + "X" * 43)
    assert refused(await call(dep, meta)) == ("audience_mismatch", "digest")
    assert dep.witness.requests == []  # decided from the request alone


@pytest.mark.anyio
async def test_a_v02_signature_is_unsupported_version() -> None:
    from mcp_vlei.signing import digest_params

    dep = deploy()
    meta = agent_presents_ecr(dep.world)
    signer = signer_for(dep.world.agent)
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    digest = digest_params({"name": "submit_filing", "arguments": ARGS})
    meta["org.gleif.vlei/signature"] = {"aid": signer.aid, "ts": ts, "digest": digest, "alg": "Ed25519",
                                        "sig": signer.sign(f"tools/call\n{ts}\n{digest}".encode())}
    assert refused(await call(dep, meta)) == ("unsupported_version", "credential_present")


@pytest.mark.anyio
async def test_a_call_that_names_no_credential_is_missing_credential() -> None:
    dep = deploy()
    meta = agent_presents_ecr(dep.world)
    del meta["org.gleif.vlei/credentialSaid"]
    assert refused(await call(dep, meta)) == ("missing_credential", "credential_present")
