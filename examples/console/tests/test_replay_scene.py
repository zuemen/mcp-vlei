"""The replay scene on /story: one call Bob's agent signed, delivered twice — byte for byte.

What a viewer of the demo video sees is checked against a verifier that really remembers. The
gateway stand-in is the package's own `VleiIdentity`, configured as vlei-authz is — for the
gateway's URL, with a replay store — on the console's in-process KERI world
(`mcp_vlei.testing.World`). No containers, no network: the only address dialled is
127.0.0.1:9, where nothing listens.

    PYTHONPATH=packages/mcp-vlei/src python -m pytest examples/console/tests/test_replay_scene.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "examples" / "console"
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))
sys.path.insert(0, str(CONSOLE))

from mcp.types import CallToolRequestParams  # noqa: E402
from mcp_vlei import VleiIdentity  # noqa: E402
from mcp_vlei.client import published_audience  # noqa: E402
from mcp_vlei.errors import VleiError  # noqa: E402
from mcp_vlei.replay import MemoryReplayStore  # noqa: E402
from mcp_vlei.report import VerificationReport  # noqa: E402

#: The package's two refusals that share the stale_signature layer. The copy must be the first.
REPLAYED = "this signature was already presented (its nonce is spent): a replay"
BEFORE_MEMORY = "before this verifier's replay memory began"


def _load():
    os.environ["VLEI_CONSOLE_MINTED"] = "1"
    os.environ.pop("VLEI_CONSOLE_TARGET", None)
    os.environ.pop("VLEI_PUBLIC", None)
    os.environ["VLEI_GATEWAY_URL"] = "http://127.0.0.1:9/mcp"
    os.environ["VLEI_SKILL_SERVER_URL"] = "http://127.0.0.1:9/mcp"
    sys.argv = ["console"]
    spec = importlib.util.spec_from_file_location("console_app_replay", CONSOLE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def console():
    return _load()


def _client(module) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url="http://page")


class GatewayStandIn:
    """The gateway, in process, where the console's `_remote` would reach it over HTTP.

    Built as vlei-authz builds its verifier: the operator's LE, the accepted root, the gateway's
    own URL as the audience, the gateway's policy — and a replay store whose memory began an hour
    ago, so what it refuses is what it has seen, not what it might have missed while down.
    """

    URL = "http://gateway.test/mcp"

    def __init__(self, console: Any, *, system_refuses: str | None = None) -> None:
        self.console = console
        self.system_refuses = system_refuses
        self.received: list[str] = []
        self.identity = VleiIdentity(
            le_credential=console.ENV.le_file,
            accepted_roots=[console.ENV.root],
            revocation_source="tel",
            witness_url=console.ENV.witness,
            witness_client=console.ENV.witness_client(),
            today=console._today,
            audience_urls=[self.URL],
            replay_store=MemoryReplayStore(
                memory_since=datetime.now(timezone.utc) - timedelta(hours=1)),
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        console = self.console
        monkeypatch.setattr(console, "_target", lambda scene: "gateway")
        monkeypatch.setattr(console, "GATEWAY_URL", self.URL)
        # Who the console signs for, read from this gateway's own /.well-known/vlei document —
        # as the console's `_audience` reads the real gateway's.
        monkeypatch.setattr(console, "_audience", lambda: published_audience(
            self.identity.well_known_document(), self.URL))
        monkeypatch.setattr(console, "_remote", self)

    async def __call__(self, scene: dict[str, Any], meta: dict[str, Any],
                       arguments: dict[str, Any]) -> dict[str, Any]:
        params = {"name": scene["tool"], "arguments": arguments, "_meta": meta}
        self.received.append(json.dumps(params, sort_keys=True))
        report = VerificationReport(tool=scene["tool"])
        try:
            await self.identity.verify_call(CallToolRequestParams.model_validate(params),
                                            self.console._policy()[scene["tool"]], report=report)
        except VleiError as exc:
            # What call_through_gateway returns for vlei-authz's 403: the body's layer, message
            # and report.
            return {"reachable": True, "report": report.as_dict(), "allowed": False,
                    "layer": exc.layer.value, "text": f"{exc.layer.value}: {exc.message}",
                    "url": self.URL}
        if self.system_refuses:
            # Verified, then refused by labor-insurance-sim on a business rule: an error result
            # that still carries the gateway's report, as call_through_gateway reads it.
            return {"reachable": True, "report": report.as_dict(), "allowed": False,
                    "layer": None, "text": self.system_refuses, "url": self.URL}
        return {"reachable": True, "report": report.as_dict(), "allowed": True, "layer": None,
                "text": json.dumps({"action": "enrol", "record": {"personRef": arguments["person_ref"]}}),
                "url": self.URL}


async def test_the_original_is_accepted_and_the_same_bytes_again_are_refused_as_a_replay(
        console, monkeypatch):
    gateway = GatewayStandIn(console)
    gateway.install(monkeypatch)
    async with _client(console) as client:
        response = await client.post("/api/story/replay")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["target"] == "gateway" and body["url"] == GatewayStandIn.URL
    assert body["original"]["status"] == "allowed"
    assert body["original"]["systemRefused"] is None
    # `status` is the verifier's outcome. No HTTP status is returned: call_through_gateway does not
    # surface one, and an in-process verification has none — so none is made up.
    assert set(body["original"]) == set(body["copy"]) == {
        "status", "check", "layer", "message", "systemRefused", "sha256"}
    copy = body["copy"]
    assert (copy["status"], copy["check"], copy["layer"]) == ("refused", "freshness",
                                                              "stale_signature")
    assert copy["message"] == REPLAYED
    assert BEFORE_MEMORY not in copy["message"]
    assert body["identicalBytes"] is True
    assert body["original"]["sha256"] == copy["sha256"]
    assert body["runId"] and body["at"]

    # Independently of what the console says it sent: what the gateway received — twice, the same.
    assert len(gateway.received) == 2 and gateway.received[0] == gateway.received[1]
    sent = json.loads(gateway.received[0])
    assert sent["arguments"] == {"person_ref": "EMP-0003",
                                 "start_date": console._today().isoformat(), "salary_grade": 3}
    assert body["arguments"] == sent["arguments"]


async def test_each_press_signs_a_new_call(console, monkeypatch):
    """A second take is a new filing, not a third delivery of the first take's signature."""
    gateway = GatewayStandIn(console)
    gateway.install(monkeypatch)
    async with _client(console) as client:
        first = (await client.post("/api/story/replay")).json()
        second = (await client.post("/api/story/replay")).json()
    assert [first["original"]["status"], second["original"]["status"]] == ["allowed", "allowed"]
    assert first["runId"] != second["runId"]
    assert first["original"]["sha256"] != second["original"]["sha256"]


async def test_a_system_refusal_after_the_gateway_accepted_is_said_not_hidden(console, monkeypatch):
    gateway = GatewayStandIn(console, system_refuses="no employer is registered under this LEI")
    gateway.install(monkeypatch)
    async with _client(console) as client:
        body = (await client.post("/api/story/replay")).json()
    assert body["original"]["status"] == "allowed"
    assert body["original"]["systemRefused"] == "no employer is registered under this LEI"
    assert (body["copy"]["status"], body["copy"]["message"]) == ("refused", REPLAYED)
    assert body["copy"]["systemRefused"] is None


async def test_without_a_gateway_the_consoles_own_verifier_refuses_the_copy(console):
    """A minted world, which no gateway trusts: the console's in-process verifier, with its own
    replay memory, decides — and the response says so."""
    async with _client(console) as client:
        response = await client.post("/api/story/replay")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["target"] == "policy" and body["url"] is None
    assert body["original"]["status"] == "allowed"
    assert (body["copy"]["status"], body["copy"]["layer"]) == ("refused", "stale_signature")
    assert body["copy"]["message"] == REPLAYED
    assert body["identicalBytes"] is True


async def test_a_gateway_whose_identity_cannot_be_read_is_sent_nothing(console, monkeypatch):
    sent: list[Any] = []
    signed: list[Any] = []

    async def deliver(*args: Any) -> dict[str, Any]:
        sent.append(args)
        return {"reachable": True, "report": None}

    real_sign = console.sign_request

    def sign(*args: Any, **kwargs: Any) -> Any:
        signed.append(args)
        return real_sign(*args, **kwargs)

    monkeypatch.setattr(console, "_target", lambda scene: "gateway")
    monkeypatch.setattr(console, "_gateway_audience", None)
    monkeypatch.setattr(console, "_remote", deliver)
    monkeypatch.setattr(console, "_in_process", deliver)
    monkeypatch.setattr(console, "sign_request", sign)
    async with _client(console) as client:
        response = await client.post("/api/story/replay")

    assert response.status_code == 502
    error = response.json()["error"]
    assert error.startswith("AudienceUnavailable: ")
    assert "/.well-known/vlei could not be read" in error
    assert sent == [] and signed == []


async def test_the_gateway_document_is_never_fetched_on_the_event_loop(console, monkeypatch):
    """A blocking httpx.get inside an async handler stalls every other request on the page for up
    to its timeout. Wherever the console signs for the gateway — the replay scene, a recorded
    scene, the interactive page — the gateway's document is read off the event loop."""
    import threading

    loop_thread = threading.get_ident()
    fetched_on: list[int] = []

    def get(url: str, **kwargs: Any) -> Any:
        fetched_on.append(threading.get_ident())
        raise httpx.ConnectError("refused")

    async def deliver(*args: Any) -> dict[str, Any]:
        return {"reachable": True, "report": None}

    monkeypatch.setattr(console, "_target", lambda scene: "gateway")
    monkeypatch.setattr(console, "_gateway_audience", None)
    monkeypatch.setattr(console.httpx, "get", get)
    monkeypatch.setattr(console, "_remote", deliver)
    monkeypatch.setattr(console, "_in_process", deliver)
    async with _client(console) as client:
        replay = await client.post("/api/story/replay")
        scene = await client.post("/scene/1")
        listing = (await client.get("/api/scenarios")).json()
        s = next(item for item in listing["scenarios"] if item["id"] == "enroll-today")
        call = await client.post("/api/call", json={"tool": s["tool"], "arguments": s["arguments"],
                                                    "variant": s["variant"]})

    assert replay.status_code == 502 and scene.status_code == 200, (replay.text, scene.text)
    assert call.status_code in (200, 502), call.text
    assert len(fetched_on) == 3, fetched_on
    assert loop_thread not in fetched_on, "the gateway's document was fetched on the event loop"


class _Overlap:
    """A slow stand-in for signing that records how many ran at once."""

    def __init__(self) -> None:
        import threading

        self.running = self.most = 0
        self.finished: list[str] = []
        self._lock = threading.Lock()

    def __call__(self, tag: str) -> str:
        import time

        with self._lock:
            self.running += 1
            self.most = max(self.most, self.running)
        time.sleep(0.05)
        with self._lock:
            self.running -= 1
            self.finished.append(tag)
        return tag


async def test_two_signings_at_once_take_turns(console):
    """One agent keystore behind every signing: two `kli sign` runs on it at once are what
    vlei-pop and the association server serialise; the console does the same."""
    import asyncio

    overlap = _Overlap()
    done = await asyncio.gather(console._signed_off_loop(overlap, "a"),
                                console._signed_off_loop(overlap, "b"))
    assert sorted(done) == ["a", "b"] and overlap.most == 1


async def test_the_page_and_the_story_share_one_signing_turn(console):
    import asyncio

    backend = console._PAGE_BACKEND
    assert backend.signing is console._SIGNING
    overlap = _Overlap()
    done = await asyncio.gather(console._signed_off_loop(overlap, "story"),
                                console.interactive._off_loop(backend.signing, overlap, "page"))
    assert sorted(done) == ["page", "story"] and overlap.most == 1


async def test_a_reissue_waits_for_a_signing_in_progress(console, monkeypatch):
    """In minted mode a signing reads the world's chain and SAID on a worker thread; a re-issue
    that replaced them half-way would pair one credential's chain with another's SAID."""
    import asyncio

    overlap = _Overlap()
    monkeypatch.setattr(console.ENV.world, "reissue_ecr",
                        lambda at: overlap.finished.append("reissued"))
    signing = asyncio.ensure_future(console._signed_off_loop(overlap, "signed"))
    await asyncio.sleep(0.01)  # the signing has its turn and is running
    await console.ENV.reissue()
    await signing
    assert overlap.finished == ["signed", "reissued"]


async def test_the_public_site_refuses_the_replay_scene(console, monkeypatch):
    sent: list[Any] = []

    async def deliver(*args: Any) -> dict[str, Any]:
        sent.append(args)
        return {"reachable": True, "report": None}

    monkeypatch.setattr(console, "PUBLIC", True)
    monkeypatch.setattr(console, "_remote", deliver)
    monkeypatch.setattr(console, "_in_process", deliver)
    async with _client(console) as client:
        response = await client.post("/api/story/replay")
    assert response.status_code == 403 and sent == []


def test_the_replay_scene_speaks_both_languages():
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))
    keys = ["st.replay.button", "st.replay.running", "st.replay.identical", "st.replay.different",
            "st.replay.where.gateway", "st.replay.where.policy", "st.replay.system"]
    keys += [f"st.replay.{which}.{status}" for which in ("original", "copy")
             for status in ("allowed", "refused", "unavailable")]
    for lang in ("zh", "en"):
        missing = [key for key in keys if not strings[lang].get(key, "").strip()]
        assert not missing, (lang, missing)
    assert strings["en"]["st.replay.button"] == "Replay a captured call"
    assert strings["zh"]["st.replay.button"] == "重送截到的呼叫"
    assert strings["en"]["st.replay.original.allowed"] == "the original call — accepted"
    assert strings["zh"]["st.replay.original.allowed"] == "原始呼叫——受理"
    assert strings["en"]["st.replay.copy.refused"].startswith("the same bytes again — refused: ")
    assert "{layer}" in strings["en"]["st.replay.copy.refused"]
    assert "{layer}" in strings["zh"]["st.replay.copy.refused"]


def test_the_layer_a_replay_is_refused_under_is_named_for_both_of_its_causes():
    """The package refuses a replay as stale_signature, the layer it shares with a signature outside
    its window. Its short label — the after-feed's, the outcome view's — must say both, or a filmed
    replay reads as merely late."""
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))
    assert strings["en"]["layer.short.stale_signature"] == "signature stale or already used"
    assert strings["zh"]["layer.short.stale_signature"] == "簽章過期或已用過"


def test_the_long_text_for_stale_signature_names_both_of_its_causes_too():
    """Not "older than 60 seconds": a replay is refused under this layer within the window."""
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))
    assert strings["en"]["layer.stale_signature"] == (
        "Stale or already used: the signature is outside its time window, or was already "
        "presented once — possibly a captured request sent again.")
    assert strings["zh"]["layer.stale_signature"] == (
        "簽章過期或已用過：超出簽章的時間窗，或已經出示過一次，可能是被攔下後重送的請求。")


def test_the_button_is_on_the_vlei_side_and_calls_the_scene():
    page = (CONSOLE / "static" / "story.html").read_text(encoding="utf-8")
    after = page[page.index('class="box side after"'):page.index('class="imp"')]
    assert 'id="replay"' in after and 'data-t="st.replay.button"' in after
    assert 'id="replay-out"' in after
    script = (CONSOLE / "static" / "story.js").read_text(encoding="utf-8")
    assert '"/api/story/replay"' in script
