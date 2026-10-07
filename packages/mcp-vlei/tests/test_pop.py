"""Proof of possession: who is answering, established before anything is presented.

Each refusal is a way a server could pass v0.2's check without holding its LE's key: copying the
public credential, relaying a challenge to the real server, replaying an old answer, signing with a
key the LE never delegated to.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
import pytest

from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.audience import Recipient
from mcp_vlei.errors import AudienceMismatch, InvalidSignature, StaleSignature, UnsupportedVersion
from mcp_vlei.kel import WitnessKeyStates
from mcp_vlei.pop import (
    MAX_POP_LIFETIME_SECONDS,
    MAX_POP_RESPONSE_BYTES,
    POP_PATH,
    PopResponder,
    challenge,
    pop_statement,
    prove_server,
)
from mcp_vlei.signing import _parse_ts, _rfc3339, canonicalize
from mcp_vlei.testing import Controller, World

URL = "http://gateway.test/mcp"
POP_URL = "http://gateway.test" + POP_PATH


def signer_for(controller: Controller) -> Signer:
    return Signer.from_seed(controller.pre, controller.seed)


def http_for(world: World, responder: PopResponder | None, *, tamper=None) -> httpx.AsyncClient:
    """One client for the witness and the server's PoP endpoint, as a real deployment has two hosts."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == POP_PATH:
            if responder is None:
                return httpx.Response(404, json={"error": "not found"})
            status, body = responder.respond(json.loads(request.content))
            return httpx.Response(status, json=tamper(body) if tamper else body)
        return world.witness_handler(request)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def prove(world: World, responder: PopResponder | None, **kwargs):
    http = kwargs.pop("http", None) or http_for(world, responder, tamper=kwargs.pop("tamper", None))
    return await prove_server(http=http, pop_url=POP_URL, endpoint_url=kwargs.pop("url", URL),
                              holder=world.le.pre,
                              key_states=WitnessKeyStates("http://witness", client=http), **kwargs)


@pytest.fixture
def world() -> World:
    return World(label="pop")


def responder(world: World, controller: Controller, **kwargs) -> PopResponder:
    return PopResponder(signer_for(controller), Recipient(world.le.pre, (URL,)), **kwargs)


class TimeSkewResponder:
    """Signs a challenge with a caller-chosen ``ts``/``exp`` instead of the clock-derived ones
    ``PopResponder`` computes — so a test can hand ``check_pop_response`` a bad window under a
    signature that verifies, proving the time check (not the signature check) is what refused it.
    ``PopResponder`` itself cannot produce these windows since Fix Round 1 (M4) rejects a lifetime
    outside 1..MAX_POP_LIFETIME_SECONDS at construction.
    """

    def __init__(self, controller: Controller, *, ts: datetime, exp: datetime) -> None:
        self._signer = signer_for(controller)
        self._ts, self._exp = ts, exp

    def respond(self, body: dict) -> tuple[int, dict]:
        nonce, url = body["nonce"], body["url"]
        statement = pop_statement(aid=self._signer.aid, nonce=nonce, url=url,
                                  ts=_rfc3339(self._ts), exp=_rfc3339(self._exp))
        sig = self._signer.sign(canonicalize(statement))
        return 200, {**statement, "sig": sig}


# --------------------------------------------------------------------------------------------- #
# The server's side
# --------------------------------------------------------------------------------------------- #

def test_the_responder_signs_the_challenge_it_was_sent(world):
    sent = challenge(URL)
    status, body = responder(world, world.le).respond(sent)
    assert status == 200
    assert (body["v"], body["aid"], body["nonce"], body["url"]) == ("vlei-pop/0.3", world.le.pre,
                                                                    sent["nonce"], URL)
    unsigned = {k: v for k, v in body.items() if k != "sig"}
    assert canonicalize(unsigned).isascii()


def test_the_responder_signs_only_for_its_own_endpoints(world):
    """A relay at another URL cannot obtain a proof for the URL its victim dialled."""
    status, body = responder(world, world.le).respond(challenge("http://relay.test/mcp"))
    assert status == 403 and body["layer"] == "audience_mismatch"


def test_the_403_for_an_unknown_endpoint_does_not_leak_this_servers_own_urls(world):
    """The refusal must not become a map of this server's loopback and tunnel addresses, and must
    not grow without bound just because the request did."""
    huge = "http://relay.test/" + "a" * 10_000
    status, body = responder(world, world.le).respond(challenge(huge))
    assert status == 403
    assert len(body["message"]) < 400
    assert URL not in body["message"]
    assert "…" in body["message"]


@pytest.mark.parametrize("bad", [None, [], {}, {"v": "vlei-pop/0.2", "nonce": "A" * 22, "url": URL},
                                 {"v": "vlei-pop/0.3", "nonce": "short", "url": URL},
                                 {"v": "vlei-pop/0.3", "nonce": "A" * 22, "url": "ftp://x/"},
                                 {"v": "vlei-pop/0.3", "nonce": "A" * 22, "url": 12345},
                                 {"v": "vlei-pop/0.3", "nonce": "A" * 22, "url": ["a", "b"]},
                                 {"v": "vlei-pop/0.3", "nonce": "A" * 22}])
def test_a_malformed_challenge_is_400_not_an_exception(world, bad):
    assert responder(world, world.le).respond(bad)[0] == 400


def test_a_keystore_that_cannot_sign_is_503(world):
    class Broken:
        aid = world.le.pre

        def sign(self, payload: bytes) -> str:
            raise RuntimeError("kli sign failed")

    status, _ = PopResponder(Broken(), Recipient(world.le.pre, (URL,))).respond(challenge(URL))
    assert status == 503


def test_a_signer_whose_aid_cannot_be_read_is_503_not_an_exception(world):
    """A ``CommandSigner`` may read its AID from the keystore lazily; a keystore that cannot be read
    then fails at ``.aid``, and that is the same unavailability as failing at ``.sign``."""
    class NoAid:
        @property
        def aid(self) -> str:
            raise RuntimeError("kli aid failed")

        def sign(self, payload: bytes) -> str:
            raise AssertionError("never reached")

    status, body = PopResponder(NoAid(), Recipient(world.le.pre, (URL,))).respond(challenge(URL))
    assert status == 503
    assert body == {"layer": None, "message": "the server could not sign (RuntimeError)"}


@pytest.mark.parametrize("bad_lifetime", [0, -1, 121])
def test_a_lifetime_outside_the_valid_range_is_rejected_at_construction(world, bad_lifetime):
    with pytest.raises(ValueError):
        PopResponder(signer_for(world.le), Recipient(world.le.pre, (URL,)), lifetime_seconds=bad_lifetime)


def test_the_default_lifetime_still_constructs(world):
    PopResponder(signer_for(world.le), Recipient(world.le.pre, (URL,)))


def test_a_server_offers_pop_only_when_it_has_a_signer(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    common = dict(le_credential=le, accepted_roots=[world.root.pre], witness_url="http://witness",
                  witness_client=world.witness_client(), audience_urls=[URL])
    without = VleiIdentity(**common)
    assert "pop" not in without.settings() and without.pop_response(challenge(URL))[0] == 404
    with_pop = VleiIdentity(**common, pop_signer=signer_for(world.le))
    assert with_pop.settings()["pop"] == with_pop.well_known_document()["pop"] == POP_PATH
    assert with_pop.pop_response(challenge(URL))[0] == 200


# --------------------------------------------------------------------------------------------- #
# The client's side: accepted
# --------------------------------------------------------------------------------------------- #

async def test_the_le_itself_proves_it(world):
    proof = await prove(world, responder(world, world.le))
    assert proof.responder_aid == world.le.pre and proof.delegated is False


async def test_a_key_the_le_delegated_to_proves_it(world):
    """The reference gateway signs with a delegated AID, so the LE's own key stays offline."""
    gateway = world.delegate("gateway", world.le)
    proof = await prove(world, responder(world, gateway))
    assert proof.responder_aid == gateway.pre and proof.delegated is True


# --------------------------------------------------------------------------------------------- #
# The client's side: refused, by layer
# --------------------------------------------------------------------------------------------- #

async def test_an_impostor_with_the_public_credential_but_not_the_key_is_refused(world):
    stranger = world.enrol(Controller("pop:stranger", witnesses=world.witnesses, toad=2))
    with pytest.raises(InvalidSignature, match="neither the server's LE"):
        await prove(world, responder(world, stranger))


async def test_a_delegate_of_someone_else_is_refused(world):
    elsewhere = world.delegate("gateway-of-holder", world.holder)
    with pytest.raises(InvalidSignature, match="neither the server's LE"):
        await prove(world, responder(world, elsewhere))


async def test_a_delegation_the_le_never_anchored_is_refused(world):
    rogue = world.delegate("rogue", world.le, approve=False)
    with pytest.raises(InvalidSignature, match="not established"):
        await prove(world, responder(world, rogue))


async def test_a_signature_under_a_key_rotated_away_is_refused(world):
    old = signer_for(world.le)
    world.le.rotate()
    stale_key = PopResponder(old, Recipient(world.le.pre, (URL,)))
    with pytest.raises(InvalidSignature, match="does not verify"):
        await prove(world, stale_key)


async def test_an_answer_to_another_challenge_is_audience_mismatch(world):
    other_nonce = challenge(URL)["nonce"]
    with pytest.raises(AudienceMismatch, match="another challenge"):
        await prove(world, responder(world, world.le), tamper=lambda b: {**b, "nonce": other_nonce})


async def test_a_server_that_will_not_prove_itself_for_this_url_is_audience_mismatch(world):
    with pytest.raises(AudienceMismatch, match="will not prove itself"):
        await prove(world, responder(world, world.le), url="http://localhost:9999/mcp")


async def test_an_old_proof_is_stale(world):
    then = datetime.now(timezone.utc) - timedelta(minutes=10)
    with pytest.raises(StaleSignature, match="not fresh"):
        await prove(world, responder(world, world.le, clock=lambda: then))


async def test_a_proof_whose_window_runs_backwards_is_stale(world):
    """``exp <= ts``: signed validly, but the window it states is empty or negative."""
    now = datetime.now(timezone.utc)
    bad = TimeSkewResponder(world.le, ts=now, exp=now)
    with pytest.raises(StaleSignature, match="impossible validity"):
        await prove(world, bad)


async def test_a_proof_whose_window_exceeds_the_maximum_lifetime_is_stale(world):
    """``exp - ts`` beyond ``MAX_POP_LIFETIME_SECONDS``: a responder is never allowed to state a
    longer validity than a client will ever accept, signature notwithstanding."""
    now = datetime.now(timezone.utc)
    bad = TimeSkewResponder(world.le, ts=now, exp=now + timedelta(seconds=MAX_POP_LIFETIME_SECONDS + 1))
    with pytest.raises(StaleSignature, match="impossible validity"):
        await prove(world, bad)


async def test_a_proof_whose_ts_is_ahead_of_the_clients_clock_beyond_the_skew_is_stale(world):
    """A validly-windowed, validly-signed proof, but its ``ts`` is further ahead of this client's
    clock than the freshness skew allows."""
    now = datetime.now(timezone.utc)
    bad = TimeSkewResponder(world.le, ts=now + timedelta(seconds=90), exp=now + timedelta(seconds=120))
    with pytest.raises(StaleSignature, match="not fresh"):
        await prove(world, bad)


@pytest.mark.parametrize("field", ["ts", "exp"])
async def test_a_proof_whose_timestamp_is_malformed_is_invalid_not_stale(world, field):
    """A proof with a timestamp that is not RFC 3339 is a malformed proof — no clock makes it fresh."""
    with pytest.raises(InvalidSignature, match=f"proof's {field} is not RFC 3339") as exc:
        await prove(world, responder(world, world.le), tamper=lambda b: {**b, field: "yesterday"})
    assert exc.value.aid == world.le.pre


def _pop_answering(world: World, response: Callable[[], httpx.Response]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == POP_PATH:
            return response()
        return world.witness_handler(request)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_an_oversize_answer_is_refused_unread(world):
    """A proof is a few hundred bytes; an answer beyond the cap is not read into memory to find
    out what it is."""
    big = b'{"v": "vlei-pop/0.3", "pad": "' + b"a" * (MAX_POP_RESPONSE_BYTES + 1) + b'"}'
    http = _pop_answering(world, lambda: httpx.Response(200, content=big))
    with pytest.raises(InvalidSignature, match="response too large"):
        await prove(world, None, http=http)


async def test_an_oversize_answer_without_a_length_is_refused_as_it_streams(world):
    read: list[int] = []

    async def chunks():
        for _ in range(200):
            read.append(1)
            yield b"a" * 1024

    http = _pop_answering(world, lambda: httpx.Response(200, content=chunks()))
    with pytest.raises(InvalidSignature, match="response too large"):
        await prove(world, None, http=http)
    assert len(read) <= MAX_POP_RESPONSE_BYTES // 1024 + 1, "read the whole answer"


async def test_a_404_is_unsupported_version_however_large_its_body(world):
    """A v0.2 server's 404 page is not read for meaning, so its size cannot turn "offers no proof"
    (unsupported_version) into "response too large" (invalid_signature)."""
    big = b"<html>" + b"a" * (MAX_POP_RESPONSE_BYTES + 1) + b"</html>"

    async def streamed():
        for _ in range(MAX_POP_RESPONSE_BYTES // 1024 + 2):
            yield b"a" * 1024

    for answer in (lambda: httpx.Response(404, content=big),  # declares its length
                   lambda: httpx.Response(404, content=streamed())):  # declares none
        with pytest.raises(UnsupportedVersion, match="404"):
            await prove(world, None, http=_pop_answering(world, answer))


async def test_an_answer_nested_too_deep_to_parse_is_invalid_not_a_crash(world):
    nested = b"[" * 20000 + b"]" * 20000
    http = _pop_answering(world, lambda: httpx.Response(200, content=nested))
    with pytest.raises(InvalidSignature, match="not a vlei-pop/0.3 statement"):
        await prove(world, None, http=http)


async def test_a_server_without_a_pop_endpoint_is_unsupported_version(world):
    with pytest.raises(UnsupportedVersion, match="404"):
        await prove(world, None)


async def test_an_unreachable_pop_endpoint_is_not_established(world):
    def down(request: httpx.Request) -> httpx.Response:
        if request.url.path == POP_PATH:
            raise httpx.ConnectError("refused", request=request)
        return world.witness_handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(down))
    with pytest.raises(InvalidSignature, match="could not be obtained"):
        await prove(world, None, http=http)


async def test_a_tampered_proof_does_not_verify(world):
    with pytest.raises(InvalidSignature, match="does not verify"):
        await prove(world, responder(world, world.le), tamper=lambda b: {**b, "sig": "0B" + "A" * 86})


async def test_a_signed_field_moved_by_one_second_does_not_verify(world):
    """``ts`` shifted by a single second, ``sig`` left as it was: the payload the signature covers
    no longer matches what is presented, however small the change — caught here, not at the
    (still-fresh, still well-windowed) time checks that run first."""
    def shift_ts(body: dict) -> dict:
        shifted = _parse_ts(body["ts"]) + timedelta(seconds=1)
        return {**body, "ts": _rfc3339(shifted)}

    with pytest.raises(InvalidSignature, match="does not verify"):
        await prove(world, responder(world, world.le), tamper=shift_ts)


async def test_a_server_whose_keystore_cannot_sign_is_not_established(world):
    def busy(request: httpx.Request) -> httpx.Response:
        if request.url.path == POP_PATH:
            return httpx.Response(503, json={"layer": None, "message": "no signer"})
        return world.witness_handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(busy))
    with pytest.raises(InvalidSignature, match="HTTP 503"):
        await prove(world, None, http=http)


def test_a_server_that_learns_its_address_late_can_say_where_it_answers(world, tmp_path):
    """A server on port 0 knows its URL only once it listens: both checks move together."""
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    server = VleiIdentity(le_credential=le, accepted_roots=[world.root.pre], witness_url="http://witness",
                          witness_client=world.witness_client(), audience_urls=["http://placeholder/mcp"],
                          pop_signer=signer_for(world.le))
    server.set_audience_urls(["http://127.0.0.1:50123/mcp"])
    assert server.recipient.urls == ("http://127.0.0.1:50123/mcp",)
    assert server.pop_response(challenge("http://127.0.0.1:50123/mcp"))[0] == 200
    assert server.pop_response(challenge("http://placeholder/mcp"))[0] == 403
