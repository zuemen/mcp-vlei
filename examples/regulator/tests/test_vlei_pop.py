"""vlei-pop: the gateway's public identity, and the proof that it holds the key behind it."""

from __future__ import annotations

import asyncio
import json
import logging

import httpx
import pytest
from conftest import GATEWAY_URL, pop_app, pop_service, signer_for

from mcp_vlei.kel import WitnessKeyStates
from mcp_vlei.pop import POP_PATH, challenge, prove_server


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway.test")


async def test_the_well_known_document_says_how_to_check_the_gateway(world):
    async with client_for(pop_app(world)) as http:
        document = (await http.get("/.well-known/vlei")).json()
    assert document["credential"] == world.le_stream
    assert document["signatureFormats"] == ["vlei-sig/0.3"]
    assert document["pop"] == POP_PATH and document["ttlMs"] == 300_000
    assert document["acceptedRoots"] == [world.root.pre]
    assert "Simulated" in document["note"]


async def test_a_client_proves_the_gateway_through_it(world):
    async with client_for(pop_app(world)) as http:
        proof = await prove_server(http=http, pop_url="http://gateway.test" + POP_PATH,
                                   endpoint_url=GATEWAY_URL, holder=world.le.pre,
                                   key_states=WitnessKeyStates("http://witness",
                                                               client=world.witness_client()))
    assert proof.delegated is True and proof.responder_aid != world.le.pre


async def test_it_proves_nothing_for_someone_elses_url(world):
    async with client_for(pop_app(world)) as http:
        response = await http.post(POP_PATH, json=challenge("http://relay.test/mcp"))
    assert response.status_code == 403 and response.json()["layer"] == "audience_mismatch"


async def test_the_keystore_is_read_on_the_first_challenge_not_at_start(world):
    made = []

    def make():
        made.append(1)
        return signer_for(world.le)

    async with client_for(pop_app(world, signer=make)) as http:
        await http.get("/.well-known/vlei")
        assert made == []
        await http.post(POP_PATH, json=challenge(GATEWAY_URL))
        await http.post(POP_PATH, json=challenge(GATEWAY_URL))
    assert made == [1]


async def test_a_full_queue_is_503_not_a_wait_forever(world):
    async with client_for(pop_app(world, max_waiting=0)) as http:
        response = await http.post(POP_PATH, json=challenge(GATEWAY_URL))
    assert response.status_code == 503


async def test_a_body_that_is_not_json_is_400(world):
    async with client_for(pop_app(world)) as http:
        response = await http.post(POP_PATH, content=b"not json")
    assert response.status_code == 400


def test_the_signer_asks_kli_and_never_holds_a_key(monkeypatch):
    calls = []

    class Done:
        def __init__(self, stdout):
            self.returncode, self.stdout, self.stderr = 0, stdout, ""

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "aid":
            return Done("E" + "G" * 43 + "\n")
        return Done("1. AA" + "B" * 86 + "\n")

    monkeypatch.setattr(pop_service.subprocess, "run", run)
    signer = pop_service.kli_signer("gateway")
    assert signer.aid == "E" + "G" * 43
    assert signer.sign(b'{"v":"vlei-pop/0.3"}') == "AA" + "B" * 86
    assert calls[1][:6] == ["kli", "sign", "--name", "gateway", "--alias", "gateway"]
    assert calls[1][-1] == '{"v":"vlei-pop/0.3"}'


def test_it_will_not_start_without_its_audience(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with pytest.raises(RuntimeError, match="VLEI_AUDIENCE_URLS"):
        pop_service.from_env({"VLEI_LE_CREDENTIAL": str(le)})


async def test_a_keystore_that_cannot_be_read_is_503_and_named(world):
    def broken():
        raise RuntimeError("kli aid failed: keystore gateway not found")

    async with client_for(pop_app(world, signer=broken)) as http:
        response = await http.post(POP_PATH, json=challenge(GATEWAY_URL))
    assert response.status_code == 503 and "no signer" in response.json()["message"]


# ---------------------------------------------------------------------------------------------- #
# Fix round 1: abuse-limit gaps on this unauthenticated, internet-facing service
# ---------------------------------------------------------------------------------------------- #

class _CountingSigner:
    """Counts signing calls without touching a keystore; never holds a real key."""

    aid = "E" + "C" * 43

    def __init__(self) -> None:
        self.calls = 0

    def sign(self, payload: bytes) -> str:
        self.calls += 1
        return "AA" + "D" * 86


async def _slow_challenge(url: str, chunk: int = 8, delay: float = 0.01):
    body = json.dumps(challenge(url)).encode()
    for i in range(0, len(body), chunk):
        yield body[i : i + chunk]
        await asyncio.sleep(delay)


async def test_the_queue_bound_is_checked_before_a_slow_body_is_read(world):
    """I1: a slow body must not let more than ``max_waiting`` requests bypass the admission
    check — the fix claims a slot before anything that can await, body reading included."""
    signer = _CountingSigner()
    async with client_for(pop_app(world, max_waiting=2, signer=signer)) as http:
        responses = await asyncio.gather(
            *(http.post(POP_PATH, content=_slow_challenge(GATEWAY_URL)) for _ in range(6))
        )
    statuses = [r.status_code for r in responses]
    accepted = statuses.count(200)
    refused = statuses.count(503)
    assert accepted + refused == 6
    assert 1 <= accepted <= 2
    assert signer.calls == accepted


async def test_an_oversize_body_with_content_length_is_413(world):
    """I2: a reported Content-Length beyond the bound is refused before the body is read."""
    big = json.dumps({"v": "vlei-pop/0.3", "nonce": "a" * 5000, "url": GATEWAY_URL}).encode()
    async with client_for(pop_app(world)) as http:
        response = await http.post(POP_PATH, content=big)
    assert response.status_code == 413


async def test_a_chunked_oversize_body_without_content_length_is_413(world):
    """I2: a chunked body carries no Content-Length, so the bound must also be enforced while
    reading, not only from a header a sender could omit or lie about."""

    async def chunks():
        for _ in range(10):
            yield b"a" * 1000

    async with client_for(pop_app(world)) as http:
        response = await http.post(POP_PATH, content=chunks())
    assert response.status_code == 413


def _counting(app, received: list[int]):
    """``app``, with every request-body byte it actually reads counted into ``received``."""
    async def counted_app(scope, receive, send):
        async def counted_receive():
            message = await receive()
            if message["type"] == "http.request":
                received.append(len(message.get("body", b"")))
            return message
        await app(scope, counted_receive, send)
    return counted_app


async def _chunks(count: int, size: int = 1000):
    for _ in range(count):
        yield b"a" * size


async def test_an_oversize_body_is_drained_and_the_connection_closed(world):
    """413 with the rest of a modestly oversize body read and discarded — not left on a
    connection the next request would share — and ``Connection: close`` besides."""
    received: list[int] = []
    async with client_for(_counting(pop_app(world), received)) as http:
        response = await http.post(POP_PATH, content=_chunks(10))
    assert response.status_code == 413
    assert response.headers.get("connection") == "close"
    assert sum(received) == 10_000, "the rest of the body was left unread"


async def test_a_body_beyond_the_drain_bound_is_not_read_to_its_end(world):
    received: list[int] = []
    async with client_for(_counting(pop_app(world), received)) as http:
        response = await http.post(POP_PATH, content=_chunks(200))
    assert response.status_code == 413 and response.headers.get("connection") == "close"
    assert sum(received) <= pop_service.MAX_DRAIN_BYTES + 1000, "read far more than the bound"


async def test_a_declared_length_beyond_the_drain_bound_is_refused_unread(world):
    received: list[int] = []
    async with client_for(_counting(pop_app(world), received)) as http:
        response = await http.post(POP_PATH, content=b"a" * (pop_service.MAX_DRAIN_BYTES + 1))
    assert response.status_code == 413 and response.headers.get("connection") == "close"
    assert sum(received) == 0


async def test_deeply_nested_json_is_400_not_a_crash(world):
    """I2: a RecursionError from deeply nested JSON is the same labelled 400 as any other
    malformed challenge, never an unhandled 500."""
    nested = b"[" * 2000 + b"]" * 2000
    assert len(nested) <= pop_service.MAX_POP_BODY_BYTES
    async with client_for(pop_app(world)) as http:
        response = await http.post(POP_PATH, content=nested)
    assert response.status_code == 400


async def test_a_kli_failure_logs_its_stderr_tail_but_the_response_never_carries_it(
    world, monkeypatch, caplog
):
    """I3: the stderr tail that explains a kli failure is logged server-side (at warning) and
    never appears in the HTTP response, which names only the exception type."""

    class Done:
        def __init__(self, stderr: str) -> None:
            self.returncode, self.stdout, self.stderr = 1, "", stderr

    def run(args, **kwargs):
        return Done("classified keystore diagnostic")

    monkeypatch.setattr(pop_service.subprocess, "run", run)
    app = pop_app(world, signer=lambda: pop_service.kli_signer("gateway"))
    async with client_for(app) as http:
        with caplog.at_level(logging.WARNING, logger=pop_service.logger.name):
            response = await http.post(POP_PATH, json=challenge(GATEWAY_URL))
    assert response.status_code == 503
    assert "classified keystore diagnostic" not in response.text
    assert "classified keystore diagnostic" in caplog.text


def test_from_env_without_a_credential_names_the_missing_variable():
    """Minor (a): an unset or empty VLEI_LE_CREDENTIAL is refused by name, not as a path that
    happens not to exist ('.')."""
    with pytest.raises(RuntimeError, match="^VLEI_LE_CREDENTIAL is not set$"):
        pop_service.from_env({})
    with pytest.raises(RuntimeError, match="^VLEI_LE_CREDENTIAL is not set$"):
        pop_service.from_env({"VLEI_LE_CREDENTIAL": "   "})


def test_create_app_refuses_to_publish_anything_but_an_le_credential(world):
    """Minor (b): an ECR (or any non-LE) credential carries person data and must never be
    published at /.well-known/vlei."""
    with pytest.raises(ValueError, match="legal-entity"):
        pop_service.create_app(le_credential=world.ecr_stream, audience_urls=[GATEWAY_URL],
                               signer=object())


def test_from_env_rejects_a_non_positive_or_non_integer_ttl(world, tmp_path):
    """Minor (c): VLEI_TTL_MS must be a positive integer of milliseconds."""
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    base_env = {"VLEI_LE_CREDENTIAL": str(le), "VLEI_AUDIENCE_URLS": GATEWAY_URL}
    for bad in ("0", "-5", "not-a-number"):
        with pytest.raises(RuntimeError, match="VLEI_TTL_MS"):
            pop_service.from_env({**base_env, "VLEI_TTL_MS": bad})


def test_the_signer_is_invoked_with_an_argument_list_no_shell_and_a_short_timeout(monkeypatch):
    """Minor (d)/(e): kli is run as an argument list (never a shell string) with a 15s timeout,
    not the original 60s."""
    calls = []

    class Done:
        def __init__(self, stdout):
            self.returncode, self.stdout, self.stderr = 0, stdout, ""

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if args[1] == "aid":
            return Done("E" + "G" * 43 + "\n")
        return Done("1. AA" + "B" * 86 + "\n")

    monkeypatch.setattr(pop_service.subprocess, "run", run)
    pop_service.kli_signer("gateway")
    args, kwargs = calls[0]
    assert isinstance(args, list)
    assert kwargs.get("timeout") == 15.0
    assert "shell" not in kwargs


async def test_set_audience_urls_changes_which_url_is_accepted(world):
    """Minor (e): set_audience_urls swaps which endpoint the responder proves itself for."""
    other_url = "http://relay.test/mcp"
    app = pop_app(world)
    async with client_for(app) as http:
        refused = await http.post(POP_PATH, json=challenge(other_url))
        assert refused.status_code == 403
        app.state.set_audience_urls([other_url])
        accepted = await http.post(POP_PATH, json=challenge(other_url))
        assert accepted.status_code == 200
        refused_again = await http.post(POP_PATH, json=challenge(GATEWAY_URL))
        assert refused_again.status_code == 403
