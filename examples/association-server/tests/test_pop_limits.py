"""Fix round 1: abuse limits on POST /.well-known/vlei/pop.

This route is unauthenticated and internet-facing, and each challenge it answers ends in a
``kli sign`` subprocess (through ``LazyKeystoreSigner``) that takes seconds. These tests check the
limits that keep a slow or oversized sender from exhausting that one signer: a body-size cap
enforced both from ``Content-Length`` and while streaming, malformed JSON refused rather than
crashing, an admission counter claimed before the body is read, and signing serialised one
challenge at a time.

None of this touches Docker or ``kli``: the module-level ``vlei`` this file imports is built
against a credential minted in-process by ``mcp_vlei.testing.World`` (the same path
``examples/console/app.py`` uses when there is no live environment), ``Path.read_text`` is
intercepted in memory for the one read ``server.py`` makes of ``credentials/le.cesr`` — nothing is
written to or read from that directory on disk — and the signer ``server.py`` builds
(``kli_signer.keystore_signer``) is replaced with a pure-Python fake that counts calls instead of
running ``kli``.

Run::

    PYTHONPATH=packages/mcp-vlei/src python -m pytest examples/association-server/tests/test_pop_limits.py -q
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
import pytest

_HERE = Path(__file__).resolve()
_SERVER_DIR = _HERE.parents[1]
_ROOT = _HERE.parents[3]
_LE_PATH = _ROOT / "credentials" / "le.cesr"
#: examples/association-server/server.py, imported under this name — never as a bare ``server``.
_MODULE_NAME = "association_server_under_test"

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


class _FakeSigner:
    """Counts signing calls without running `kli` or touching Docker; never holds a real key."""

    aid = "E" + "F" * 43
    verkey = ""

    def __init__(self) -> None:
        self.calls = 0

    def sign(self, payload: bytes) -> str:
        self.calls += 1
        return "AA" + "Z" * 86


@pytest.fixture(scope="module")
def pop_app():
    """Import `examples/association-server/server.py` with a minted LE credential, a fake root
    AID, a temp replay store and a fake, never-kli signer — then hand back its ASGI app and the
    fake signer, so a test can see how many times it was called."""
    from mcp_vlei.testing import World

    world = World(role="labor-insurance-filing", label="association-server-pop-limits")
    fake_signer = _FakeSigner()

    real_read_text = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if self == _LE_PATH:
            return world.le_stream
        return real_read_text(self, *args, **kwargs)

    env_backup = {k: os.environ.get(k) for k in ("VLEI_ROOT_AID", "VLEI_REPLAY_DB")}
    os.environ["VLEI_ROOT_AID"] = world.root.pre
    os.environ["VLEI_REPLAY_DB"] = str(Path(tempfile.mkdtemp()) / "replay.sqlite3")

    sys.path.insert(0, str(_ROOT / "examples" / "my-agent"))
    import kli_signer  # the module server.py itself imports LazyKeystoreSigner from

    real_keystore_signer = kli_signer.keystore_signer
    kli_signer.keystore_signer = lambda keystore, alias: fake_signer

    import importlib.util

    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _SERVER_DIR / "server.py")
    server = importlib.util.module_from_spec(spec)
    Path.read_text = fake_read_text
    try:
        sys.modules[_MODULE_NAME] = server
        spec.loader.exec_module(server)  # examples/association-server/server.py
    finally:
        Path.read_text = real_read_text
        kli_signer.keystore_signer = real_keystore_signer
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return server.mcp.streamable_http_app(), fake_signer, server.PUBLIC_URL + "/mcp"


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://association.test")


def _challenge(url: str) -> dict[str, str]:
    from mcp_vlei.pop import challenge

    return challenge(url)


def test_the_server_is_imported_under_a_name_of_its_own(pop_app):
    """A generic ``server`` in sys.modules would be whichever examples/*/server.py a run imported
    first — another suite's, or this one handed to a test that meant another."""
    loaded = sys.modules.get(_MODULE_NAME)
    assert loaded is not None and Path(loaded.__file__).resolve() == _SERVER_DIR / "server.py"
    assert sys.modules.get("server") is not loaded


async def test_a_valid_challenge_is_answered_and_the_fake_signer_is_used(pop_app):
    """Sanity check for the fixture itself: a well-formed challenge for this server's own
    endpoint is answered 200, signed by the fake signer — never `kli`, never Docker."""
    app, fake_signer, endpoint = pop_app
    before = fake_signer.calls
    async with client_for(app) as http:
        response = await http.post("/.well-known/vlei/pop", json=_challenge(endpoint))
    assert response.status_code == 200
    assert fake_signer.calls == before + 1


async def test_an_oversize_body_with_content_length_is_413(pop_app):
    """A reported Content-Length beyond the bound is refused before the body is read."""
    app, fake_signer, endpoint = pop_app
    before = fake_signer.calls
    big = json.dumps({"v": "vlei-pop/0.3", "nonce": "a" * 5000, "url": endpoint}).encode()
    async with client_for(app) as http:
        response = await http.post("/.well-known/vlei/pop", content=big)
    assert response.status_code == 413
    assert fake_signer.calls == before  # never reached signing


async def test_a_chunked_oversize_body_without_content_length_is_413(pop_app):
    """A chunked body carries no Content-Length, so the bound is enforced while reading too."""
    app, fake_signer, _endpoint = pop_app
    before = fake_signer.calls

    async def chunks():
        for _ in range(10):
            yield b"a" * 1000

    async with client_for(app) as http:
        response = await http.post("/.well-known/vlei/pop", content=chunks())
    assert response.status_code == 413
    assert fake_signer.calls == before


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


async def test_an_oversize_body_is_drained_and_the_connection_closed(pop_app):
    """413 with the rest of a modestly oversize body read and discarded — not left on a
    connection the next request would share — and ``Connection: close`` besides."""
    app, fake_signer, _endpoint = pop_app
    received: list[int] = []

    async def chunks():
        for _ in range(10):
            yield b"a" * 1000

    async with client_for(_counting(app, received)) as http:
        response = await http.post("/.well-known/vlei/pop", content=chunks())
    assert response.status_code == 413
    assert response.headers.get("connection") == "close"
    assert sum(received) == 10_000, "the rest of the body was left unread"


async def test_a_body_beyond_the_drain_bound_is_not_read_to_its_end(pop_app):
    app, _fake_signer, _endpoint = pop_app
    received: list[int] = []

    async def chunks():
        for _ in range(200):
            yield b"a" * 1000

    async with client_for(_counting(app, received)) as http:
        response = await http.post("/.well-known/vlei/pop", content=chunks())
    assert response.status_code == 413 and response.headers.get("connection") == "close"
    assert sum(received) <= 64 * 1024 + 1000, "read far more than the bound"


async def test_deeply_nested_json_is_400_not_a_crash(pop_app):
    """A RecursionError from deeply nested JSON is the same labelled 400 as any other malformed
    challenge, never an unhandled 500."""
    app, fake_signer, _endpoint = pop_app
    before = fake_signer.calls
    nested = b"[" * 2000 + b"]" * 2000
    server_module = sys.modules[_MODULE_NAME]

    assert len(nested) <= server_module.MAX_POP_BODY_BYTES
    async with client_for(app) as http:
        response = await http.post("/.well-known/vlei/pop", content=nested)
    assert response.status_code == 400
    assert fake_signer.calls == before


async def _slow_challenge(url: str, chunk: int = 8, delay: float = 0.01):
    body = json.dumps(_challenge(url)).encode()
    for i in range(0, len(body), chunk):
        yield body[i : i + chunk]
        await asyncio.sleep(delay)


async def test_the_queue_bound_is_checked_before_a_slow_body_is_read(pop_app):
    """A slow body must not let more than the admitted bound bypass the admission check: the slot
    is claimed before anything that can await, body reading included. Extra requests beyond the
    bound are refused 503, and the signer is called at most the number actually admitted."""
    app, fake_signer, endpoint = pop_app
    server_module = sys.modules[_MODULE_NAME]

    before = fake_signer.calls
    attempts = server_module._POP_MAX_WAITING + 4
    async with client_for(app) as http:
        responses = await asyncio.gather(
            *(http.post("/.well-known/vlei/pop", content=_slow_challenge(endpoint))
              for _ in range(attempts))
        )
    statuses = [r.status_code for r in responses]
    accepted = statuses.count(200)
    refused = statuses.count(503)
    assert accepted + refused == attempts
    assert 1 <= accepted <= server_module._POP_MAX_WAITING
    assert fake_signer.calls - before == accepted
