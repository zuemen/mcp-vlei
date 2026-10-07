"""vlei-pop — who operates this gateway, and the proof that it holds the key.

Two public routes, outside the gateway's external authorization (deploy/agentgateway/config.yaml):

* ``GET /.well-known/vlei`` — the operator's LE credential, the signature format the gateway
  verifies (``vlei-sig/0.3``), where to challenge it, and how long a client may rely on what it
  verified (``ttlMs``).
* ``POST /.well-known/vlei/pop`` — a client's challenge, answered with a statement signed by the
  gateway's AID (``mcp_vlei.pop``). The AID is delegated by the operator's LE, so the LE's own key
  stays offline; ``scripts/bootstrap-gateway-signer.sh`` creates it.

Signing is ``kli sign`` in this container's own KERI keystore: the private key never leaves the
keystore and is never in this process. It takes seconds, so challenges are signed one at a time and
a short queue beyond that is answered 503.

Configuration is environment only:

* ``VLEI_LE_CREDENTIAL`` — the operator's LE credential (CESR). Required.
* ``VLEI_ACCEPTED_ROOTS`` — published for clients, comma-separated.
* ``VLEI_AUDIENCE_URLS`` — the endpoint URLs this gateway answers at; it proves itself for no
  other. Required.
* ``VLEI_POP_KEYSTORE`` — keystore and alias ``kli sign`` uses. Default ``gateway``.
* ``VLEI_TTL_MS`` — advertised ``ttlMs``. Default 300000.
* ``MCP_VLEI_NAMESPACE`` — the extension's namespace (provisional default ``org.gleif.vlei``).

Simulated — not connected to the Bureau of Labor Insurance. Every identity is fictional.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable, Sequence

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_vlei.audience import Recipient
from mcp_vlei.chain import VLEI_SCHEMAS
from mcp_vlei.extension import _presented
from mcp_vlei.namespace import keys as namespace_keys
from mcp_vlei.pop import POP_PATH, PopResponder
from mcp_vlei.signing import SIGNATURE_FORMAT, CommandSigner

logger = logging.getLogger(__name__)

SIMULATED = "Simulated — not connected to the Bureau of Labor Insurance"
DEFAULT_TTL_MS = 300_000
#: A challenge is a handful of short fields; nothing legitimate is anywhere near this large. Bounds
#: both a reported ``Content-Length`` and a chunked body that carries none.
MAX_POP_BODY_BYTES = 4096
_TOO_LARGE_MESSAGE = f"a challenge is at most {MAX_POP_BODY_BYTES} bytes"
#: An oversize body is read and discarded up to this much, so a sender that sent a little too much
#: reads its 413 rather than a reset; beyond it nothing more is read. Either way the 413 says
#: ``Connection: close``: no unread remainder is left on a connection the next request would share.
MAX_DRAIN_BYTES = 64 * 1024


def _too_large() -> JSONResponse:
    return JSONResponse({"layer": None, "message": _TOO_LARGE_MESSAGE}, status_code=413,
                        headers={"Connection": "close"})


def _kli(args: list[str], timeout: float = 15.0) -> str:
    result = subprocess.run(["kli", *args], capture_output=True, text=True, timeout=timeout,
                            stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        # The tail is diagnostic, not client-facing: it can carry local paths or keystore detail
        # that a caller of this service has no business seeing. Logged here, at the one place both
        # `kli aid` (building the signer) and `kli sign` (answering a challenge) run through, so
        # neither catch site above losing it also loses it from the server's own logs.
        tail = result.stderr.strip()[-300:]
        logger.warning("kli %s failed (exit %s): %s", args[0], result.returncode, tail)
        raise RuntimeError(f"kli {args[0]} failed: {tail}")
    return result.stdout


def kli_signer(keystore: str, alias: str | None = None) -> CommandSigner:
    """A signer over ``kli sign`` in a local keystore: the key stays in the keystore."""
    alias = alias or keystore
    aid = _kli(["aid", "--name", keystore, "--alias", alias]).strip().splitlines()[-1].strip()
    return CommandSigner(
        aid=aid, verkey="",
        command=lambda text: _kli(["sign", "--name", keystore, "--alias", alias, "--text", text]),
    )


def create_app(
    *,
    le_credential: str,
    audience_urls: Sequence[str],
    signer: Any | Callable[[], Any],
    accepted_roots: Sequence[str] = (),
    ttl_ms: int = DEFAULT_TTL_MS,
    namespace: str | None = None,
    max_waiting: int = 4,
) -> Starlette:
    """The two routes. ``signer`` may be a callable that builds it on first use: reading the AID
    from a keystore takes seconds, and the well-known document should not wait for it."""
    presented = _presented(le_credential, None)
    if presented.schema != VLEI_SCHEMAS["LE"]:
        actual = next((name for name, said in VLEI_SCHEMAS.items() if said == presented.schema), None)
        raise ValueError(
            "vlei-pop publishes the operator's legal-entity (LE) credential; the presented "
            f"credential {presented.said} is {'an ' + actual if actual else 'of schema ' + presented.schema} "
            "credential, which may carry person data and must never be served at /.well-known/vlei"
        )
    recipient = Recipient(presented.issuee, tuple(audience_urls))
    keys = namespace_keys(namespace)
    document = {
        "extension": keys.extension,
        "credential": le_credential,
        "acceptedRoots": list(accepted_roots),
        "signatureAlgs": ["Ed25519"],
        "signatureFormats": [SIGNATURE_FORMAT],
        "pop": POP_PATH,
        "ttlMs": ttl_ms,
        "note": SIMULATED,
    }
    lock = threading.Lock()
    held: dict[str, Any] = {"recipient": recipient}

    def responder() -> PopResponder:
        with lock:
            if "responder" not in held:
                held["responder"] = PopResponder(signer() if callable(signer) else signer,
                                                 held["recipient"])
            return held["responder"]

    def set_audience_urls(urls: Sequence[str]) -> None:
        """For a gateway that learns its address only once it listens (port 0)."""
        with lock:
            held["recipient"] = Recipient(recipient.aid, tuple(urls))
            if "responder" in held:
                held["responder"].recipient = held["recipient"]

    gate = asyncio.Semaphore(1)
    waiting = {"n": 0}

    async def well_known(_: Request) -> JSONResponse:
        return JSONResponse(document)

    async def read_challenge(request: Request) -> tuple[Any, JSONResponse | None]:
        """The parsed body, or the refusal for it: oversize (413 — a reported ``Content-Length``
        checked up front, a chunked body with none bounded as it is read; drained up to
        ``MAX_DRAIN_BYTES``, and the connection closed) or not JSON, including JSON nested deep
        enough to exhaust the recursion limit (400, the same refusal as any other malformed
        challenge — never an unhandled crash)."""
        content_length = request.headers.get("content-length", "").strip()
        declared = int(content_length) if content_length.isdigit() else None
        if declared is not None and declared > MAX_DRAIN_BYTES:
            return None, _too_large()  # not worth reading; closed with the answer
        oversize = declared is not None and declared > MAX_POP_BODY_BYTES
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            oversize = oversize or total > MAX_POP_BODY_BYTES
            if oversize:
                if total > MAX_DRAIN_BYTES:
                    break  # stop reading: the connection closes with the 413
                continue  # drained, not kept
            chunks.append(chunk)
        if oversize:
            return None, _too_large()
        try:
            return json.loads(b"".join(chunks)), None
        except (ValueError, RecursionError):
            return None, JSONResponse({"layer": None, "message": "a challenge is JSON"}, status_code=400)

    async def pop(request: Request) -> JSONResponse:
        # Claim a slot before anything that can await — including reading the body — so a client
        # cannot hold a slot open merely by sending slowly; `max_waiting` bounds requests actually
        # admitted, not requests merely received.
        if waiting["n"] >= max_waiting:
            return JSONResponse({"layer": None, "message": "busy: try again in a few seconds"},
                                status_code=503)
        waiting["n"] += 1
        try:
            body, refusal = await read_challenge(request)
            if refusal is not None:
                return refusal
            async with gate:
                try:
                    answering = await anyio.to_thread.run_sync(responder)
                except Exception as exc:  # noqa: BLE001 - the keystore could not be read
                    return JSONResponse({"layer": None, "message": f"no signer ({type(exc).__name__})"},
                                        status_code=503)
                status, payload = await anyio.to_thread.run_sync(answering.respond, body)
            return JSONResponse(payload, status_code=status)
        finally:
            waiting["n"] -= 1

    async def health(_: Request) -> JSONResponse:
        answering = held.get("responder")
        return JSONResponse({
            "ok": True,
            "audience": {"aid": held["recipient"].aid, "urls": list(held["recipient"].urls)},
            "signer": answering.signer.aid if answering else None,
        })

    app = Starlette(routes=[
        Route("/.well-known/vlei", well_known, methods=["GET"]),
        Route(POP_PATH, pop, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
    ])
    app.state.set_audience_urls = set_audience_urls
    return app


def from_env(environ: dict[str, str] | None = None) -> Starlette:
    env = os.environ if environ is None else environ
    raw_credential = env.get("VLEI_LE_CREDENTIAL", "").strip()
    if not raw_credential:
        raise RuntimeError("VLEI_LE_CREDENTIAL is not set")
    le_path = Path(raw_credential)
    if not le_path.is_file():
        raise RuntimeError(f"VLEI_LE_CREDENTIAL {str(le_path)!r} does not exist")
    audience = [u.strip() for u in env.get("VLEI_AUDIENCE_URLS", "").split(",") if u.strip()]
    if not audience:
        raise RuntimeError("VLEI_AUDIENCE_URLS is empty: the gateway proves itself only for its own URLs")
    keystore = env.get("VLEI_POP_KEYSTORE", "gateway").strip() or "gateway"
    raw_ttl = env.get("VLEI_TTL_MS", "").strip()
    ttl_ms = DEFAULT_TTL_MS
    if raw_ttl:
        try:
            ttl_ms = int(raw_ttl)
        except ValueError:
            ttl_ms = 0  # fall through to the same refusal as a non-positive value
        if ttl_ms <= 0:
            raise RuntimeError(f"VLEI_TTL_MS must be a positive integer of milliseconds, not {raw_ttl!r}")
    return create_app(
        le_credential=le_path.read_text(encoding="utf-8").strip(),
        audience_urls=audience,
        signer=lambda: kli_signer(keystore),
        accepted_roots=[r.strip() for r in env.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r.strip()],
        ttl_ms=ttl_ms,
        namespace=env.get("MCP_VLEI_NAMESPACE", "").strip() or None,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(from_env(), host=os.environ.get("HOST", "0.0.0.0"),
                port=int(os.environ.get("PORT", "9100")))
