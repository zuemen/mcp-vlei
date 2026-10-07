"""Proof of possession: a server shows it holds its legal entity's key before anything is presented.

A server's LE credential is public — anyone can copy ``/.well-known/vlei`` and publish it as their
own. Verifying the chain says whose credential it is, not who is answering. So a v0.3 client sends
a fresh challenge, and the server answers with a statement signed by its LE's key, or by a key its
LE delegated to (anchored in the LE's key event log)::

    POST <origin>/.well-known/vlei/pop   {"v": "vlei-pop/0.3", "nonce": N, "url": U}
    200                                  {"v", "aid", "nonce": N, "url": U, "ts", "exp", "sig"}

    signed bytes = JCS({"aid", "exp", "nonce", "ts", "url", "v"})

The nonce makes the answer fresh. ``url`` ties it to the endpoint the client is about to call, and
a server signs only for its own endpoints — so a relay at another URL cannot obtain an answer for
the URL its victim dialled. The format tag keeps a proof from ever passing as a request signature.

:class:`PopResponder` is the server's side; :func:`prove_server` the client's. Neither presents a
credential: the client learns who is answering before it shows anyone anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Sequence

import httpx
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audience import Recipient, is_qb64_identifier, normalise_endpoint
from .errors import (
    AudienceMismatch,
    ChainInvalid,
    InvalidSignature,
    StaleSignature,
    UnsupportedVersion,
)
from .signing import (
    _NONCE,
    DEFAULT_FRESHNESS_SECONDS,
    _parse_ts,
    _rfc3339,
    canonicalize,
    cesr_decode_signature,
    cesr_decode_verkey,
    new_nonce,
)

__all__ = [
    "POP_FORMAT",
    "POP_PATH",
    "PopProof",
    "PopResponder",
    "challenge",
    "pop_statement",
    "prove_server",
    "check_pop_response",
]

POP_FORMAT = "vlei-pop/0.3"
#: Where a server answers challenges, next to its ``/.well-known/vlei`` (RFC 8615).
POP_PATH = "/.well-known/vlei/pop"
#: How long a proof is valid for, as the responder states it; and the longest a client accepts.
DEFAULT_POP_LIFETIME_SECONDS = 60
MAX_POP_LIFETIME_SECONDS = 120
#: The most of a server's answer to a challenge a client reads. A proof is a few hundred bytes; an
#: answer beyond this is not one, and is not read into memory to find out.
MAX_POP_RESPONSE_BYTES = 64 * 1024


def pop_statement(*, aid: str, nonce: str, url: str, ts: str, exp: str) -> dict[str, str]:
    """The object a proof of possession signs."""
    return {"aid": aid, "exp": exp, "nonce": nonce, "ts": ts, "url": url, "v": POP_FORMAT}


def challenge(url: str, nonce: str | None = None) -> dict[str, str]:
    """What a client sends: a fresh nonce, and the endpoint it is about to call."""
    return {"v": POP_FORMAT, "nonce": nonce or new_nonce(), "url": normalise_endpoint(url)}


# ------------------------------------------------------------------------------------------- #
# The server's side
# ------------------------------------------------------------------------------------------- #

class PopResponder:
    """Answers challenges with this server's key — for its own endpoints only.

    ``signer`` is anything with ``.aid`` and ``.sign(bytes) -> str``: a ``CommandSigner`` over
    ``kli sign`` keeps the key in a KERI keystore. Its AID must be the LE's issuee or delegated by
    it; a client checks that in the AID's key event log, not here.
    """

    def __init__(
        self,
        signer: Any,
        recipient: Recipient,
        *,
        lifetime_seconds: int = DEFAULT_POP_LIFETIME_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not (0 < lifetime_seconds <= MAX_POP_LIFETIME_SECONDS):
            raise ValueError(
                f"lifetime_seconds must be between 1 and {MAX_POP_LIFETIME_SECONDS}, "
                f"not {lifetime_seconds}: a proof a client would refuse on arrival is not one worth issuing"
            )
        self.signer = signer
        self.recipient = recipient
        self.lifetime = timedelta(seconds=lifetime_seconds)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def respond(self, body: Any) -> tuple[int, dict[str, Any]]:
        """``(status, JSON body)`` for one challenge. Never raises for what a client sent."""
        if not isinstance(body, dict) or body.get("v") != POP_FORMAT:
            return 400, {"layer": None, "message": f"a challenge is {{\"v\": \"{POP_FORMAT}\", "
                                                   "\"nonce\", \"url\"}"}
        nonce, url = body.get("nonce"), body.get("url")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            return 400, {"layer": None, "message": "nonce: 22-64 characters of base64url"}
        try:
            url = normalise_endpoint(url)
        except ValueError as exc:
            return 400, {"layer": None, "message": f"url: {exc}"}
        if url not in self.recipient.urls:
            echoed = url if len(url) <= 200 else url[:200] + "…"
            return 403, {
                "layer": "audience_mismatch",
                # Neither this server's own URLs (loopback and tunnel addresses among them) nor an
                # unbounded echo of what was sent: the requester already knows what it asked for.
                "message": f"{echoed} is not an endpoint this server will prove itself for",
            }
        now = self._clock()
        try:
            # Inside the try: a signer may read its AID from the keystore, and one that cannot is
            # as unavailable as one that cannot sign.
            statement = pop_statement(aid=self.signer.aid, nonce=nonce, url=url,
                                      ts=_rfc3339(now), exp=_rfc3339(now + self.lifetime))
            sig = self.signer.sign(canonicalize(statement))
        except Exception as exc:  # noqa: BLE001 - a keystore that cannot sign is unavailability
            return 503, {"layer": None, "message": f"the server could not sign ({type(exc).__name__})"}
        return 200, {**statement, "sig": sig}


# ------------------------------------------------------------------------------------------- #
# The client's side
# ------------------------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PopProof:
    """What a verified proof of possession established."""

    responder_aid: str
    ts: str
    exp: str
    #: True when the responder is an AID the LE delegated to, not the LE's own.
    delegated: bool
    agreeing: int
    configured: int


def check_pop_response(
    body: Any, *, sent: dict[str, str], now: datetime,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> dict[str, str]:
    """Everything about an answer that needs no key: its shape, its challenge, its window."""
    if not isinstance(body, dict) or body.get("v") != POP_FORMAT:
        raise InvalidSignature(f"the server's answer is not a {POP_FORMAT} statement")
    fields = {k: body.get(k) for k in ("aid", "nonce", "url", "ts", "exp", "sig")}
    if not all(isinstance(v, str) and v for v in fields.values()):
        raise InvalidSignature("the server's proof is missing aid, nonce, url, ts, exp or sig")
    if not is_qb64_identifier(fields["aid"]):
        raise InvalidSignature("the server's proof names no CESR identifier")
    if fields["nonce"] != sent["nonce"] or fields["url"] != sent["url"]:
        raise AudienceMismatch(
            f"the server's proof answers another challenge (nonce or URL {fields['url']}), not the "
            f"one sent for {sent['url']}: a relay, or an old proof replayed",
            aid=fields["aid"],
        )
    ts = _parse_ts(fields["ts"], what="the server's proof's ts", aid=fields["aid"])
    exp = _parse_ts(fields["exp"], what="the server's proof's exp", aid=fields["aid"])
    skew = timedelta(seconds=freshness_seconds)
    if exp <= ts or exp - ts > timedelta(seconds=MAX_POP_LIFETIME_SECONDS):
        raise StaleSignature("the server's proof states an impossible validity", aid=fields["aid"])
    if ts > now + skew or now > exp + skew:
        raise StaleSignature("the server's proof is not fresh: check both clocks", aid=fields["aid"])
    return fields


def _verifies(keys: Sequence[str], sig: str, payload: bytes) -> bool:
    try:
        raw = cesr_decode_signature(sig)
    except (ValueError, TypeError, InvalidSignature):
        return False
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(key)).verify(raw, payload)
            return True
        except (_CryptoInvalidSignature, InvalidSignature):
            continue
    return False


async def _read_bounded(response: httpx.Response, limit: int) -> bytes | None:
    """The body, or ``None`` once it is known to exceed ``limit`` — from a declared length before
    anything is read, or while streaming one that declares none. Decoded bytes are counted, so a
    compressed answer cannot expand past the limit either."""
    declared = response.headers.get("content-length", "").strip()
    if declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def prove_server(
    *,
    http: httpx.AsyncClient,
    pop_url: str,
    endpoint_url: str,
    holder: str,
    key_states: Any,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    now: datetime | None = None,
) -> PopProof:
    """Challenge the server at ``pop_url`` and verify its answer, or raise the layer that failed.

    ``holder`` is the issuee of the LE credential the client has already verified for this server;
    ``key_states`` a resolver of key states from witnesses (``WitnessKeyStates``) — the responder's
    key is read from its own log, never from the answer.
    """
    sent = challenge(endpoint_url)
    try:
        async with http.stream("POST", pop_url, json=sent) as response:
            status = response.status_code
            # A 404 is read for its status alone: its body, whatever its size, says nothing.
            raw = b"" if status == 404 else await _read_bounded(response, MAX_POP_RESPONSE_BYTES)
    except httpx.HTTPError as exc:
        raise InvalidSignature(
            f"the server's proof of possession could not be obtained from {pop_url} "
            f"({type(exc).__name__}); that it holds its key was not established"
        ) from exc
    if status == 404:
        raise UnsupportedVersion(
            f"{pop_url} answered 404: the server offers no proof of possession "
            f"({POP_FORMAT}) — a v0.2 server, or not one this client can verify"
        )
    if raw is None:
        raise InvalidSignature(
            f"{pop_url} answered with a response too large (over {MAX_POP_RESPONSE_BYTES} bytes); "
            "a proof is a few hundred, and that the server holds its key was not established"
        )
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: JSON nested deeper than Python parses
        body = None
    if status == 403 and isinstance(body, dict) and body.get("layer") == "audience_mismatch":
        raise AudienceMismatch(f"the server will not prove itself for {sent['url']}: {body.get('message')}")
    if status != 200:
        raise InvalidSignature(
            f"{pop_url} answered HTTP {status}; that the server holds its key was not established"
        )
    fields = check_pop_response(body, sent=sent, now=now or datetime.now(timezone.utc),
                                freshness_seconds=freshness_seconds)
    responder = fields["aid"]
    try:
        state = await key_states.resolve(responder)
    except ChainInvalid as exc:
        raise InvalidSignature(
            f"the key state of {responder}, which signed the server's proof, was not established: "
            f"{exc.message}",
            aid=responder,
        ) from exc
    if state.threshold != 1:
        raise InvalidSignature(f"{responder} requires {state.threshold} signatures; a proof carries one",
                               aid=responder)
    payload = canonicalize(pop_statement(aid=responder, nonce=fields["nonce"], url=fields["url"],
                                         ts=fields["ts"], exp=fields["exp"]))
    if not _verifies(state.keys, fields["sig"], payload):
        raise InvalidSignature(
            f"the server's proof does not verify under the current key state of {responder}",
            aid=responder,
        )
    if responder != holder and state.delegator != holder:
        raise InvalidSignature(
            f"the server's proof is signed by {responder}, which is neither the server's LE "
            f"({holder}) nor delegated by it in the LE's key event log",
            aid=responder,
        )
    return PopProof(responder_aid=responder, ts=fields["ts"], exp=fields["exp"],
                    delegated=responder != holder, agreeing=state.agreeing,
                    configured=state.configured)
