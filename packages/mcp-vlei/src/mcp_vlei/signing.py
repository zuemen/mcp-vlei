"""Canonicalization, digests, signing and verification for the vLEI MCP extension.

The signed payload is deliberately small and fixed::

    method + "\\n" + ts + "\\n" + digest

with ``digest = base64url(sha256(JCS(params without _meta)))``.

``_meta`` is excluded because it carries the signature; excluding the whole member rather than one
key keeps the rule auditable by eye.

This is a **single-pass** design. There is no nonce and no challenge round trip, because a stateless
gateway must be able to decide from one message — that is the deployment shape that lets an
institution adopt the extension without modifying its existing systems. Replay is bounded instead by
a freshness window plus a :class:`ReplayCache`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Sequence

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import DigestMismatch, InvalidSignature, StaleSignature

__all__ = [
    "canonicalize",
    "digest_params",
    "sign_request",
    "verify_request",
    "precheck_request",
    "ReplayCache",
    "Signer",
    "CommandSigner",
    "DEFAULT_FRESHNESS_SECONDS",
    "cesr_encode_signature",
    "cesr_decode_signature",
    "cesr_decode_verkey",
]

#: Default freshness window. Short enough to bound replay, long enough to survive ordinary clock
#: skew between two organizations that have never synchronized anything with each other.
DEFAULT_FRESHNESS_SECONDS = 60


# -------------------------------------------------------------------------------------------- #
# RFC 8785 (JCS) canonicalization
# -------------------------------------------------------------------------------------------- #

def _jcs_number(value: float | int) -> str:
    """Serialize a number per RFC 8785, which defers to ECMAScript ``Number::toString``."""
    if isinstance(value, bool):  # bool is a subclass of int; JCS treats it as a literal
        raise TypeError("bool is not a JSON number")
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not representable in JSON")
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    out = repr(value)
    return out.replace("e+", "e").replace("E", "e")


def _jcs_string(value: str) -> str:
    # json.dumps with ensure_ascii=False already produces the minimal escaping RFC 8785 requires
    # (control characters, quote, backslash) and leaves everything else as literal UTF-8.
    return json.dumps(value, ensure_ascii=False)


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 sorts by UTF-16 code units. Python compares str by code point, which differs
        # only for astral-plane keys; encode to UTF-16BE to get the specified ordering exactly.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_jcs_string(k)}:{_jcs(v)}" for k, v in items) + "}"
    raise TypeError(f"not JSON-serializable: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """RFC 8785 canonical serialization, as UTF-8 bytes."""
    return _jcs(value).encode("utf-8")


def digest_params(params: dict[str, Any] | None) -> str:
    """``base64url(sha256(JCS(params without _meta)))``, unpadded.

    ``params`` of ``None`` and ``{}`` produce the same digest, because on the wire they mean the
    same thing and a signature must not depend on which one a client library chose.
    """
    payload = {k: v for k, v in (params or {}).items() if k != "_meta"}
    h = hashlib.sha256(canonicalize(payload)).digest()
    return base64.urlsafe_b64encode(h).decode("ascii").rstrip("=")


def signed_payload(method: str, ts: str, digest: str) -> bytes:
    return f"{method}\n{ts}\n{digest}".encode("utf-8")


# -------------------------------------------------------------------------------------------- #
# Minimal CESR encoding for Ed25519 material
# -------------------------------------------------------------------------------------------- #
#
# Full CESR lives in keripy; this is the narrow subset the extension puts on the wire, so that the
# package is usable without keripy installed. When keripy is present, its primitives interoperate
# with these encodings byte for byte.

_SIG_CODE = "0B"   # Ed25519 signature, 64 raw bytes -> 88 characters
_VERKEY_CODES = ("D", "B")  # Ed25519 verification key, 32 raw bytes -> 44 characters

#: Indexed Ed25519 signature codes. `kli sign` and anything signing on behalf of a multi-key
#: identifier emit these: the same 64 raw bytes, with a two-character code carrying the key index
#: instead of `0B`. Accepting them is what lets a signer that keeps its key in a keystore — the
#: shape Signify uses — interoperate with one that holds a raw seed.
_INDEXED_SIG_CODES = ("A", "B", "2A", "2B", "3A", "3B")


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def cesr_encode_signature(raw: bytes) -> str:
    if len(raw) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(raw)}")
    # 64 % 3 == 1, so two lead pad bytes align the raw material to a base64 boundary; the code
    # then replaces the two characters those pad bytes produced.
    return _SIG_CODE + _b64u(b"\x00\x00" + raw)[2:]


def cesr_decode_signature(qb64: str) -> bytes:
    """Decode either a non-indexed (`0B`) or an indexed (`A…`) Ed25519 signature.

    Both carry the same 64 raw bytes; only the two-character code differs, so the raw material is
    recovered the same way. Accepting both means a keystore-backed signer and a raw-seed signer
    produce signatures this package can verify interchangeably.
    """
    if len(qb64) != 88:
        raise InvalidSignature(f"not a CESR Ed25519 signature: {qb64[:8]}... (len {len(qb64)})")
    if not (qb64.startswith(_SIG_CODE) or qb64[0] in ("A", "B", "2", "3")):
        raise InvalidSignature(f"unrecognized signature code: {qb64[:2]!r}")
    return base64.urlsafe_b64decode("AA" + qb64[2:])[2:]


def cesr_decode_verkey(qb64: str) -> bytes:
    if not qb64 or qb64[0] not in _VERKEY_CODES or len(qb64) != 44:
        raise InvalidSignature(f"not a CESR Ed25519 verification key: {qb64[:8]}...")
    return base64.urlsafe_b64decode("A" + qb64[1:])[1:]


# -------------------------------------------------------------------------------------------- #
# Signer
# -------------------------------------------------------------------------------------------- #

@dataclass
class Signer:
    """Holds one signing key and the AID it speaks for.

    In production the private key should not be here at all: Signify keeps it on the holder's
    device and returns signatures. :meth:`from_key_store` exists so the reference agent is
    runnable and inspectable, and the README says as much.
    """

    aid: str
    _private: Ed25519PrivateKey

    @classmethod
    def from_seed(cls, aid: str, seed: bytes) -> "Signer":
        return cls(aid=aid, _private=Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_key_store(cls, key_store: str, aid: str) -> "Signer":
        """Load ``<key_store>/<aid>.key`` — 32 raw bytes of Ed25519 seed."""
        from pathlib import Path

        path = Path(key_store) / f"{aid}.key"
        seed = path.read_bytes()
        if len(seed) != 32:
            raise ValueError(f"{path} must contain 32 raw seed bytes, got {len(seed)}")
        return cls.from_seed(aid, seed)

    @property
    def verkey(self) -> str:
        raw = self._private.public_key().public_bytes_raw()
        return "D" + _b64u(b"\x00" + raw)[1:]

    def sign(self, payload: bytes) -> str:
        return cesr_encode_signature(self._private.sign(payload))


# -------------------------------------------------------------------------------------------- #
# Replay cache
# -------------------------------------------------------------------------------------------- #

class CommandSigner:
    """Signs by asking something else to sign, so the private key is never in this process.

    This is the shape Signify has: the holder's device keeps the key, and the agent sends a payload
    and receives a signature. Here the "device" is a local keystore reached through a command —
    ``kli sign`` in the reference deployment — which is enough to demonstrate that the agent works
    without ever possessing the key.

    ``command`` receives the text to sign and must return the CESR signature.
    """

    def __init__(self, aid: str, verkey: str, command: "Callable[[str], str]") -> None:
        self.aid = aid
        self._verkey = verkey
        self._command = command

    @property
    def verkey(self) -> str:
        return self._verkey

    def sign(self, payload: bytes) -> str:
        signature = self._command(payload.decode("utf-8")).strip()
        # `kli sign` numbers its output lines ("1. AAC9…"); take the signature off the last one.
        signature = signature.splitlines()[-1].split(". ")[-1].strip()
        if len(signature) != 88:
            raise ValueError(f"signer returned {signature[:12]!r}, which is not a CESR signature")
        return signature


@dataclass
class ReplayCache:
    """Remembers ``(aid, digest, ts)`` for at least the freshness window.

    The freshness window alone does not stop replay — it only bounds it to a minute. This is the
    other half, and a verifier that omits it has a one-minute replay window rather than none.
    """

    window_seconds: int = DEFAULT_FRESHNESS_SECONDS
    _seen: dict[tuple[str, str, str], float] = field(default_factory=dict)

    def check_and_record(self, aid: str, digest: str, ts: str) -> None:
        now = time.monotonic()
        self._evict(now)
        key = (aid, digest, ts)
        if key in self._seen:
            raise StaleSignature(
                "request already seen (replay)", aid=aid
            )
        self._seen[key] = now

    def _evict(self, now: float) -> None:
        cutoff = now - (self.window_seconds * 2)
        for key in [k for k, t in self._seen.items() if t < cutoff]:
            del self._seen[key]


# -------------------------------------------------------------------------------------------- #
# Sign / verify a request
# -------------------------------------------------------------------------------------------- #

def _now_rfc3339() -> str:
    # Milliseconds: the replay key is (aid, digest, ts), and at whole seconds a client that
    # legitimately repeated a call within the same second had the second one refused as a replay.
    # RFC 3339 allows the fraction, and every verifier here parses it.
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sign_request(
    signer: Signer,
    method: str,
    params: dict[str, Any] | None,
    *,
    ts: str | None = None,
) -> dict[str, Any]:
    """Produce the ``VleiSignature`` object for ``params._meta``.

    ``params`` must not change between this call and the call being sent: any change produces
    ``digest_mismatch`` at the counterparty, which is the intended behavior.
    """
    ts = ts or _now_rfc3339()
    digest = digest_params(params)
    return {
        "aid": signer.aid,
        "ts": ts,
        "digest": digest,
        "sig": signer.sign(signed_payload(method, ts, digest)),
        "alg": "Ed25519",
    }


def _parse_ts(ts: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError) as exc:
        raise StaleSignature(f"timestamp is not RFC 3339: {ts!r}") from exc
    if parsed.tzinfo is None:
        # RFC 3339 requires an offset. Without one, "how old is this" has no answer — and comparing
        # it would raise instead of naming a layer.
        raise StaleSignature(f"timestamp carries no time zone: {ts!r}")
    return parsed


def _fields(signature: Any) -> tuple[str, str, str, str]:
    if not isinstance(signature, dict):
        raise InvalidSignature("the signature is not an object")
    aid, ts = signature.get("aid", ""), signature.get("ts", "")
    claimed_digest, sig = signature.get("digest", ""), signature.get("sig", "")
    if not all(isinstance(v, str) and v for v in (aid, ts, claimed_digest, sig)):
        raise InvalidSignature(
            "signature object is missing aid, ts, digest or sig",
            aid=aid if isinstance(aid, str) and aid else None,
        )
    alg = signature.get("alg", "Ed25519")
    if alg != "Ed25519":
        raise InvalidSignature(f"unsupported signature algorithm {alg!r}", aid=aid)
    return aid, ts, claimed_digest, sig


def _check_fresh_and_digest(
    aid: str, ts: str, claimed_digest: str, params: dict[str, Any] | None,
    freshness_seconds: int, now: datetime | None,
) -> None:
    now = now or datetime.now(timezone.utc)
    skew = abs(now - _parse_ts(ts))
    if skew > timedelta(seconds=freshness_seconds):
        raise StaleSignature(
            f"signature timestamp is {int(skew.total_seconds())}s from now, "
            f"outside the {freshness_seconds}s freshness window",
            aid=aid,
        )
    if digest_params(params) != claimed_digest:
        raise DigestMismatch(
            "request arguments do not match the signed digest; "
            "they were altered after signing",
            aid=aid,
        )


def precheck_request(
    signature: Any,
    params: dict[str, Any] | None,
    *,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    now: datetime | None = None,
) -> None:
    """The checks that need nothing but the request: shape, freshness and digest.

    A verifier runs these before it fetches the signer's key state, so a stale or altered call is
    refused without a round trip to a witness. :func:`verify_request` repeats them; they are cheap.
    """
    aid, ts, claimed_digest, _ = _fields(signature)
    _check_fresh_and_digest(aid, ts, claimed_digest, params, freshness_seconds, now)


def verify_request(
    signature: Any,
    method: str,
    params: dict[str, Any] | None,
    verkey: str | Sequence[str],
    *,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    replay_cache: ReplayCache | None = None,
    now: datetime | None = None,
) -> None:
    """Verify a request signature, raising the exception for the layer that failed.

    ``verkey`` is the signer's **current key state** — one key or the list a key event log
    establishes. It must never come from the request being verified: whoever sends a call would
    then choose the key it is checked against. :class:`mcp_vlei.kel.WitnessKeyStates` is where a
    relying party gets it.

    Checked in this order, because each check makes the next one meaningful:

    1. freshness  -> ``stale_signature``
    2. digest     -> ``digest_mismatch``
    3. signature  -> ``invalid_signature``
    4. replay     -> ``stale_signature``

    The digest is compared before the signature so that an altered-argument attack is reported as
    ``digest_mismatch`` rather than as a generic signature failure. The two are operationally
    different: one is tampering in transit, the other is a key-state problem.

    Replay is recorded **last**, once the signature has verified. Recording it earlier would let
    anyone who can guess the (AID, digest, timestamp) of a call about to be made burn it first with
    a signature that does not verify — and let unauthenticated traffic grow the cache.
    """
    aid, ts, claimed_digest, sig = _fields(signature)
    _check_fresh_and_digest(aid, ts, claimed_digest, params, freshness_seconds, now)

    keys = [verkey] if isinstance(verkey, str) else list(verkey)
    try:
        raw_signature = cesr_decode_signature(sig)
    except (ValueError, TypeError) as exc:  # binascii.Error is a ValueError
        raise InvalidSignature(f"signature is not valid CESR: {exc}", aid=aid) from exc
    payload = signed_payload(method, ts, claimed_digest)
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(key)).verify(raw_signature, payload)
            break
        except _CryptoInvalidSignature:
            continue
    else:
        raise InvalidSignature(
            "signature does not verify under the signer's current key state", aid=aid
        )

    if replay_cache is not None:
        replay_cache.check_and_record(aid, claimed_digest, ts)


def scope_satisfied(required: dict[str, Any] | None, held: dict[str, Any] | None) -> tuple[bool, str]:
    """Compare a tool's declared scope against the scope carried by the caller's credential.

    The specification fixes *where* scope lives and *that* it must be checked; it does not impose a
    universal scope algebra, because what "within scope" means is a deployment's policy. This is the
    default comparison the package ships with:

    * a numeric requirement is satisfied when the held value is >= the required value
    * a list requirement is satisfied when the held list is a superset
    * anything else is satisfied by equality
    * a key the holder does not carry at all is not satisfied

    Returns ``(ok, reason)``; ``reason`` is empty when ``ok``.
    """
    if not required:
        return True, ""
    held = held or {}
    for key, want in required.items():
        if key not in held:
            return False, f"credential carries no {key!r}"
        have = held[key]
        if isinstance(want, (int, float)) and not isinstance(want, bool):
            if isinstance(have, bool) or not isinstance(have, (int, float)) or have < want:
                return False, f"{key}: requires at least {want}, credential carries {have!r}"
        elif isinstance(want, (list, tuple, set)):
            # Only a list covers a list. A string is iterable, and reading "TW" as {"T", "W"} once
            # let a held string satisfy any requirement made of its letters.
            if not isinstance(have, (list, tuple, set)):
                return False, f"{key}: requires a list, credential carries {have!r}"
            try:
                missing = set(want) - set(have)
            except TypeError:
                return False, f"{key}: cannot compare {have!r} with {want!r}"
            if missing:
                return False, f"{key}: credential does not cover {sorted(map(str, missing))}"
        elif have != want:
            return False, f"{key}: requires {want!r}, credential carries {have!r}"
    return True, ""
