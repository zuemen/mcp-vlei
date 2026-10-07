"""Canonicalization, digests, signing and verification for the vLEI MCP extension (vlei-sig/0.3).

A v0.3 signature covers a small **statement**, canonicalized with RFC 8785::

    {"aid", "aud": {"aid", "url"}, "cred", "digest", "exp", "method", "nonce", "ts", "v"}

``v`` is ``vlei-sig/0.3``; ``aud`` the recipient (its LE AID and the endpoint URL); ``cred`` the
presented credential's SAID; ``digest = base64url(sha256(JCS(params without _meta)))`` — the tool
and every argument; ``ts``/``exp`` the window the signer allows; ``nonce`` 128 random bits that a
verifier claims once (:mod:`mcp_vlei.replay`).

``_meta`` is excluded from the digest because it carries the signature; excluding the whole member
rather than one key keeps the rule auditable by eye.

This is still a **single-pass** design: a stateless gateway decides from one message. The nonce is
the client's, so no challenge round trip is needed; the verifier only has to remember which nonces
it has seen until they expire.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
from dataclasses import dataclass
from decimal import Decimal
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Sequence

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .audience import Audience, Recipient, is_qb64_identifier
from .errors import (
    DigestMismatch,
    InvalidSignature,
    MissingCredential,
    StaleSignature,
    UnsupportedVersion,
)
from .replay import ReplayStore

__all__ = [
    "canonicalize",
    "loads_strict",
    "reject_duplicate_members",
    "MAX_SAFE_INTEGER",
    "digest_params",
    "sign_request",
    "verify_request",
    "precheck_request",
    "unsupported_version",
    "parse_signature",
    "ParsedSignature",
    "statement",
    "statement_bytes",
    "new_nonce",
    "Signer",
    "CommandSigner",
    "SIGNATURE_FORMAT",
    "DEFAULT_FRESHNESS_SECONDS",
    "DEFAULT_LIFETIME_SECONDS",
    "DEFAULT_MAX_LIFETIME_SECONDS",
    "cesr_encode_signature",
    "cesr_decode_signature",
    "cesr_decode_verkey",
]

#: The signature format this package signs and verifies. A verifier refuses any other
#: (``unsupported_version``); a v0.2 signature carries no ``v`` at all.
SIGNATURE_FORMAT = "vlei-sig/0.3"

#: How far apart a signer's and a verifier's clocks may be. Long enough to survive ordinary clock
#: skew between two organizations that have never synchronized anything with each other.
DEFAULT_FRESHNESS_SECONDS = 60

#: How long a client's signature is valid for (``exp - ts``), unless it says otherwise.
DEFAULT_LIFETIME_SECONDS = 30

#: The longest ``exp - ts`` a verifier accepts: a signer cannot ask for a signature good for a day.
DEFAULT_MAX_LIFETIME_SECONDS = 60

_NONCE = re.compile(r"[A-Za-z0-9_-]{22,64}")


# -------------------------------------------------------------------------------------------- #
# RFC 8785 (JCS) canonicalization
# -------------------------------------------------------------------------------------------- #

#: The largest integer I-JSON (RFC 7493) carries exactly: beyond it, a JSON number has no portable
#: value, and RFC 8785 serializes numbers as IEEE-754 doubles.
MAX_SAFE_INTEGER = 2**53 - 1


def _jcs_number(value: float | int) -> str:
    """Serialize a number per RFC 8785, which defers to ECMAScript ``Number::toString``.

    ``1e21`` is ``1e+21`` and ``1e-7`` is ``1e-7`` — not Python's ``1e21`` / ``1e-07``. An integer
    beyond ±(2**53 - 1) is refused rather than rounded: rounding would give two different integers
    one digest, and a JavaScript signer would have signed the rounded one.
    """
    if isinstance(value, bool):  # bool is a subclass of int; JCS treats it as a literal
        raise TypeError("bool is not a JSON number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(
                f"integer {value} is outside the I-JSON range (|n| <= 2**53 - 1) and has no "
                "portable canonical form"
            )
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not representable in JSON")
    if value == 0:
        return "0"  # -0 included
    if value < 0:
        return "-" + _jcs_number(-value)
    # repr() gives the shortest digits that round-trip, which is what ECMAScript requires; only the
    # layout differs. digits * 10**(n - k) == value, k digits, as in ECMA-262 Number::toString.
    _, raw, exponent = Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, raw)).rstrip("0")
    exponent += len(raw) - len(digits)
    k = len(digits)
    n = exponent + k
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


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


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A ``json`` ``object_pairs_hook`` that refuses a repeated member name (ValueError)."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate member name {key!r}: the object has no single reading")
        seen[key] = value
    return seen


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def loads_strict(text: str | bytes) -> Any:
    """Parse JSON as I-JSON (RFC 7493): a repeated member name or NaN/Infinity is a ValueError.

    Python keeps the last of two equal keys and other parsers keep the first, so a duplicate is how
    a verifier and a backend come to read different arguments under one valid digest.
    """
    return json.loads(text, object_pairs_hook=reject_duplicate_members, parse_constant=_no_constant)


def digest_params(params: dict[str, Any] | None) -> str:
    """``base64url(sha256(JCS(params without _meta)))``, unpadded.

    ``params`` of ``None`` and ``{}`` produce the same digest, because on the wire they mean the
    same thing and a signature must not depend on which one a client library chose.
    """
    payload = {k: v for k, v in (params or {}).items() if k != "_meta"}
    h = hashlib.sha256(canonicalize(payload)).digest()
    return base64.urlsafe_b64encode(h).decode("ascii").rstrip("=")


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
# Command signer
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


# -------------------------------------------------------------------------------------------- #
# Sign / verify a request (vlei-sig/0.3)
# -------------------------------------------------------------------------------------------- #

def _now_rfc3339() -> str:
    return _rfc3339(datetime.now(timezone.utc))


def _rfc3339(moment: datetime) -> str:
    """UTC, milliseconds, ``Z``: the form every signature here carries."""
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_nonce() -> str:
    """128 random bits, base64url, unpadded: 22 characters."""
    return secrets.token_urlsafe(16)


def statement(
    *,
    aid: str,
    aud: dict[str, str],
    cred: str,
    digest: str,
    ts: str,
    exp: str,
    nonce: str,
    method: str = "tools/call",
) -> dict[str, Any]:
    """The object a v0.3 request signature covers.

    On the signing side every field is ASCII by construction: CESR identifiers, a normalised URL,
    base64url and RFC 3339 timestamps (:func:`sign_request`). A verifier rebuilds it from the fields
    a request carried, which are shape-checked (:func:`parse_signature`) but not all held to ASCII
    — ``aud.url`` is compared only once normalised. JCS writes whatever it is given as UTF-8, so a
    field that is not ASCII yields bytes no conforming signer signed: it does not verify.
    """
    return {
        "aid": aid,
        "aud": {"aid": aud["aid"], "url": aud["url"]},
        "cred": cred,
        "digest": digest,
        "exp": exp,
        "method": method,
        "nonce": nonce,
        "ts": ts,
        "v": SIGNATURE_FORMAT,
    }


def statement_bytes(**fields: Any) -> bytes:
    """``JCS(statement(**fields))`` — the exact bytes a v0.3 signature is over."""
    return canonicalize(statement(**fields))


def sign_request(
    signer: Signer,
    method: str,
    params: dict[str, Any] | None,
    *,
    audience: Audience,
    credential_said: str,
    ts: str | None = None,
    exp: str | None = None,
    lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Produce the ``VleiSignature`` object (``vlei-sig/0.3``) for ``params._meta``.

    ``audience`` is the recipient — the AID of the LE the client verified for that server and the
    URL the call is sent to. ``credential_said`` is the credential presented with the call, which
    the signature speaks for. ``params`` must not change between this call and the call being
    sent: any change is ``digest_mismatch`` at the counterparty, as intended.
    """
    if not credential_said:
        raise ValueError("credential_said is required: a v0.3 signature speaks for one credential")
    if not is_qb64_identifier(credential_said):
        # Every verifier refuses it (invalid_signature); fail here, before a signer is asked.
        raise ValueError(
            f"credential_said {credential_said!r:.60} is not a 44-character CESR identifier"
        )
    ts = ts or _now_rfc3339()
    if exp is None:
        try:
            start = _parse_ts(ts, what="ts")
        except InvalidSignature as exc:  # the caller's own value: a programming error, not a layer
            raise ValueError(exc.message) from exc
        exp = _rfc3339(start + timedelta(seconds=lifetime_seconds))
    body: dict[str, Any] = {
        "v": SIGNATURE_FORMAT,
        "aid": signer.aid,
        "aud": audience.to_wire(),
        "ts": ts,
        "exp": exp,
        "nonce": nonce or new_nonce(),
        "digest": digest_params(params),
    }
    body["sig"] = signer.sign(
        statement_bytes(aid=body["aid"], aud=body["aud"], cred=credential_said,
                        digest=body["digest"], ts=ts, exp=exp, nonce=body["nonce"], method=method)
    )
    body["alg"] = "Ed25519"
    return body


def _parse_ts(ts: str, *, what: str = "timestamp", aid: str | None = None) -> datetime:
    """An RFC 3339 timestamp with an offset, or ``invalid_signature`` naming ``what`` and ``aid``.

    A timestamp that is not one is a malformed signature object — the spec's ``invalid_signature``
    — not a stale one: no clock makes it fresh, and ``stale_signature`` would tell a caller that
    re-signing the same way could succeed.
    """
    shown = repr(ts) if len(repr(ts)) <= 64 else repr(ts)[:64] + "…"
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidSignature(f"{what} is not RFC 3339: {shown}", aid=aid) from exc
    if parsed.tzinfo is None:
        # RFC 3339 requires an offset. Without one, "how old is this" has no answer — and comparing
        # it would raise instead of naming a layer.
        raise InvalidSignature(f"{what} carries no time zone: {shown}", aid=aid)
    return parsed


def _seconds_beyond(span: timedelta) -> str:
    """``span`` in seconds, to one decimal, rounded **up**: the amount by which a signature broke a
    bound must never print as the bound itself — 60.001 s past a 60 s tolerance reads ``60.1s``,
    where ``int()`` read ``60s``, as if within it."""
    tenths = -(-span // timedelta(milliseconds=100))
    return f"{tenths / 10:.1f}s"


@dataclass(frozen=True)
class ParsedSignature:
    """A v0.3 signature object whose every field has the shape the statement needs."""

    aid: str
    aud: dict[str, str]
    ts: str
    exp: str
    nonce: str
    digest: str
    sig: str


def unsupported_version(signature: Any) -> UnsupportedVersion | None:
    """The refusal for a signature made in another format, or ``None``.

    Another format is a ``v`` other than ``vlei-sig/0.3``, or no ``v`` on an object shaped like a
    vlei-sig/0.2 signature (``aid``, ``ts``, ``digest``, ``sig``) — which binds no recipient, nonce
    or expiry, and is refused by name rather than as a signature that "does not verify". Anything
    else (not an object, junk) is not a signature of any format: ``None`` here, and
    ``invalid_signature`` from :func:`parse_signature`.
    """
    if not isinstance(signature, dict):
        return None
    signer = signature.get("aid")
    signer = signer if is_qb64_identifier(signer) else None
    version = signature.get("v")
    if version == SIGNATURE_FORMAT:
        return None
    if version is None:
        if not all(isinstance(signature.get(k), str) and signature.get(k)
                   for k in ("aid", "ts", "digest", "sig")):
            return None
        return UnsupportedVersion(
            "the signature names no format — a vlei-sig/0.2 signature (method, time and digest; "
            f"no recipient, nonce or expiry). This verifier requires {SIGNATURE_FORMAT}: upgrade "
            "the client",
            aid=signer,
        )
    return UnsupportedVersion(
        f"signature format {version!r} is not supported; this verifier requires {SIGNATURE_FORMAT}",
        aid=signer,
    )


def parse_signature(signature: Any) -> ParsedSignature:
    """Shape-check a v0.3 signature object: ``unsupported_version``, then ``invalid_signature``."""
    if not isinstance(signature, dict):
        raise InvalidSignature("the signature is not an object")
    foreign = unsupported_version(signature)
    if foreign is not None:
        raise foreign
    aid = signature.get("aid")
    signer = aid if is_qb64_identifier(aid) else None
    if signature.get("v") != SIGNATURE_FORMAT:
        raise InvalidSignature("the signature object names no format and is not a signature",
                               aid=signer)
    missing = [k for k in ("aid", "aud", "ts", "exp", "nonce", "digest", "sig") if not signature.get(k)]
    if missing:
        raise InvalidSignature(f"signature object is missing {', '.join(missing)}", aid=signer)
    if signer is None:
        raise InvalidSignature("signature.aid is not a 44-character CESR identifier")
    aud = signature["aud"]
    if not (isinstance(aud, dict) and set(aud) == {"aid", "url"}
            and all(isinstance(aud[k], str) for k in aud)):
        raise InvalidSignature("signature.aud must be an object with exactly aid and url", aid=aid)
    if not is_qb64_identifier(aud["aid"]):
        # Names no recipient at all — not "another" one: a malformed object, not audience_mismatch.
        raise InvalidSignature("signature.aud.aid is not a 44-character CESR identifier", aid=aid)
    texts = {k: signature[k] for k in ("ts", "exp", "nonce", "digest", "sig")}
    if not all(isinstance(v, str) for v in texts.values()):
        raise InvalidSignature("signature fields ts, exp, nonce, digest and sig are strings", aid=aid)
    if not _NONCE.fullmatch(texts["nonce"]):
        raise InvalidSignature("signature.nonce is not 22-64 characters of base64url", aid=aid)
    if signature.get("alg", "Ed25519") != "Ed25519":
        raise InvalidSignature(f"unsupported signature algorithm {signature.get('alg')!r}", aid=aid)
    for name in ("ts", "exp"):
        _parse_ts(texts[name], what=f"signature.{name}", aid=aid)
    return ParsedSignature(aid=aid, aud=dict(aud), **texts)


def _check_time(
    sig: ParsedSignature, *, freshness_seconds: int, max_lifetime_seconds: int,
    memory_since: datetime | None, now: datetime,
) -> None:
    ts = _parse_ts(sig.ts, what="signature.ts", aid=sig.aid)
    exp = _parse_ts(sig.exp, what="signature.exp", aid=sig.aid)
    skew = timedelta(seconds=freshness_seconds)
    if exp <= ts:
        raise StaleSignature("the signature expires before it was made", aid=sig.aid)
    if exp - ts > timedelta(seconds=max_lifetime_seconds):
        raise StaleSignature(
            f"the signature asks to be valid for {_seconds_beyond(exp - ts)}; this "
            f"verifier accepts at most {max_lifetime_seconds}s",
            aid=sig.aid,
        )
    if ts > now + skew:
        raise StaleSignature(
            f"the signature is dated {_seconds_beyond(ts - now)} ahead of this verifier's "
            f"clock, beyond the {freshness_seconds}s tolerance",
            aid=sig.aid,
        )
    if now > exp + skew:
        raise StaleSignature(
            f"the signature expired {_seconds_beyond(now - exp)} ago "
            f"(tolerance {freshness_seconds}s)",
            aid=sig.aid,
        )
    if memory_since is not None and ts < memory_since + skew:
        raise StaleSignature(
            "the signature was made before this verifier's replay memory began (it restarted); "
            "re-sign and send again",
            aid=sig.aid,
        )


def _check_digest(sig: ParsedSignature, params: dict[str, Any] | None) -> None:
    try:
        digest = digest_params(params)
    except (ValueError, TypeError) as exc:
        # NaN, Infinity, a lone surrogate or an integer beyond I-JSON have no canonical form, and
        # an in-process caller can pass values JSON has no type for at all; no signature can cover
        # them. Refused here with a layer, rather than escaping as a crash.
        raise DigestMismatch(
            f"request arguments contain a value no signature can cover ({exc})", aid=sig.aid
        ) from exc
    if digest != sig.digest:
        raise DigestMismatch(
            "request arguments do not match the signed digest; they were altered after signing",
            aid=sig.aid,
        )


def precheck_request(
    signature: Any,
    params: dict[str, Any] | None,
    *,
    recipient: Recipient,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    max_lifetime_seconds: int = DEFAULT_MAX_LIFETIME_SECONDS,
    memory_since: datetime | None = None,
    now: datetime | None = None,
) -> ParsedSignature:
    """Everything decidable from the request and the verifier's own configuration, in order:

    format and shape -> time -> recipient -> digest. A verifier runs these before it fetches the
    signer's key state, so a replay to the wrong server or an altered call costs no witness round
    trip. :func:`verify_request` repeats them; they are cheap.
    """
    sig = parse_signature(signature)
    _check_time(sig, freshness_seconds=freshness_seconds, max_lifetime_seconds=max_lifetime_seconds,
                memory_since=memory_since, now=now or datetime.now(timezone.utc))
    recipient.check(sig.aud, signer=sig.aid)
    _check_digest(sig, params)
    return sig


def verify_request(
    signature: Any,
    method: str,
    params: dict[str, Any] | None,
    verkey: str | Sequence[str],
    *,
    recipient: Recipient,
    credential_said: str | None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    max_lifetime_seconds: int = DEFAULT_MAX_LIFETIME_SECONDS,
    replay_store: ReplayStore | None = None,
    now: datetime | None = None,
) -> ParsedSignature:
    """Verify a v0.3 request signature, raising the exception for the layer that failed.

    ``verkey`` is the signer's **current key state** — one key or the list a key event log
    establishes. It must never come from the request being verified: whoever sends a call would
    then choose the key it is checked against (:class:`mcp_vlei.kel.WitnessKeyStates`).

    In order: format (``unsupported_version``), shape (``invalid_signature``), time
    (``stale_signature``), recipient (``audience_mismatch``), digest (``digest_mismatch``), the
    signature over the rebuilt statement (``invalid_signature``), and last the nonce claim
    (``stale_signature``). The claim is made only once the signature has verified: claiming earlier
    would let anyone who saw a nonce burn it with a signature that does not verify.

    ``replay_store=None`` claims nothing: the signature is then **not single-use**, and a copy
    verifies again for as long as its window lasts. Only a caller that de-duplicates nonces itself
    may pass it; :class:`mcp_vlei.extension.VleiIdentity` always verifies with a store.
    """
    if not credential_said:
        raise MissingCredential(
            "credentialSaid is required: a vlei-sig/0.3 signature speaks for one named credential"
        )
    if not is_qb64_identifier(credential_said):
        raise InvalidSignature(
            f"credentialSaid is not a 44-character CESR identifier: {credential_said!r}"
        )
    sig = precheck_request(
        signature, params, recipient=recipient, freshness_seconds=freshness_seconds,
        max_lifetime_seconds=max_lifetime_seconds,
        memory_since=replay_store.memory_since if replay_store is not None else None, now=now,
    )
    keys = [verkey] if isinstance(verkey, str) else list(verkey)
    try:
        raw_signature = cesr_decode_signature(sig.sig)
    except (ValueError, TypeError) as exc:  # binascii.Error is a ValueError
        raise InvalidSignature(f"signature is not valid CESR: {exc}", aid=sig.aid) from exc
    payload = statement_bytes(aid=sig.aid, aud=sig.aud, cred=credential_said, digest=sig.digest,
                              ts=sig.ts, exp=sig.exp, nonce=sig.nonce, method=method)
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(key)).verify(raw_signature, payload)
            break
        except _CryptoInvalidSignature:
            continue
    else:
        raise InvalidSignature(
            "signature does not verify under the signer's current key state", aid=sig.aid
        )

    if replay_store is not None:
        # The time check accepts until exp + skew; the claim is made a moment later, on the store's
        # clock. Kept one skew beyond that, a copy checked just before the boundary still finds it.
        expires = _parse_ts(sig.exp, aid=sig.aid) + 2 * timedelta(seconds=freshness_seconds)
        if not replay_store.claim(sig.aid, sig.nonce, expires):
            raise StaleSignature(
                "this signature was already presented (its nonce is spent): a replay", aid=sig.aid
            )
    return sig


_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def arguments_satisfied(
    rules: dict[str, Any] | None, arguments: dict[str, Any] | None, *, today: date
) -> tuple[bool, str]:
    """Check a call's arguments against the rules a tool declares for them.

    Scope compares the credential with the tool; it does not read the call. Some rules are about
    the call — an enrolment may be filed for today or up to ten days ahead. A requirement states
    them under ``arguments``, as deployment policy, one object of rules per argument:

    * ``{"dateWithinDays": [lo, hi]}`` — an ISO date (``YYYY-MM-DD``) from ``lo`` to ``hi`` days
      after ``today``, inclusive.

    A rule this function does not know is refused, not ignored: a deployment that wrote it meant
    something by it. Returns ``(ok, reason)``; ``reason`` is empty when ``ok``.
    """
    if not rules:
        return True, ""
    problem = argument_rules_problem(rules)
    if problem:
        return False, problem
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return False, "the call's arguments are not an object, so no rule on them can be checked"
    for name, rule in rules.items():
        for op, bound in rule.items():
            value = arguments.get(name)
            if not isinstance(value, str) or not _ISO_DATE.fullmatch(value):
                return False, f"{name}: requires a date (YYYY-MM-DD); the call carries {value!r}"
            try:
                day = date.fromisoformat(value)
            except ValueError:
                return False, f"{name}: {value!r} is not a date"
            low, high = bound
            offset = (day - today).days
            if not low <= offset <= high:
                return False, (
                    f"{name}: {value} is {offset} days from {today.isoformat()}; "
                    f"the tool accepts {low} to {high}"
                )
    return True, ""


def parse_utc_offset(text: str) -> timezone | None:
    """``"+08:00"`` -> that fixed UTC offset; ``""`` -> ``None`` (use the local date).

    Where a deployment counts "today" for :func:`arguments_satisfied`: a filing window is the
    filing office's days, and a verifier and the clients it serves should count the same ones.
    Strict — ASCII digits, ``±HH:MM``, no more than ``±14:00`` — and a ``ValueError`` otherwise.
    """
    if not text:
        return None
    match = re.fullmatch(r"([+-])([0-9]{2}):([0-9]{2})", text)
    hours, minutes = (int(match.group(2)), int(match.group(3))) if match else (99, 99)
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise ValueError(f"a UTC offset looks like +08:00; got {text!r}")
    sign = 1 if match.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def today_at(offset: timezone | None) -> date:
    """The date at a fixed UTC offset, or the local date when there is none."""
    return date.today() if offset is None else datetime.now(offset).date()


def argument_rules_problem(rules: Any) -> str | None:
    """What is wrong with a requirement's ``arguments`` rules, or ``None`` when they can be applied.

    Checked on every call by :func:`arguments_satisfied`, which refuses with this as the reason —
    a deployment's mistake is a refusal that names itself, never an exception without a layer —
    and available to a deployment that would rather not start with a policy it cannot apply.
    """
    if rules is None:
        return None
    if not isinstance(rules, dict):
        return "the tool's argument rules are not an object keyed by argument name"
    for name, rule in rules.items():
        if not isinstance(rule, dict) or not rule:
            return f"{name}: the tool's rule for it is not a non-empty object"
        for op, bound in rule.items():
            if op != "dateWithinDays":
                return f"{name}: unknown rule {op!r}; refusing rather than ignoring it"
            if not (isinstance(bound, (list, tuple)) and len(bound) == 2
                    and all(isinstance(b, int) and not isinstance(b, bool) for b in bound)):
                return f"{name}: dateWithinDays must be [lo, hi], two whole numbers of days; got {bound!r}"
    return None


def _is_nan(value: Any) -> bool:
    return isinstance(value, float) and math.isnan(value)


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
    if held is None:
        held = {}
    if not isinstance(held, dict):
        # `"maxAmount" in "maxAmount"` is true for a string, and indexing it then raised TypeError
        # out of the verification with no layer and no record.
        return False, f"the credential's scope is not an object: {held!r}"
    for key, want in required.items():
        if key not in held:
            return False, f"credential carries no {key!r}"
        have = held[key]
        if isinstance(want, (int, float)) and not isinstance(want, bool):
            # NaN compares false with everything, so `NaN < want` let it through as "enough".
            # isnan only on floats: a JSON integer can be arbitrarily large, and math.isnan on
            # 10**400 raises OverflowError instead of answering.
            if (isinstance(have, bool) or not isinstance(have, (int, float))
                    or _is_nan(have) or _is_nan(want) or have < want):
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
        elif type(have) is not type(want) or have != want:
            # By type as well as value: `1 == True`, so a held 1 met a required True.
            return False, f"{key}: requires {want!r}, credential carries {have!r}"
    return True, ""
