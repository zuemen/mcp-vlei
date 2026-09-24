"""Key event logs: an identifier's current keys, established from its own log.

A request signature means nothing until the key it verifies under is known to belong to the
identifier that claims it. In KERI that is not looked up anywhere — it is **derived**:

* a self-addressing prefix is the digest of the inception event that created it, so the inception
  (and the keys in it) is the only one that can claim that prefix;
* each later event names the digest of the one before it and is signed by the keys current at that
  point, so the log cannot be reordered, truncated in the middle or altered;
* a rotation must reveal keys whose digests the previous establishment event committed to, so
  whoever steals a signing key still cannot rotate to a key of their choosing;
* witnesses receipt each event, and a log with fewer receipts than its threshold is one the
  witnesses never agreed to;
* a delegated identifier is valid only once its delegator anchors the inception in their own log.

This module checks exactly those things and nothing else. It is deliberately small — the subset of
KERI that `kli` emits for single-key, witnessed, optionally delegated identifiers — and it refuses
anything outside that subset rather than guessing: weighted thresholds, unknown digest codes and
unknown attachment codes outside a group all raise :class:`~mcp_vlei.errors.ChainInvalid`.

Duplicity — two conflicting logs for one prefix, each internally valid — is caught across the
witnesses a relying party is configured with (:class:`WitnessKeyStates`), not beyond them. Witnesses
run by one operator can be made to agree; independent witnesses, or watchers, are what make the
check meaningful. The limit is stated in ``docs/CONFORMANCE.md``.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Sequence

import httpx
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ChainInvalid

__all__ = [
    "KeyState",
    "Message",
    "check_said",
    "StreamKeyStates",
    "WitnessKeyStates",
    "delegator_of",
    "digest_of",
    "key_states_in",
    "parse_messages",
    "recompute_event_said",
    "verify_kel",
]

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_DUMMY = "#" * 44
ESTABLISHMENT = ("icp", "dip", "rot", "drt")
KEL_ILKS = ESTABLISHMENT + ("ixn",)
#: How many delegators deep a resolution may go. vLEI needs one (GLEIF -> QVI, person -> agent).
MAX_DELEGATION_DEPTH = 4


# ------------------------------------------------------------------------------------------- #
# CESR: the narrow subset `kli` puts after an event
# ------------------------------------------------------------------------------------------- #

def _b64int(text: str) -> int:
    value = 0
    for char in text:
        value = value * 64 + _B64.index(char)
    return value


def _seqner(qb64: str) -> int:
    if len(qb64) != 24 or not qb64.startswith("0A"):
        raise ChainInvalid(f"not a CESR sequence number: {qb64[:8]}...")
    return int.from_bytes(base64.urlsafe_b64decode("AA" + qb64[2:])[2:], "big")


def _indexed_signature(qb64: str) -> tuple[int, bytes]:
    """An indexed Ed25519 signature (`A` both lists, `B` current only): index and raw bytes."""
    if len(qb64) != 88 or qb64[0] not in ("A", "B"):
        raise ChainInvalid(f"unsupported indexed signature code {qb64[:2]!r}")
    return _B64.index(qb64[1]), base64.urlsafe_b64decode("AA" + qb64[2:])[2:]


def _public_key(qb64: str) -> Ed25519PublicKey:
    if len(qb64) != 44 or qb64[0] not in ("D", "B"):
        raise ChainInvalid(f"unsupported key code {qb64[:1]!r}: only Ed25519 keys are accepted")
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode("A" + qb64[1:])[1:])


def digest_of(data: bytes) -> str:
    """CESR ``E``: Blake3-256, the digest KERI uses for SAIDs, prefixes and key commitments."""
    import blake3

    return "E" + base64.urlsafe_b64encode(b"\x00" + blake3.blake3(data).digest(length=32)).decode(
        "ascii"
    )[1:]


@dataclass
class Message:
    """One JSON body from a CESR stream, with the exact bytes it arrived as and its attachments."""

    body: dict[str, Any]
    raw: str
    #: Controller signatures, as (key index, raw signature).
    signatures: list[tuple[int, bytes]] = field(default_factory=list)
    #: Witness receipts, as (witness index, raw signature).
    receipts: list[tuple[int, bytes]] = field(default_factory=list)
    #: Seal source couples: which (sn, SAID) of another log anchors this event.
    sources: list[tuple[int, str]] = field(default_factory=list)
    #: Seal source triples after an ACDC: (prefix, sn, SAID) of the event that issued it.
    triples: list[tuple[str, int, str]] = field(default_factory=list)

    @property
    def ilk(self) -> str | None:
        return self.body.get("t")


def _parse_attachments(text: str, message: Message) -> None:
    pos, end = 0, len(text)
    group_end = -1
    while pos < end:
        if text[pos] != "-" or pos + 4 > end:
            raise ChainInvalid(f"unrecognized attachment at {text[pos:pos + 8]!r}")
        code, count = text[pos + 1], _b64int(text[pos + 2 : pos + 4])
        pos += 4
        if code == "V":
            # A group: its length is stated, so anything inside it this parser does not know can be
            # stepped over. Skipping is safe — an attachment that is not read cannot make a check
            # pass, only fail to help one.
            group_end = pos + count * 4
            continue
        if code not in ("A", "B", "G", "I", "E", "C"):
            if pos <= group_end:
                pos = group_end
                continue
            raise ChainInvalid(f"unsupported attachment code -{code}")
        if code in ("A", "B"):
            target = message.signatures if code == "A" else message.receipts
            for _ in range(count):
                target.append(_indexed_signature(text[pos : pos + 88]))
                pos += 88
        elif code == "G":
            for _ in range(count):
                message.sources.append((_seqner(text[pos : pos + 24]), text[pos + 24 : pos + 68]))
                pos += 68
        elif code == "I":
            for _ in range(count):
                message.triples.append(
                    (text[pos : pos + 44], _seqner(text[pos + 44 : pos + 68]), text[pos + 68 : pos + 112])
                )
                pos += 112
        elif code == "E":  # first-seen replay couples: ordinal + datetime, informational
            pos += count * (24 + 36)
        elif code == "C":  # non-transferable receipt couples: prefix + signature
            pos += count * (44 + 88)


def parse_messages(stream: str) -> list[Message]:
    """Every JSON body in a CESR stream — key events, registry events and ACDCs — in order."""
    decoder = json.JSONDecoder()
    messages: list[Message] = []
    pos = 0
    while pos < len(stream):
        start = stream.find("{", pos)
        if start < 0:
            break
        try:
            body, end = decoder.raw_decode(stream, start)
        except json.JSONDecodeError as exc:
            raise ChainInvalid(f"malformed JSON in the stream at offset {start}") from exc
        if not isinstance(body, dict):
            raise ChainInvalid(f"expected a JSON object at offset {start}")
        message = Message(body=body, raw=stream[start:end])
        following = stream.find("{", end)
        attachments = stream[end : following if following >= 0 else len(stream)].strip()
        if attachments:
            _parse_attachments(attachments, message)
        messages.append(message)
        pos = end
    return messages


# ------------------------------------------------------------------------------------------- #
# Checks
# ------------------------------------------------------------------------------------------- #

def recompute_event_said(message: Message, fields: tuple[str, ...] = ("d",)) -> str:
    """The SAID a message's own bytes imply, with ``fields`` replaced by filler of equal length."""
    said = message.body.get("d", "")
    if not isinstance(said, str) or len(said) != 44 or not said.startswith("E"):
        raise ChainInvalid(f"unsupported SAID {str(said)[:8]!r}: only Blake3-256 is accepted")
    dummied = message.raw
    for name in fields:
        needle = f'"{name}":"{said}"'
        if needle not in dummied:
            raise ChainInvalid(f"event {said}: field {name!r} does not carry its SAID")
        dummied = dummied.replace(needle, f'"{name}":"{_DUMMY}"', 1)
    return digest_of(dummied.encode("utf-8"))


def _check_version(message: Message) -> None:
    version = message.body.get("v", "")
    if not (isinstance(version, str) and len(version) == 17 and version[4:10] == "10JSON"):
        raise ChainInvalid(f"unsupported version string {version!r}")
    try:
        size = int(version[10:16], 16)
    except ValueError as exc:
        raise ChainInvalid(f"unreadable version string {version!r}") from exc
    if size != len(message.raw.encode("utf-8")):
        raise ChainInvalid(
            f"event {message.body.get('d')} states {size} bytes but is "
            f"{len(message.raw.encode('utf-8'))}; it was altered"
        )


def check_said(message: Message, fields: tuple[str, ...] = ("d",)) -> None:
    """Refuse a message whose bytes do not hash to the SAID it carries, or whose size is misstated."""
    _check_version(message)
    if recompute_event_said(message, fields) != message.body.get("d"):
        raise ChainInvalid(
            f"event {message.body.get('d')} does not hash to its own SAID; its contents were altered"
        )


def _threshold(value: Any, what: str) -> int:
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            pass
    raise ChainInvalid(f"unsupported {what} threshold {value!r}: only numeric thresholds are accepted")


def _verified(message: Message, keys: list[str], signatures: list[tuple[int, bytes]]) -> set[int]:
    data = message.raw.encode("utf-8")
    ok: set[int] = set()
    for index, signature in signatures:
        if index >= len(keys):
            continue
        try:
            _public_key(keys[index]).verify(signature, data)
        except _CryptoInvalidSignature:
            continue
        ok.add(index)
    return ok


@dataclass(frozen=True)
class KeyState:
    """What a verified log establishes about an identifier, as of its last event."""

    pre: str
    sn: int
    #: SAID of the last event.
    digest: str
    #: Current signing keys, CESR.
    keys: list[str]
    threshold: int
    #: Digests the last establishment event committed to for the next rotation.
    next_digests: list[str]
    witnesses: list[str]
    toad: int
    delegator: str | None
    #: Every seal anchored by a verified event in this log.
    seals: list[dict[str, Any]]

    def anchors(self, seal: dict[str, Any]) -> bool:
        """Does a verified event in this log anchor ``seal`` (matched on `i`, `s` and `d`)?"""
        return any(
            isinstance(s, dict)
            and s.get("i") == seal.get("i")
            and s.get("s") == seal.get("s")
            and s.get("d") == seal.get("d")
            for s in self.seals
        )


def delegator_of(messages: list[Message], pre: str) -> str | None:
    """The delegator named by ``pre``'s inception, if it is a delegated identifier."""
    for message in messages:
        if message.ilk in ("icp", "dip") and message.body.get("i") == pre:
            return message.body.get("di") if message.ilk == "dip" else None
    return None


def verify_kel(messages: list[Message], pre: str, *, delegator: KeyState | None = None) -> KeyState:
    """Verify ``pre``'s key event log and return its current key state.

    ``delegator`` is the verified key state of the identifier named in a ``dip``; a delegated log
    is refused without it, and refused when it does not anchor the delegated events.
    """
    events = [m for m in messages if m.ilk in KEL_ILKS and m.body.get("i") == pre]
    if not events:
        raise ChainInvalid(f"no key event log was found for {pre}", aid=pre)

    keys: list[str] = []
    threshold = 1
    next_digests: list[str] = []
    next_threshold = 1
    witnesses: list[str] = []
    toad = 0
    delegated_by: str | None = None
    seals: list[dict[str, Any]] = []
    previous = ""

    for index, message in enumerate(events):
        body, ilk = message.body, message.ilk
        said = body.get("d", "")
        if body.get("s") != f"{index:x}":
            raise ChainInvalid(
                f"the log of {pre} is not continuous: event {index} states sequence number "
                f"{body.get('s')!r}",
                aid=pre,
            )

        if index == 0:
            if ilk not in ("icp", "dip"):
                raise ChainInvalid(f"the log of {pre} does not begin with an inception", aid=pre)
            if not pre.startswith("E") or body.get("i") != said:
                raise ChainInvalid(
                    f"the prefix {pre} does not derive from its inception event; "
                    "only self-addressing identifiers are accepted",
                    aid=pre,
                )
            try:
                check_said(message, ("d", "i"))
            except ChainInvalid as exc:
                raise ChainInvalid(
                    f"the prefix {pre} does not derive from its inception event: {exc.message}",
                    aid=pre,
                ) from exc
            keys = list(body.get("k") or [])
            threshold = _threshold(body.get("kt"), "signing")
            witnesses = list(body.get("b") or [])
        else:
            check_said(message)
            if body.get("p") != previous:
                raise ChainInvalid(
                    f"event {index} of {pre} does not follow the one before it", aid=pre
                )
            if ilk in ("icp", "dip"):
                raise ChainInvalid(f"the log of {pre} has a second inception", aid=pre)
            if ilk in ("rot", "drt"):
                if (ilk == "drt") != (delegated_by is not None):
                    raise ChainInvalid(f"event {index} of {pre} has the wrong rotation type", aid=pre)
                revealed = list(body.get("k") or [])
                committed = set(next_digests)
                if not revealed or any(
                    digest_of(key.encode("utf-8")) not in committed for key in revealed
                ):
                    raise ChainInvalid(
                        f"rotation {index} of {pre} reveals keys the previous establishment "
                        "event did not commit to",
                        aid=pre,
                    )
                if len(revealed) < next_threshold:
                    raise ChainInvalid(
                        f"rotation {index} of {pre} does not satisfy the committed threshold",
                        aid=pre,
                    )
                keys = revealed
                threshold = _threshold(body.get("kt"), "signing")
                removed = set(body.get("br") or [])
                witnesses = [w for w in witnesses if w not in removed] + list(body.get("ba") or [])

        if ilk in ESTABLISHMENT:
            next_digests = list(body.get("n") or [])
            next_threshold = _threshold(body.get("nt"), "next")
            toad = _threshold(body.get("bt"), "witness")

        signed = _verified(message, keys, message.signatures)
        if len(signed) < max(threshold, 1):
            raise ChainInvalid(
                f"event {index} of {pre} is not signed by its current keys "
                f"({len(signed)} valid signature(s), threshold {threshold})",
                aid=pre,
            )
        receipted = _verified(message, witnesses, message.receipts)
        if len(receipted) < toad:
            raise ChainInvalid(
                f"event {index} of {pre} carries {len(receipted)} valid witness receipt(s); "
                f"its witness threshold is {toad}",
                aid=pre,
            )

        if ilk in ("dip", "drt"):
            named = body.get("di") if ilk == "dip" else delegated_by
            seal = {"i": pre, "s": body.get("s"), "d": said}
            if delegator is None or delegator.pre != named or not delegator.anchors(seal):
                raise ChainInvalid(
                    f"the delegation of {pre} by {named} is not anchored in the delegator's "
                    "key event log; the delegator never approved it",
                    aid=pre,
                )
            delegated_by = named

        seals.extend(s for s in (body.get("a") or []) if isinstance(s, dict))
        previous = said

    return KeyState(
        pre=pre,
        sn=len(events) - 1,
        digest=previous,
        keys=keys,
        threshold=threshold,
        next_digests=next_digests,
        witnesses=witnesses,
        toad=toad,
        delegator=delegated_by,
        seals=seals,
    )


# ------------------------------------------------------------------------------------------- #
# Sources of logs
# ------------------------------------------------------------------------------------------- #

class StreamKeyStates:
    """Key states established from logs carried in a presented stream (`kli vc export --full`).

    Self-certifying, so the presenter cannot forge them — but the presenter chooses how much of each
    log to include. That is enough to prove an issuance happened; it is not enough to establish a
    key that is current *now*, which is why request signatures use :class:`WitnessKeyStates`.
    """

    def __init__(self, messages: list[Message]) -> None:
        self.messages = messages
        self._states: dict[str, KeyState] = {}
        self._resolving: set[str] = set()

    def prefixes(self) -> list[str]:
        return [m.body["i"] for m in self.messages if m.ilk in ("icp", "dip") and "i" in m.body]

    def resolve(self, pre: str) -> KeyState:
        if pre in self._states:
            return self._states[pre]
        if pre in self._resolving or len(self._resolving) > MAX_DELEGATION_DEPTH:
            raise ChainInvalid(f"the delegation of {pre} does not terminate", aid=pre)
        self._resolving.add(pre)
        try:
            named = delegator_of(self.messages, pre)
            delegator = self.resolve(named) if named else None
            state = verify_kel(self.messages, pre, delegator=delegator)
        finally:
            self._resolving.discard(pre)
        self._states[pre] = state
        return state


def key_states_in(messages: list[Message]) -> dict[str, KeyState]:
    """Verify every key event log in a stream, delegators resolved from the same stream."""
    source = StreamKeyStates(messages)
    return {pre: source.resolve(pre) for pre in source.prefixes()}


class WitnessKeyStates:
    """Current key states, read from witnesses' copies of each log and verified here.

    The witness is asked, not the presenter: a key rotated away last week must not verify a request
    today, and only a log the presenter did not choose can show that.

    Given several witnesses, it also catches **duplicity** — a controller (or whoever holds its
    keys) showing different witnesses different logs, each internally valid. The copies are compared
    event by event, and two different events at one sequence number refuse the identifier. A copy
    that is merely shorter is a witness still catching up, not a conflict, and the longest copy is
    the one verified. With one witness there is nothing to compare, and nothing is claimed.

    ``quorum`` is how many witnesses must answer; by default a majority. Fewer is not "no
    conflict", it is "not established".
    """

    def __init__(
        self,
        witness_url: str | Sequence[str],
        *,
        quorum: int | None = None,
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        urls = [witness_url] if isinstance(witness_url, str) else list(witness_url)
        urls = [u.rstrip("/") for u in urls if u]
        if not urls:
            raise ValueError("witness_url is required to read a key event log")
        self.witness_urls = urls
        self.witness_url = urls[0]
        self.quorum = quorum or len(urls) // 2 + 1
        if not 1 <= self.quorum <= len(urls):
            raise ValueError(f"quorum must be between 1 and {len(urls)}")
        self._timeout = timeout
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def messages(self, pre: str, witness_url: str | None = None) -> list[Message]:
        url = witness_url or self.witness_url
        http = await self._http()
        try:
            response = await http.get(f"{url}/query", params={"typ": "kel", "pre": pre})
        except httpx.HTTPError as exc:
            raise ChainInvalid(
                f"the key event log of {pre} could not be read from {url} "
                f"({type(exc).__name__}); its key state was not established",
                aid=pre,
            ) from exc
        if response.status_code != 200:
            raise ChainInvalid(
                f"the key event log of {pre} could not be read from {url} "
                f"(HTTP {response.status_code}); its key state was not established",
                aid=pre,
            )
        return parse_messages(response.text)

    async def _copies(self, pre: str) -> list[tuple[str, list[Message]]]:
        copies: list[tuple[str, list[Message]]] = []
        failures: list[ChainInvalid] = []
        for url in self.witness_urls:
            try:
                copies.append((url, await self.messages(pre, url)))
            except ChainInvalid as exc:
                failures.append(exc)
        if len(copies) < self.quorum:
            reason = f": {failures[0].message}" if failures else ""
            raise ChainInvalid(
                f"only {len(copies)} of {len(self.witness_urls)} witnesses answered for {pre}, "
                f"and {self.quorum} are required; its key state was not established{reason}",
                aid=pre,
            )
        return copies

    async def resolve(self, pre: str, *, _depth: int = 0) -> KeyState:
        if _depth > MAX_DELEGATION_DEPTH:
            raise ChainInvalid(f"the delegation of {pre} does not terminate", aid=pre)
        copies = await self._copies(pre)

        seen: dict[int, tuple[str, str]] = {}
        for url, messages in copies:
            for message in messages:
                if message.ilk not in KEL_ILKS or message.body.get("i") != pre:
                    continue
                try:
                    sn = int(str(message.body.get("s")), 16)
                except ValueError:
                    continue  # verify_kel refuses it with a reason
                said = message.body.get("d", "")
                if sn in seen and seen[sn][0] != said:
                    raise ChainInvalid(
                        f"duplicity: witnesses {seen[sn][1]} and {url} hold different events at "
                        f"sequence number {sn} of {pre}; its key state cannot be trusted",
                        aid=pre,
                    )
                seen.setdefault(sn, (said, url))

        def length(copy: tuple[str, list[Message]]) -> int:
            return sum(1 for m in copy[1] if m.ilk in KEL_ILKS and m.body.get("i") == pre)

        messages = max(copies, key=length)[1]
        named = delegator_of(messages, pre)
        delegator = await self.resolve(named, _depth=_depth + 1) if named else None
        return verify_kel(messages, pre, delegator=delegator)
