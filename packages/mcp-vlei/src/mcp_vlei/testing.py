"""A minimal KERI controller for tests and demos: real events, real signatures, real SAIDs.

**Never use this for real keys.** Seeds are derived from labels so that every run produces the same
identifiers; that is exactly what a test wants and exactly what a production key must not be.

The package verifies key event logs, transaction event logs and ACDC issuance proofs. Testing that
against placeholder JSON would only prove the checks were skipped, so this module mints the real
thing, in the byte format `kli` produces — compare `credentials/ecr.cesr` after a bootstrap:

* compact JSON in keripy's field order, with a version string that states the serialized size;
* Blake3-256 SAIDs, with self-addressing prefixes where KERI uses them (`icp`, `dip`, `vcp`);
* attachments grouped the way `kli vc export --full` and a witness's `/query` group them:
  ``-V`` group, ``-A`` controller signatures, ``-B`` witness receipts, ``-G`` seal source couples,
  ``-E`` first-seen replay couples; ``-I`` seal source triples after an ACDC.

:class:`World` assembles the whole deployment — witnesses, the GLEIF-like root, a delegated QVI, an
LE, the person holding the ECR and the agent they delegated to — and serves it over an
``httpx.MockTransport`` shaped like a witness, so the package's own HTTP code is what gets tested.

Seeds are derived from labels, so every SAID and AID is the same on every run.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import blake3
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
DUMMY = "#" * 44
DT = "2026-09-23T09:06:42.652807+00:00"
FIRST_SEEN = "1AAG" + "2026-09-23T09c04c48d924882p00c00"

QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
ECR_SCHEMA = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"
LEI = "984500ABCDEF12345678"


# ------------------------------------------------------------------------------------------- #
# CESR primitives
# ------------------------------------------------------------------------------------------- #

def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def b64int(value: int, width: int) -> str:
    out = ""
    for _ in range(width):
        out = B64[value % 64] + out
        value //= 64
    return out


def counter(code: str, count: int) -> str:
    return "-" + code + b64int(count, 2)


def digest(data: bytes) -> str:
    """CESR ``E``: Blake3-256, 32 raw bytes -> 44 characters."""
    return "E" + _b64u(b"\x00" + blake3.blake3(data).digest(length=32))[1:]


def seqner(sn: int) -> str:
    """CESR ``0A``: a 16-byte ordinal -> 24 characters."""
    return "0A" + _b64u(b"\x00\x00" + sn.to_bytes(16, "big"))[2:]


def group(attachments: str) -> str:
    assert len(attachments) % 4 == 0, "attachments must align to quadlets"
    return counter("V", len(attachments) // 4) + attachments


def serialize(body: dict[str, Any], fields: tuple[str, ...], proto: str = "KERI") -> str:
    """Fill in the version string and the SAID fields, exactly as keripy does."""
    body = dict(body)
    for name in fields:
        body[name] = DUMMY
    body["v"] = f"{proto}10JSON000000_"
    size = len(json.dumps(body, separators=(",", ":")))
    body["v"] = f"{proto}10JSON{size:06x}_"
    said = digest(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    for name in fields:
        body[name] = said
    return json.dumps(body, separators=(",", ":"))


class Key:
    """One Ed25519 key pair. ``code`` is ``D`` (transferable) or ``B`` (a witness's)."""

    def __init__(self, label: str, code: str = "D") -> None:
        self.seed = hashlib.sha256(label.encode("utf-8")).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.code = code

    @property
    def qb64(self) -> str:
        return self.code + _b64u(b"\x00" + self._private.public_key().public_bytes_raw())[1:]

    @property
    def next_digest(self) -> str:
        """The commitment a prior establishment event makes to this key."""
        return digest(self.qb64.encode("utf-8"))

    def indexed(self, data: bytes, index: int) -> str:
        """CESR ``A``: an indexed Ed25519 signature, 88 characters."""
        return "A" + B64[index] + _b64u(b"\x00\x00" + self._private.sign(data))[2:]


class Witness:
    def __init__(self, label: str) -> None:
        self.key = Key(f"witness:{label}", code="B")

    @property
    def aid(self) -> str:
        return self.key.qb64


# ------------------------------------------------------------------------------------------- #
# Controller: a key event log
# ------------------------------------------------------------------------------------------- #

@dataclass
class Event:
    raw: str
    attachments: str

    @property
    def body(self) -> dict[str, Any]:
        return json.loads(self.raw)

    @property
    def said(self) -> str:
        return self.body["d"]

    def cesr(self) -> str:
        return self.raw + group(self.attachments)


class Controller:
    """An AID with a key event log: inception, interaction, rotation, and delegation."""

    def __init__(
        self,
        label: str,
        *,
        witnesses: list[Witness] | None = None,
        toad: int | None = None,
        delegator: "Controller | None" = None,
        approve: bool = True,
        receipts: int | None = None,
    ) -> None:
        self.label = label
        #: How many witnesses actually receipt each event. Fewer than ``toad`` is a log the
        #: witnesses never agreed to, which a verifier must refuse.
        self.receipts = receipts
        self._generation = 0
        self.keys = [Key(f"{label}:0")]
        self.next = [Key(f"{label}:1")]
        self.witnesses = list(witnesses or [])
        self.toad = len(self.witnesses) if toad is None else toad
        self.delegator = delegator
        self.events: list[Event] = []

        body: dict[str, Any] = {
            "v": "",
            "t": "dip" if delegator else "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": [key.qb64 for key in self.keys],
            "nt": "1",
            "n": [key.next_digest for key in self.next],
            "bt": f"{self.toad:x}",
            "b": [w.aid for w in self.witnesses],
            "c": [],
            "a": [],
        }
        if delegator:
            body["di"] = delegator.pre
        raw = serialize(body, ("d", "i"))
        self.pre = json.loads(raw)["i"]
        source = delegator.interact([{"i": self.pre, "s": "0", "d": self.pre}]) if (
            delegator and approve
        ) else None
        self._append(raw, source)

    # -- events ------------------------------------------------------------------------------ #

    @property
    def sn(self) -> int:
        return len(self.events) - 1

    @property
    def seed(self) -> bytes:
        """The current signing key's seed, for a `Signer` that speaks for this AID."""
        return self.keys[0].seed

    def _append(self, raw: str, delegation_source: tuple[int, str] | None = None) -> Event:
        data = raw.encode("utf-8")
        sn = len(self.events)
        attachments = counter("A", len(self.keys)) + "".join(
            key.indexed(data, index) for index, key in enumerate(self.keys)
        )
        signing = self.witnesses[: self.receipts] if self.receipts is not None else self.witnesses
        if signing:
            attachments += counter("B", len(signing)) + "".join(
                w.key.indexed(data, index) for index, w in enumerate(signing)
            )
        if delegation_source:
            attachments += counter("G", 1) + seqner(delegation_source[0]) + delegation_source[1]
        attachments += counter("E", 1) + seqner(sn) + FIRST_SEEN
        event = Event(raw, attachments)
        self.events.append(event)
        return event

    def interact(self, seals: list[dict[str, str]]) -> tuple[int, str]:
        """Anchor seals; returns the (sn, SAID) of the anchoring event."""
        raw = serialize(
            {
                "v": "",
                "t": "ixn",
                "d": "",
                "i": self.pre,
                "s": f"{self.sn + 1:x}",
                "p": self.events[-1].said,
                "a": seals,
            },
            ("d",),
        )
        event = self._append(raw)
        return self.sn, event.said

    def rotate(self, *, reveal: list[Key] | None = None) -> None:
        """Rotate to the committed next keys — or, with ``reveal``, to keys that were not committed."""
        self._generation += 1
        self.keys = reveal or self.next
        self.next = [Key(f"{self.label}:{self._generation + 1}")]
        body: dict[str, Any] = {
            "v": "",
            "t": "drt" if self.delegator else "rot",
            "d": "",
            "i": self.pre,
            "s": f"{self.sn + 1:x}",
            "p": self.events[-1].said,
            "kt": "1",
            "k": [key.qb64 for key in self.keys],
            "nt": "1",
            "n": [key.next_digest for key in self.next],
            "bt": f"{self.toad:x}",
            "br": [],
            "ba": [],
            "a": [],
        }
        raw = serialize(body, ("d",))
        source = None
        if self.delegator:
            said = json.loads(raw)["d"]
            source = self.delegator.interact([{"i": self.pre, "s": f"{self.sn + 1:x}", "d": said}])
        self._append(raw, source)

    def kel(self) -> str:
        return "".join(event.cesr() for event in self.events)


# ------------------------------------------------------------------------------------------- #
# Registry: a transaction event log
# ------------------------------------------------------------------------------------------- #

class Registry:
    """A credential registry anchored in its issuer's key event log."""

    def __init__(self, issuer: Controller, label: str) -> None:
        self.issuer = issuer
        raw = serialize(
            {
                "v": "",
                "t": "vcp",
                "d": "",
                "i": "",
                "ii": issuer.pre,
                "s": "0",
                "c": ["NB"],
                "bt": "0",
                "b": [],
                "n": seqner(int.from_bytes(hashlib.sha256(label.encode()).digest()[:8], "big")),
            },
            ("d", "i"),
        )
        self.regk = json.loads(raw)["i"]
        sn, said = issuer.interact([{"i": self.regk, "s": "0", "d": self.regk}])
        self.vcp = Event(raw, counter("G", 1) + seqner(sn) + said)
        #: vcid -> [iss, rev?]
        self.tels: dict[str, list[Event]] = {}

    def _anchored(self, body: dict[str, Any], seal_sn: str, anchor: bool) -> Event:
        raw = serialize(body, ("d",))
        said = json.loads(raw)["d"]
        if anchor:
            sn, anchor_said = self.issuer.interact([{"i": body["i"], "s": seal_sn, "d": said}])
        else:
            sn, anchor_said = self.issuer.sn, self.issuer.events[-1].said
        return Event(raw, counter("G", 1) + seqner(sn) + anchor_said)

    def issue(self, vcid: str, *, anchor: bool = True) -> None:
        body = {"v": "", "t": "iss", "d": "", "i": vcid, "s": "0", "ri": self.regk, "dt": DT}
        self.tels[vcid] = [self._anchored(body, "0", anchor)]

    def revoke(self, vcid: str) -> None:
        iss = self.tels[vcid][0]
        body = {
            "v": "", "t": "rev", "d": "", "i": vcid, "s": "1",
            "ri": self.regk, "p": iss.said, "dt": DT,
        }
        self.tels[vcid].append(self._anchored(body, "1", True))

    def tel(self, vcid: str) -> str:
        return "".join(event.cesr() for event in self.tels.get(vcid, []))


# ------------------------------------------------------------------------------------------- #
# Credentials
# ------------------------------------------------------------------------------------------- #

def acdc(
    schema: str,
    issuer: str,
    issuee: str,
    registry: str,
    attributes: dict[str, Any],
    edge: tuple[str, str, str] | None = None,
) -> str:
    """Serialize an ACDC and fill in the SAID its contents imply."""
    body: dict[str, Any] = {
        "v": "",
        "d": "",
        "i": issuer,
        "ri": registry,
        "s": schema,
        "a": {"i": issuee, "dt": DT, **attributes},
    }
    if edge:
        label, target, target_schema = edge
        body["e"] = {"d": "", label: {"n": target, "s": target_schema}}
    return serialize(body, ("d",), proto="ACDC")


@dataclass
class Credential:
    raw: str
    registry: Registry

    @property
    def said(self) -> str:
        return json.loads(self.raw)["d"]

    @property
    def issuer(self) -> Controller:
        return self.registry.issuer


def export(chain: list[Credential]) -> str:
    """What `kli vc export --full` writes: issuer KELs, registries and issuances, then the ACDCs.

    ``chain`` is leaf first. Delegators' logs are included when they are not already issuers,
    because a delegated issuer's inception is only valid alongside its delegator's approval.
    """
    out: list[str] = []
    seen: set[str] = set()

    def kel(controller: Controller) -> None:
        if controller.pre in seen:
            return
        seen.add(controller.pre)
        out.append(controller.kel())
        if controller.delegator:
            kel(controller.delegator)

    for credential in chain:
        kel(credential.issuer)
        out.append(credential.registry.vcp.cesr())
        out.append("".join(e.cesr() for e in credential.registry.tels.get(credential.said, [])[:1]))
    for credential in reversed(chain):
        iss = credential.registry.tels.get(credential.said, [None])[0]
        out.append(credential.raw)
        if iss is not None:
            out.append(counter("I", 1) + credential.said + seqner(0) + iss.said)
    return "".join(out)


# ------------------------------------------------------------------------------------------- #
# World: the whole deployment, and a witness that serves it
# ------------------------------------------------------------------------------------------- #

@dataclass
class World:
    """root -> QVI (delegated) -> LE -> ECR (a person) -> agent (delegated by that person)."""

    role: str = "member-registration"
    scope: dict[str, Any] | None = None
    label: str = "world"
    witnesses: list[Witness] = field(init=False)
    controllers: dict[str, Controller] = field(init=False)
    registries: list[Registry] = field(init=False)

    def __post_init__(self) -> None:
        tag = self.label
        self.witnesses = [Witness(f"{tag}:{name}") for name in ("wan", "wil", "wes")]
        wits = dict(witnesses=self.witnesses, toad=2)
        self.root = Controller(f"{tag}:root", **wits)
        self.qvi = Controller(f"{tag}:qvi", delegator=self.root, **wits)
        self.le = Controller(f"{tag}:le", **wits)
        self.holder = Controller(f"{tag}:ecr", **wits)
        self.agent = Controller(f"{tag}:agent", delegator=self.holder, **wits)
        self.controllers = {
            c.pre: c for c in (self.root, self.qvi, self.le, self.holder, self.agent)
        }

        self.root_registry = Registry(self.root, f"{tag}:rootRegistry")
        self.qvi_registry = Registry(self.qvi, f"{tag}:qviRegistry")
        self.le_registry = Registry(self.le, f"{tag}:leRegistry")
        self.registries = [self.root_registry, self.qvi_registry, self.le_registry]

        self.qvi_credential = self.issue(
            self.root_registry, QVI_SCHEMA, self.qvi.pre, {"LEI": "5493001KJTIIGC8Y1R17"}
        )
        self.le_credential = self.issue(
            self.qvi_registry, LE_SCHEMA, self.le.pre, {"LEI": LEI},
            edge=("qvi", self.qvi_credential),
        )
        attributes: dict[str, Any] = {
            "LEI": LEI,
            "personLegalName": "Chen Wei-Ting",
            "engagementContextRole": self.role,
        }
        if self.scope:
            attributes["scope"] = self.scope
        self.ecr_credential = self.issue(
            self.le_registry, ECR_SCHEMA, self.holder.pre, attributes,
            edge=("le", self.le_credential),
        )

    def issue(
        self,
        registry: Registry,
        schema: str,
        issuee: str,
        attributes: dict[str, Any],
        *,
        edge: tuple[str, Credential] | None = None,
        anchor: bool = True,
    ) -> Credential:
        edge_spec = None
        if edge:
            label, parent = edge
            edge_spec = (label, parent.said, json.loads(parent.raw)["s"])
        raw = acdc(schema, registry.issuer.pre, issuee, registry.regk, attributes, edge_spec)
        credential = Credential(raw, registry)
        registry.issue(credential.said, anchor=anchor)
        return credential

    def reissue_ecr(self, dt: str) -> Credential:
        """Issue the holder a fresh ECR — what an LE does after withdrawing the last one.

        ``dt`` is the issuance time. It is part of the credential, so a new issuance has a new
        SAID; re-issuing the same bytes would silently resurrect a revoked credential.
        """
        attributes = json.loads(self.ecr_credential.raw)["a"]
        attributes = {k: v for k, v in attributes.items() if k not in ("i",)} | {"dt": dt}
        self.ecr_credential = self.issue(
            self.le_registry, ECR_SCHEMA, self.holder.pre, attributes,
            edge=("le", self.le_credential),
        )
        return self.ecr_credential

    def enrol(self, controller: Controller) -> Controller:
        """Make an identifier's log available from the witness — an attacker's included."""
        self.controllers[controller.pre] = controller
        if controller.delegator:
            self.enrol(controller.delegator)
        return controller

    def enrol_registry(self, registry: Registry) -> Registry:
        self.registries.append(registry)
        self.enrol(registry.issuer)
        return registry

    # -- what gets presented ----------------------------------------------------------------- #

    @property
    def chain(self) -> list[Credential]:
        return [self.ecr_credential, self.le_credential, self.qvi_credential]

    @property
    def ecr_stream(self) -> str:
        return export(self.chain)

    @property
    def le_stream(self) -> str:
        return export([self.le_credential, self.qvi_credential])

    # -- the witness --------------------------------------------------------------------------- #

    def witness_handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/query":
            return httpx.Response(404)
        typ = request.url.params.get("typ")
        if typ == "kel":
            controller = self.controllers.get(request.url.params.get("pre", ""))
            return httpx.Response(200, text=controller.kel() if controller else "")
        if typ == "tel":
            vcid = request.url.params.get("vcid", "")
            return httpx.Response(200, text="".join(r.tel(vcid) for r in self.registries))
        return httpx.Response(400)

    def witness_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.witness_handler))
