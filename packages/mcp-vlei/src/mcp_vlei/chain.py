"""Reading and checking an ACDC credential chain without asking anyone.

This is what mode (a) of ``spec/SPEC.md`` actually requires of a relying party: the presenter
publishes a credential, and the verifier **checks it itself**. Sending it to a verification service
is the other mode, and it is not available for a counterparty's credential anyway —
``/presentations`` requires headers signed by the AID the credential was issued to, so only the
holder can present.

What is established here:

* every credential's SAID is recomputed and must match the one claimed;
* every edge resolves to a credential that is present in the stream;
* the chain is continuous — each link's issuer is the previous link's issuee;
* the chain terminates at an issuer the relying party accepts as a root;
* every credential was **issued by the identifier it names** (:func:`verify_issuance`): its
  issuance event is in a registry that issuer incepted, and the issuer's key event log — verified
  from its inception, signatures and witness receipts included — anchors both.

The last point is what makes the others mean anything. A SAID proves a credential was not altered
after it was made; it says nothing about who made it. Anyone can write an ECR that names a real LE as
its issuer and themselves as its issuee, and every SAID in it will recompute. Making the LE's log
anchor that issuance takes the LE's keys.

What is **not** established here is **revocation**. It lives in the issuer's transaction event log as
it is *now*, and a presented stream shows it as the presenter chose to export it. Reaching the live
log is exactly what "offline" rules out; :mod:`mcp_vlei.revocation` does it.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Iterator

from .errors import ChainInvalid, UnknownRoot
from .kel import Message, StreamKeyStates, check_said

__all__ = [
    "Acdc",
    "VLEI_SCHEMAS",
    "parse_stream",
    "recompute_said",
    "verify_issuance",
    "verify_vlei_chain",
    "walk_chain",
]

#: The published WebOfTrust/vLEI schema SAIDs. A credential's type is its `s`, never a name or a
#: field the credential's author chose.
VLEI_SCHEMAS = {
    "QVI": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "LE": "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    "OOR": "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
    "ECR": "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
}
_TYPE_OF = {said: name for name, said in VLEI_SCHEMAS.items()}
#: What each vLEI credential must be issued under. An ECR or OOR is a legal entity's statement
#: about its own staff, so it chains to that entity's LE credential; an LE credential chains to the
#: QVI that verified the entity.
_ISSUED_UNDER = {"ECR": "LE", "OOR": "LE", "LE": "QVI"}

_BACKSLASH = chr(92)
#: A SAID is 44 characters. The recomputation replaces it with the same number of filler characters
#: so the serialization keeps its length — the `v` field encodes the size and must stay true.
_DUMMY = "#" * 44


@dataclass(frozen=True)
class Acdc:
    """One credential, with the exact bytes it arrived as."""

    said: str
    schema: str
    issuer: str
    issuee: str
    attributes: dict[str, Any]
    edges: dict[str, str]
    raw: str
    #: The registry whose transaction event log records this credential's issuance.
    registry: str = ""
    #: Edge label -> the schema SAID the edge declares its target to have.
    edge_schemas: dict[str, str] | None = None

    @property
    def role(self) -> str | None:
        return self.attributes.get("engagementContextRole") or self.attributes.get("officialRole")

    @property
    def lei(self) -> str | None:
        return self.attributes.get("LEI")


def _json_objects(raw: str) -> Iterator[tuple[int, int]]:
    """Yield the span of every top-level JSON object in a CESR stream.

    A CESR stream interleaves JSON with binary-ish attachment codes, so the objects are found by
    balancing braces rather than by parsing the stream as a whole.
    """
    i = 0
    while i < len(raw):
        start = raw.find("{", i)
        if start < 0:
            return
        depth, k, in_string, escaped = 0, start, False, False
        while k < len(raw):
            char = raw[k]
            if in_string:
                if escaped:
                    escaped = False
                elif char == _BACKSLASH:
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        yield start, k + 1
        i = k + 1


def parse_stream(cesr: str) -> dict[str, Acdc]:
    """Every ACDC in the stream, keyed by SAID.

    Key events and transaction events are skipped: an ACDC is recognised by carrying a registry
    identifier and an attribute block.
    """
    found: dict[str, Acdc] = {}
    for start, end in _json_objects(cesr):
        text = cesr[start:end]
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            continue
        if "ri" not in body or not isinstance(body.get("a"), dict):
            continue
        edges = {
            label: value["n"]
            for label, value in (body.get("e") or {}).items()
            if isinstance(value, dict) and "n" in value
        }
        found[body["d"]] = Acdc(
            said=body["d"],
            schema=body.get("s", ""),
            issuer=body.get("i", ""),
            issuee=body["a"].get("i", ""),
            attributes=body["a"],
            edges=edges,
            raw=text,
            registry=body.get("ri", ""),
            edge_schemas={
                label: value["s"]
                for label, value in (body.get("e") or {}).items()
                if isinstance(value, dict) and "s" in value
            },
        )
    return found


def recompute_said(credential: Acdc) -> str:
    """Recompute a credential's SAID from its own bytes.

    The SAID is a Blake3-256 digest of the credential with its `d` field replaced by filler of the
    same length. Recomputing it over the bytes as they arrived — rather than over a re-serialized
    copy — is what makes the check meaningful: any difference in field order, spacing or content
    changes the digest.
    """
    try:
        import blake3
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ChainInvalid(
            "recomputing a SAID needs blake3: pip install blake3"
        ) from exc

    dummied = credential.raw.replace(f'"d":"{credential.said}"', f'"d":"{_DUMMY}"', 1)
    if dummied == credential.raw:
        dummied = credential.raw.replace(f'"d": "{credential.said}"', f'"d": "{_DUMMY}"', 1)
    if dummied == credential.raw:
        raise ChainInvalid(
            f"could not locate the SAID field in credential {credential.said}",
            credential_said=credential.said,
        )

    digest = blake3.blake3(dummied.encode("utf-8")).digest(length=32)
    # CESR 'E': Blake3-256 digest, 32 raw bytes -> 44 characters.
    return "E" + base64.urlsafe_b64encode(b"\x00" + digest).decode("ascii")[1:]


def walk_chain(
    credentials: dict[str, Acdc], said: str, accepted_roots: list[str]
) -> list[Acdc]:
    """Follow the edges from ``said`` to a root, checking each link on the way.

    Returns the chain, target first. Raises :class:`ChainInvalid` on the first link that does not
    hold, naming which one — a chain that fails in the middle is a different problem from one that
    reaches the wrong root, and the operator's next step differs.
    """
    chain: list[Acdc] = []
    current = credentials.get(said)
    if current is None:
        raise ChainInvalid(
            f"credential {said} is not present in the stream it was presented with",
            credential_said=said,
        )

    seen: set[str] = set()
    while True:
        if current.said in seen:
            raise ChainInvalid(
                f"the chain loops back to {current.said}", credential_said=current.said
            )
        seen.add(current.said)

        recomputed = recompute_said(current)
        if recomputed != current.said:
            raise ChainInvalid(
                f"credential {current.said} does not hash to its own SAID "
                f"(recomputed {recomputed}) — its contents were altered",
                credential_said=current.said,
            )
        chain.append(current)

        if current.issuer in accepted_roots:
            return chain

        if not current.edges:
            # Nothing is wrong with a chain that ends here — it ends at a root this party does not
            # accept. That is a disagreement between organizations, not a defect in the credential,
            # and the specification names it separately because the remedy is different.
            raise UnknownRoot(
                f"the chain ends at {current.said}, issued by {current.issuer}, "
                "which is not an accepted root",
                credential_said=current.said,
            )

        # A vLEI credential carries one chaining edge. Where several exist, follow the one that
        # continues this issuer's authority rather than guessing.
        parent = None
        for label, target in current.edges.items():
            candidate = credentials.get(target)
            if candidate is None:
                raise ChainInvalid(
                    f"credential {current.said} has an edge {label!r} to {target}, "
                    "which was not presented with it",
                    credential_said=current.said,
                )
            if candidate.issuee == current.issuer:
                parent = candidate
                break
        if parent is None:
            labels = ", ".join(sorted(current.edges))
            raise ChainInvalid(
                f"credential {current.said} was issued by {current.issuer}, but none of its "
                f"edges ({labels}) was issued to that identifier — the chain is broken here",
                credential_said=current.said,
            )
        current = parent


def verify_issuance(
    credential: Acdc, messages: list[Message], key_states: StreamKeyStates
) -> None:
    """Establish that ``credential`` was issued by the identifier it names as issuer.

    Three things must line up, and each is checked against bytes that hash to their own SAIDs:

    1. an ``iss`` event for this credential, in the registry the credential names;
    2. that registry's inception (``vcp``), naming this credential's issuer as its issuer;
    3. the issuer's key event log anchoring both — which only the issuer's keys can do.

    Raises :class:`ChainInvalid` naming the first that does not hold.
    """
    said, issuer, registry = credential.said, credential.issuer, credential.registry
    if not registry:
        raise ChainInvalid(
            f"credential {said} names no registry, so its issuance cannot be established",
            credential_said=said,
        )

    inceptions = [m for m in messages if m.ilk == "vcp" and m.body.get("i") == registry]
    if not inceptions:
        raise ChainInvalid(
            f"the registry {registry} that credential {said} names is not in the stream; "
            "its issuance cannot be established",
            credential_said=said,
        )
    vcp = inceptions[0]
    check_said(vcp, ("d", "i"))
    if vcp.body.get("ii") != issuer:
        raise ChainInvalid(
            f"credential {said} names {issuer} as its issuer, but the registry {registry} "
            f"belongs to {vcp.body.get('ii')}",
            credential_said=said,
        )

    state = key_states.resolve(issuer)
    if not state.anchors({"i": registry, "s": "0", "d": vcp.body.get("d")}):
        raise ChainInvalid(
            f"the key event log of {issuer} does not anchor the registry {registry}",
            credential_said=said,
        )

    issuances = [m for m in messages if m.ilk == "iss" and m.body.get("i") == said]
    if not issuances:
        raise ChainInvalid(
            f"no issuance event for credential {said} is in the stream",
            credential_said=said,
        )
    for iss in issuances:
        check_said(iss)
        if iss.body.get("ri") != registry or iss.body.get("s") != "0":
            continue
        if state.anchors({"i": said, "s": "0", "d": iss.body.get("d")}):
            return
    raise ChainInvalid(
        f"the issuance of credential {said} is not anchored in the key event log of its "
        f"issuer {issuer}: whoever wrote it did not hold that issuer's keys",
        credential_said=said,
    )


def verify_vlei_chain(chain: list[Acdc]) -> None:
    """Refuse a chain whose credentials are real but do not mean what the leaf claims.

    Issuance proves each credential was made by the identifier it names. It does not prove the
    chain has the shape the vLEI governance gives it, and two properly issued chains without that
    shape are forgeries of a different kind:

    * a QVI issuing an ECR straight off its own QVI credential — no legal entity in the chain, any
      LEI the QVI cares to write;
    * an LE issuing an ECR that names **another** entity's LEI.

    So: every edge must point at a credential of the type it declares; an ECR or OOR must be issued
    under an LE credential, and an LE credential under a QVI credential; and an ECR or OOR must name
    the same LEI as the LE credential it is issued under.
    """
    for child, parent in zip(chain, chain[1:]):
        declared = {
            (child.edge_schemas or {}).get(label)
            for label, target in child.edges.items()
            if target == parent.said
        } - {None}
        if declared and parent.schema not in declared:
            raise ChainInvalid(
                f"credential {child.said} declares its edge to be a credential of schema "
                f"{sorted(declared)[0]}, but {parent.said} is of schema {parent.schema}",
                credential_said=child.said,
            )
        kind, wanted = _TYPE_OF.get(child.schema), _ISSUED_UNDER.get(_TYPE_OF.get(child.schema, ""))
        if wanted and _TYPE_OF.get(parent.schema) != wanted:
            actual = _TYPE_OF.get(parent.schema) or f"schema {parent.schema}"
            raise ChainInvalid(
                f"an {kind} credential must be issued under an {wanted} credential; "
                f"{child.said} is issued under {actual} {parent.said}",
                credential_said=child.said,
            )
        if kind in ("ECR", "OOR") and child.lei != parent.lei:
            raise ChainInvalid(
                f"the {kind} credential {child.said} names LEI {child.lei}, but the LE credential "
                f"it is issued under is for LEI {parent.lei}",
                credential_said=child.said,
            )
