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
* the chain terminates at an issuer the relying party accepts as a root.

What is **not** established here, and is reported rather than assumed:

* **issuer signatures.** Verifying them means replaying each issuer's key event log to find the key
  that was current when the credential was issued. That is keripy's job, and it is not reimplemented
  here.
* **revocation.** Revocation lives in the issuer's transaction event log, and reaching it is exactly
  what "offline" rules out.

A chain that passes these checks has not been forged after the fact — the SAIDs are digests over the
content, so altering any field breaks them — but it could have been fabricated wholesale by someone
who never held the issuers' keys. That is why the result says so, and why
:class:`~mcp_vlei.verifier.VleiVerifier` remains the right tool whenever revocation matters.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Iterator

from .errors import ChainInvalid

__all__ = ["Acdc", "parse_stream", "recompute_said", "walk_chain"]

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
            raise ChainInvalid(
                f"the chain ends at {current.said}, issued by {current.issuer}, "
                "which is not an accepted root and has no edge to follow",
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
