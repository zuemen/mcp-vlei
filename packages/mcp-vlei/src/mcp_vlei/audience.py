"""Who a call is for: the recipient's LE AID and the endpoint the call is sent to (v0.3).

A v0.2 signature said what was called and when, and nothing about where. Any server that received
one — or anyone who read its logs — could send it to another server inside the freshness window.
A v0.3 signature names its recipient twice: the **AID** of the legal entity whose credential the
client verified for that server, and the **URL** the client sends the call to. The first is the
accountable party; the second tells apart two servers — or two routes of one gateway — that the
same entity operates.

* :class:`Audience` is the client's side: one recipient, put into the signature.
* :class:`Recipient` is the verifier's side: who it is (its LE's issuee) and every URL its callers
  use. It refuses a signature made for anyone else with ``audience_mismatch``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from .errors import AudienceMismatch

__all__ = ["Audience", "Recipient", "normalise_endpoint", "is_qb64_identifier"]

#: A 44-character CESR identifier (an AID, or a SAID): qualified base64, URL-safe alphabet.
_QB64_44 = re.compile(r"[A-Za-z0-9_-]{44}")
_DEFAULT_PORTS = {"http": 80, "https": 443}
#: A percent-encoded octet. ``%2f`` and ``%2F`` are the same octet (RFC 3986 §6.2.2.1).
_PERCENT_TRIPLET = re.compile(r"%[0-9A-Fa-f]{2}")


def is_qb64_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_QB64_44.fullmatch(value))


def normalise_endpoint(url: str) -> str:
    """The one spelling of an endpoint URL that a client signs and a verifier compares.

    Scheme and host lower-case, the host IDNA-encoded, the default port dropped, an empty path
    written ``/``, percent-encoded octets in upper case (``%2f`` is ``%2F``). User-info, a query or a fragment is refused rather than dropped: an endpoint is
    a place, and a URL carrying more than a place is not one the two sides can agree on.
    Raises ``ValueError``.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("an endpoint URL is required")
    url = url.strip()
    if "?" in url or "#" in url:
        raise ValueError(f"{url!r}: an endpoint URL carries no query or fragment")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"{url!r}: only http and https endpoints are signed for")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{url!r}: an endpoint URL carries no user-info")
    host = parts.hostname or ""
    if not host:
        raise ValueError(f"{url!r}: no host")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"{url!r}: the host is not a valid IDNA name") from exc
    if ":" in host:  # an IPv6 literal; urlsplit removed the brackets
        host = f"[{host}]"
    port = parts.port  # ValueError on a malformed port
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    if not path.isascii():
        raise ValueError(f"{url!r}: percent-encode the path; the signed form is ASCII")
    path = _PERCENT_TRIPLET.sub(lambda m: m.group(0).upper(), path)
    return f"{scheme}://{netloc}{path}"


@dataclass(frozen=True)
class Audience:
    """One recipient, as a client signs for it."""

    aid: str
    url: str

    def __post_init__(self) -> None:
        if not is_qb64_identifier(self.aid):
            raise ValueError(f"audience aid {self.aid!r} is not a 44-character CESR identifier")
        object.__setattr__(self, "url", normalise_endpoint(self.url))

    def to_wire(self) -> dict[str, str]:
        return {"aid": self.aid, "url": self.url}


@dataclass(frozen=True)
class Recipient:
    """Who a verifier is: the issuee of its own LE credential, and the URLs its callers use.

    A server reached as ``http://localhost:3000/mcp`` and as ``http://127.0.0.1:3000/mcp`` lists
    both: they are different strings, and a signature names one.
    """

    aid: str
    urls: tuple[str, ...]

    def __post_init__(self) -> None:
        if not is_qb64_identifier(self.aid):
            raise ValueError(f"recipient aid {self.aid!r} is not a 44-character CESR identifier")
        urls = tuple(dict.fromkeys(normalise_endpoint(u) for u in self.urls))
        if not urls:
            raise ValueError(
                "a recipient needs at least one endpoint URL: a verifier that cannot say where it "
                "is reached cannot check where a call was meant to go"
            )
        object.__setattr__(self, "urls", urls)

    def check(self, aud: Any, *, signer: str | None = None) -> str:
        """Raise ``AudienceMismatch`` unless ``aud`` names this recipient; return the URL matched."""
        if not isinstance(aud, dict) or set(aud) != {"aid", "url"} or not all(
            isinstance(aud[k], str) for k in aud
        ):
            raise AudienceMismatch("the signature's aud is not {aid, url}", aid=signer)
        if aud["aid"] != self.aid:
            raise AudienceMismatch(
                f"the call was signed for {aud['aid']}, not for this server ({self.aid}): it was "
                "meant for another recipient, or replayed from one",
                aid=signer,
            )
        try:
            url = normalise_endpoint(aud["url"])
        except ValueError as exc:
            raise AudienceMismatch(
                f"the call was signed for an unusable URL ({exc})", aid=signer
            ) from exc
        if url not in self.urls:
            # Not this server's URLs: the caller is not verified yet, and the list (loopback and
            # tunnel addresses among them) is nothing it needs. Nor an unbounded echo of its own.
            shown = url if len(url) <= 200 else url[:200] + "…"
            raise AudienceMismatch(
                f"the call was signed for {shown}, which is not this server's endpoint: it was "
                "meant for another endpoint, or replayed from one",
                aid=signer,
            )
        return url

    @classmethod
    def of(cls, aid: str, urls: Iterable[str]) -> "Recipient":
        return cls(aid=aid, urls=tuple(urls))
