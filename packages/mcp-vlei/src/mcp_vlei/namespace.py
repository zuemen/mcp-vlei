"""The extension's namespace — provisional, and configuration rather than a constant.

This draft uses ``org.gleif.vlei`` as a provisional, demonstration namespace. It has not been
reviewed or endorsed by GLEIF. Reverse-domain prefixes conventionally belong to the domain's owner,
so the final name is expected to follow GLEIF's view — it may stay as is, or move to another prefix.
Every ``_meta`` key and the extension identifier are built here, from ``MCP_VLEI_NAMESPACE`` when
it is set, so a change of name is a change of configuration::

    MCP_VLEI_NAMESPACE=net.zuemen.vlei python examples/association-server/server.py

Both parties must use the same namespace. A server that requires the extension treats a client
that declared it under another namespace exactly as one that did not declare it: ``-32021``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

__all__ = ["DEFAULT", "ENV", "Keys", "current", "keys", "valid"]

#: The provisional default. Not a claim about who owns or has approved the name.
DEFAULT = "org.gleif.vlei"
ENV = "MCP_VLEI_NAMESPACE"

#: Reverse-domain: two or more dot-separated labels, each starting with a letter and ending with a
#: letter or digit (the `_meta` prefix grammar of MCP 2026-07-28, as the SDK validates it). MCP
#: reserves every prefix whose second label is ``modelcontextprotocol`` or ``mcp``
#: (``io.modelcontextprotocol``, ``dev.mcp``); ``com.example.mcp`` is not reserved. Reserved
#: prefixes are refused.
_LABEL = r"[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_NAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})+")
_RESERVED_SECOND = {"mcp", "modelcontextprotocol"}


def valid(namespace: str) -> bool:
    """A reverse-domain name that MCP does not reserve."""
    if not isinstance(namespace, str) or not _NAME.fullmatch(namespace) or len(namespace) > 200:
        return False
    return namespace.split(".")[1].lower() not in _RESERVED_SECOND


def current() -> str:
    """The namespace in effect: ``MCP_VLEI_NAMESPACE``, or the provisional default."""
    namespace = os.environ.get(ENV, "").strip() or DEFAULT
    if not valid(namespace):
        raise ValueError(
            f"{ENV}={namespace!r} is not a usable namespace: a reverse-domain name whose second "
            "label is not 'mcp' or 'modelcontextprotocol' (MCP reserves those)"
        )
    return namespace


@dataclass(frozen=True)
class Keys:
    """Every name this extension puts on the wire, under one namespace."""

    namespace: str

    def __post_init__(self) -> None:
        if not valid(self.namespace):
            raise ValueError(f"{self.namespace!r} is not a usable namespace (see mcp_vlei.namespace)")

    def key(self, name: str) -> str:
        return f"{self.namespace}/{name}"

    @property
    def extension(self) -> str:
        """The extension identifier, advertised in ``capabilities.extensions``."""
        return self.key("identity")

    @property
    def credential(self) -> str:
        return self.key("credential")

    @property
    def credential_said(self) -> str:
        return self.key("credentialSaid")

    @property
    def delegated_aid(self) -> str:
        return self.key("delegatedAid")

    @property
    def signature(self) -> str:
        return self.key("signature")

    @property
    def attestation(self) -> str:
        return self.key("attestation")

    @property
    def requires(self) -> str:
        return self.key("requires")

    @property
    def failure(self) -> str:
        return self.key("failure")

    @property
    def report(self) -> str:
        return self.key("report")

    @property
    def request_keys(self) -> tuple[str, ...]:
        """The keys a caller presents in ``params._meta``."""
        return (self.credential, self.credential_said, self.delegated_aid, self.signature)


def keys(namespace: str | None = None) -> Keys:
    """The keys under `namespace`, or under the namespace in effect."""
    return Keys(namespace or current())
