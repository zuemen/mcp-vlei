"""Failure layers and exceptions for the org.gleif.vlei/identity extension.

Naming the failure layer is normative, not cosmetic: the correct recovery differs per layer, and
``skills/vlei-identity/SKILL.md`` keys its behavior off these exact strings. A verifier that
collapses everything into "access denied" makes the skill impossible to write and the demo
impossible to narrate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = [
    "FailureLayer",
    "VleiError",
    "ExtensionRequired",
    "InvalidSignature",
    "StaleSignature",
    "DigestMismatch",
    "ChainInvalid",
    "Revoked",
    "RoleMismatch",
    "ScopeExceeded",
    "UnknownRoot",
    "MissingCredential",
    "EXTENSION_REQUIRED_CODE",
]

#: JSON-RPC error code used when a server requires the extension and the client did not declare it.
EXTENSION_REQUIRED_CODE = -32021


class FailureLayer(str, Enum):
    """The layer at which verification failed. See ``spec/SPEC.md`` §Errors."""

    INVALID_SIGNATURE = "invalid_signature"
    STALE_SIGNATURE = "stale_signature"
    DIGEST_MISMATCH = "digest_mismatch"
    CHAIN_INVALID = "chain_invalid"
    REVOKED = "revoked"
    ROLE_MISMATCH = "role_mismatch"
    SCOPE_EXCEEDED = "scope_exceeded"
    UNKNOWN_ROOT = "unknown_root"

    #: Not a verification failure: the caller presented nothing at all.
    MISSING_CREDENTIAL = "missing_credential"

    @property
    def retryable(self) -> bool:
        """Only a stale signature is worth retrying, and only once.

        Every other layer is a state of the world that a retry cannot change: a revoked credential
        stays revoked, a role that does not match still does not match, and a digest mismatch means
        the request was altered after signing.
        """
        return self is FailureLayer.STALE_SIGNATURE


@dataclass
class VleiError(Exception):
    """Base class. Carries the failure layer so callers never have to parse prose."""

    layer: FailureLayer
    message: str
    aid: str | None = None
    credential_said: str | None = None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.layer.value}] {self.message}"

    def to_detail(self) -> dict[str, Any]:
        """The structured form a server attaches alongside the human-readable text."""
        detail: dict[str, Any] = {"layer": self.layer.value, "message": self.message}
        if self.aid:
            detail["aid"] = self.aid
        if self.credential_said:
            detail["credentialSaid"] = self.credential_said
        return detail

    def to_text(self) -> str:
        """The text of the ``isError: true`` tool result.

        The layer is placed first and unadorned so that a model reading the result can key off it
        without heuristics.
        """
        return f"{self.layer.value}: {self.message}"


class ExtensionRequired(Exception):
    """Raised when the server requires the extension and the client did not declare it.

    Distinct from :class:`VleiError` on purpose: this is a configuration problem at ``initialize``,
    not a rejected credential, and it is reported as a JSON-RPC error rather than a tool result.
    """

    def __init__(self, capabilities: list[str] | None = None) -> None:
        self.capabilities = capabilities or ["org.gleif.vlei/identity"]
        super().__init__(
            "server requires capabilities not declared by the client: "
            + ", ".join(self.capabilities)
        )

    def to_error(self) -> dict[str, Any]:
        return {
            "code": EXTENSION_REQUIRED_CODE,
            "message": str(self),
            "data": {"requiredCapabilities": self.capabilities},
        }


def _layered(name: str, layer: FailureLayer) -> type[VleiError]:
    def __init__(  # noqa: N807
        self: VleiError,
        message: str,
        *,
        aid: str | None = None,
        credential_said: str | None = None,
    ) -> None:
        VleiError.__init__(self, layer, message, aid, credential_said)

    return type(name, (VleiError,), {"__init__": __init__, "layer_const": layer})


InvalidSignature = _layered("InvalidSignature", FailureLayer.INVALID_SIGNATURE)
StaleSignature = _layered("StaleSignature", FailureLayer.STALE_SIGNATURE)
DigestMismatch = _layered("DigestMismatch", FailureLayer.DIGEST_MISMATCH)
ChainInvalid = _layered("ChainInvalid", FailureLayer.CHAIN_INVALID)
Revoked = _layered("Revoked", FailureLayer.REVOKED)
RoleMismatch = _layered("RoleMismatch", FailureLayer.ROLE_MISMATCH)
ScopeExceeded = _layered("ScopeExceeded", FailureLayer.SCOPE_EXCEEDED)
UnknownRoot = _layered("UnknownRoot", FailureLayer.UNKNOWN_ROOT)
MissingCredential = _layered("MissingCredential", FailureLayer.MISSING_CREDENTIAL)
