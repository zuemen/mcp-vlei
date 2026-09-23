"""Server-side extension: ``VleiIdentity``.

Three lines in a server::

    from mcp_vlei import VleiIdentity

    mcp = MCPServer(name="association", version="0.1.0", extensions=[VleiIdentity(
        le_credential="credentials/le.cesr", requires="ECR",
        verifier_url="http://localhost:7676", accepted_roots=["E..."])])

Everything else follows from what the tools already declare. A tool states its requirement in its
own ``_meta``; the extension reads it and enforces it. Tool code contains no vLEI logic and no
verification decisions — that separation is what makes the same requirement enforceable in-process,
at a gateway, or by a third party without the tool changing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable, Sequence

from .errors import (
    EXTENSION_REQUIRED_CODE,
    MissingCredential,
    RoleMismatch,
    ScopeExceeded,
    VleiError,
)
from .signing import DEFAULT_FRESHNESS_SECONDS, ReplayCache, scope_satisfied, verify_request
from .verifier import VerificationResult, VleiVerifier

try:  # MCP Python SDK 2.2.0+, SEP-2133
    from mcp.server.extension import Extension as _Extension
except ImportError:  # pragma: no cover - lets the package import without the SDK present
    class _Extension:  # type: ignore[no-redef]
        """Shim matching the SEP-2133 surface this extension uses."""

        def settings(self) -> dict[str, Any]: ...
        def tools(self) -> Sequence[Any]: return ()
        async def intercept_tool_call(self, ctx, call_next): return await call_next(ctx)


EXTENSION_ID = "org.gleif.vlei/identity"
META_CREDENTIAL = "org.gleif.vlei/credential"
META_DELEGATED_AID = "org.gleif.vlei/delegatedAid"
META_SIGNATURE = "org.gleif.vlei/signature"
META_ATTESTATION = "org.gleif.vlei/attestation"
META_REQUIRES = "org.gleif.vlei/requires"

__all__ = ["VleiIdentity", "EXTENSION_ID"]


class VleiIdentity(_Extension):
    """Presents this server's LE credential and enforces per-tool ECR requirements."""

    def __init__(
        self,
        *,
        le_credential: str | Path,
        verifier_url: str,
        accepted_roots: list[str],
        requires: str | None = "ECR",
        well_known: str | None = None,
        freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
        ttl_ms: int = 30_000,
        verifier: VleiVerifier | None = None,
        on_decision: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.le_credential = Path(le_credential).read_text(encoding="utf-8").strip()
        self.requires = requires
        self.accepted_roots = list(accepted_roots)
        self.well_known = well_known
        self.freshness_seconds = freshness_seconds
        self.verifier = verifier or VleiVerifier(
            verifier_url, accepted_roots=accepted_roots, ttl_ms=ttl_ms
        )
        self._replay = ReplayCache(window_seconds=freshness_seconds)
        #: Called with an audit record for every decision. The reference dashboard uses this to
        #: render each connection's layer-by-layer outcome live.
        self.on_decision = on_decision

    # ------------------------------------------------------------------------------------- #
    # Capability declaration
    # ------------------------------------------------------------------------------------- #

    def settings(self) -> dict[str, Any]:
        """The ``Implementation.extensions["org.gleif.vlei/identity"]`` value."""
        capability: dict[str, Any] = {
            "presents": ["LE"],
            "acceptedRoots": self.accepted_roots,
            "signatureAlgs": ["Ed25519"],
        }
        if self.requires:
            capability["requires"] = self.requires
        if self.well_known:
            capability["discovery"] = {"wellKnown": self.well_known}
        return {EXTENSION_ID: capability}

    def discover_meta(self) -> dict[str, Any]:
        """``_meta`` for the ``server/discover`` result: the server's LE credential.

        ``Implementation`` has no ``_meta`` in core MCP, which is the structural reason the
        credential travels here and at ``/.well-known/vlei`` rather than on the party object.
        """
        return {META_CREDENTIAL: self.le_credential}

    def well_known_document(self) -> dict[str, Any]:
        """Body for ``/.well-known/vlei`` — the passive-verification location, mode (a).

        Published separately from ``discover`` so that a counterparty can check who operates this
        server *before* connecting to it.
        """
        return {
            "extension": EXTENSION_ID,
            "credential": self.le_credential,
            "acceptedRoots": self.accepted_roots,
            "signatureAlgs": ["Ed25519"],
        }

    def tools(self) -> Sequence[Any]:
        """One diagnostic tool. Public by design: it reports what the caller presented, which is
        useless to an attacker and invaluable when a deployment is misconfigured."""
        return [
            {
                "name": "vlei_whoami",
                "title": "Who am I, as this server sees me",
                "description": (
                    "Report the organizational identity this server established for the caller: "
                    "LEI, role, holder AID, delegated AID, credential SAID, and which root the "
                    "chain terminated at. Returns 'unverified' when no credential was presented."
                ),
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]

    # ------------------------------------------------------------------------------------- #
    # Enforcement
    # ------------------------------------------------------------------------------------- #

    @staticmethod
    def requirement_for(tool: Any) -> dict[str, Any] | None:
        meta = getattr(tool, "_meta", None)
        if meta is None and isinstance(tool, dict):
            meta = tool.get("_meta")
        return (meta or {}).get(META_REQUIRES)

    async def intercept_tool_call(
        self,
        ctx: Any,
        call_next: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        """Verify before the tool runs; never let the tool see an unverified caller as verified."""
        tool = getattr(ctx, "tool", None)
        requirement = self.requirement_for(tool) if tool is not None else None
        meta = dict(getattr(ctx, "meta", None) or {})
        name = getattr(ctx, "tool_name", None) or getattr(tool, "name", "<unknown>")

        if name == "vlei_whoami":
            result = await self._try_verify(ctx, meta, requirement=None)
            return _text(_whoami_text(result))

        if not requirement:
            self._audit(name, None, allowed=True, note="public tool")
            return await call_next(ctx)

        try:
            result = await self._verify(ctx, meta, requirement)
        except VleiError as exc:
            self._audit(name, None, allowed=False, note=exc.layer.value)
            return _text(exc.to_text(), is_error=True, detail=exc.to_detail())

        setattr(ctx, "vlei", result)
        self._audit(name, result, allowed=True)
        return await call_next(ctx)

    async def _try_verify(
        self, ctx: Any, meta: dict[str, Any], requirement: dict[str, Any] | None
    ) -> VerificationResult | None:
        try:
            return await self._verify(ctx, meta, requirement)
        except VleiError:
            return None

    async def _verify(
        self,
        ctx: Any,
        meta: dict[str, Any],
        requirement: dict[str, Any] | None,
    ) -> VerificationResult:
        credential = meta.get(META_CREDENTIAL)
        signature = meta.get(META_SIGNATURE)
        delegated = meta.get(META_DELEGATED_AID)

        if not credential or not signature:
            raise MissingCredential(
                "this tool requires an ECR credential and a signed request; "
                "the caller presented "
                + ("no signature" if credential else "no credential")
            )

        aid = signature.get("aid", "")
        said = meta.get("org.gleif.vlei/credentialSaid") or _said_of(credential)

        # Chain, revocation and root first: a signature that verifies under a revoked credential
        # is still worthless, and checking it first would report the wrong layer.
        result = await self.verifier.verify(
            credential,
            said=said,
            aid=delegated or aid,
            source="presented",
        )

        verkey = getattr(ctx, "caller_verkey", None) or meta.get("org.gleif.vlei/verkey")
        if verkey:
            verify_request(
                signature,
                getattr(ctx, "method", "tools/call"),
                getattr(ctx, "params", None),
                verkey,
                freshness_seconds=self.freshness_seconds,
                replay_cache=self._replay,
            )

        if requirement:
            wanted_role = requirement.get("role")
            if wanted_role and result.role != wanted_role:
                raise RoleMismatch(
                    f"tool requires role {wanted_role!r}; "
                    f"the presented credential carries {result.role!r}",
                    aid=result.aid,
                    credential_said=result.credential_said,
                )
            ok, reason = scope_satisfied(requirement.get("scope"), result.scope)
            if not ok:
                raise ScopeExceeded(
                    reason, aid=result.aid, credential_said=result.credential_said
                )

        return result

    def _audit(
        self,
        tool: str,
        result: VerificationResult | None,
        *,
        allowed: bool,
        note: str = "",
    ) -> None:
        if self.on_decision is None:
            return
        record: dict[str, Any] = {"tool": tool, "allowed": allowed, "note": note}
        if result:
            record |= {
                "lei": result.lei,
                "role": result.role,
                "holderAid": result.holder_aid,
                "delegateAid": result.aid if result.aid != result.holder_aid else None,
                "credentialSaid": result.credential_said,
                "source": result.source,
            }
        else:
            record["identity"] = "unverified"
        self.on_decision(record)


# ------------------------------------------------------------------------------------------- #

def _said_of(cesr: str) -> str:
    """Best-effort SAID extraction from a CESR stream, for the presentation URL."""
    import re

    match = re.search(r'"d"\s*:\s*"([A-Za-z0-9_-]{44})"', cesr)
    if match:
        return match.group(1)
    match = re.search(r"[EF][A-Za-z0-9_-]{43}", cesr)
    return match.group(0) if match else ""


def _text(text: str, *, is_error: bool = False, detail: dict[str, Any] | None = None) -> dict:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if detail:
        result["_meta"] = {"org.gleif.vlei/failure": detail}
    return result


def _whoami_text(result: VerificationResult | None) -> str:
    if result is None:
        return (
            "unverified: no organizational identity was established for this caller. "
            "Public tools remain available; tools declaring org.gleif.vlei/requires do not."
        )
    lines = [
        f"LEI:            {result.lei}",
        f"role:           {result.role or '(none)'}",
        f"holder AID:     {result.holder_aid}",
        f"delegate AID:   {result.aid if result.aid != result.holder_aid else '(none)'}",
        f"credential:     {result.credential_said}",
        f"root of trust:  {result.root_aid or '(as configured)'}",
        f"source:         {result.source}",
    ]
    return "\n".join(lines)
