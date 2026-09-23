"""Server-side extension: ``VleiIdentity``.

Written against the MCP Python SDK 2.2.0 ``mcp.server.extension.Extension`` surface (SEP-2133).

Three lines in a server::

    from mcp_vlei import VleiIdentity

    vlei = VleiIdentity(le_credential="credentials/le.cesr", requires="ECR",
                        verifier_url="http://localhost:7676", accepted_roots=["E..."])
    mcp = MCPServer(name="association", version="0.1.0", extensions=[vlei])
    vlei.bind(mcp)      # lets the extension read each tool's declared requirement

Everything else follows from what the tools already declare. A tool states its requirement in its
own ``_meta``; the extension reads it and enforces it. Tool code contains no vLEI logic and makes
no verification decisions — that separation is what makes the same requirement enforceable
in-process, at a gateway, or by a third party without the tool changing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Sequence

from mcp.server.extension import CallNext, Extension, HandlerResult, ToolBinding
from mcp.server.context import ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, TextContent

from .errors import (
    MissingCredential,
    RoleMismatch,
    ScopeExceeded,
    VleiError,
)
from .signing import DEFAULT_FRESHNESS_SECONDS, ReplayCache, scope_satisfied, verify_request
from .verifier import VerificationResult, VleiVerifier

EXTENSION_ID = "org.gleif.vlei/identity"
META_CREDENTIAL = "org.gleif.vlei/credential"
META_DELEGATED_AID = "org.gleif.vlei/delegatedAid"
META_SIGNATURE = "org.gleif.vlei/signature"
META_ATTESTATION = "org.gleif.vlei/attestation"
META_REQUIRES = "org.gleif.vlei/requires"
META_FAILURE = "org.gleif.vlei/failure"

__all__ = ["VleiIdentity", "EXTENSION_ID"]


class VleiIdentity(Extension):
    """Presents this server's LE credential and enforces per-tool ECR requirements."""

    identifier = EXTENSION_ID

    def __init__(
        self,
        *,
        le_credential: str | Path,
        verifier_url: str = "",
        accepted_roots: list[str] | None = None,
        requires: str | None = "ECR",
        well_known: str | None = None,
        freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
        ttl_ms: int = 30_000,
        verifier: VleiVerifier | None = None,
        requirements: dict[str, dict[str, Any]] | None = None,
        on_decision: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.le_credential = Path(le_credential).read_text(encoding="utf-8").strip()
        self.requires = requires
        self.accepted_roots = list(accepted_roots or [])
        self.well_known = well_known
        self.freshness_seconds = freshness_seconds
        self.verifier = verifier or VleiVerifier(
            verifier_url, accepted_roots=self.accepted_roots, ttl_ms=ttl_ms
        )
        self._replay = ReplayCache(window_seconds=freshness_seconds)
        #: Tool name -> requirement. Populated from the bound server's tool list, or supplied
        #: directly for a deployment that keeps its policy elsewhere (a gateway, for instance).
        self._requirements: dict[str, dict[str, Any]] = dict(requirements or {})
        self._server: Any = None
        #: Called with an audit record for every decision. The reference dashboard uses this to
        #: render each connection's layer-by-layer outcome live.
        self.on_decision = on_decision

    def bind(self, server: Any) -> None:
        """Give the extension the server whose tools it guards.

        An extension is constructed before the server that holds it, so it cannot read the tool
        registry at construction time. Binding afterwards is explicit and keeps the requirement in
        one place — the tool's own ``_meta`` — instead of duplicating it into the extension.
        """
        self._server = server

    # ------------------------------------------------------------------------------------- #
    # Capability declaration
    # ------------------------------------------------------------------------------------- #

    def settings(self) -> dict[str, Any]:
        """Advertised at ``capabilities.extensions["org.gleif.vlei/identity"]``."""
        capability: dict[str, Any] = {
            "presents": ["LE"],
            "acceptedRoots": self.accepted_roots,
            "signatureAlgs": ["Ed25519"],
            "ttlMs": self.verifier.ttl_ms,
        }
        if self.requires:
            capability["requires"] = self.requires
        if self.well_known:
            capability["discovery"] = {"wellKnown": self.well_known}
        return capability

    def discover_meta(self) -> dict[str, Any]:
        """``_meta`` carrying this server's LE credential.

        ``Implementation`` has no ``_meta`` in core MCP, which is the structural reason the
        credential travels here and at ``/.well-known/vlei`` rather than on the party object.
        """
        return {META_CREDENTIAL: self.le_credential}

    def well_known_document(self) -> dict[str, Any]:
        """Body for ``/.well-known/vlei`` — the passive-verification location, mode (a).

        Published separately from the session so a counterparty can check who operates this server
        *before* connecting to it.
        """
        return {
            "extension": EXTENSION_ID,
            "credential": self.le_credential,
            "acceptedRoots": self.accepted_roots,
            "signatureAlgs": ["Ed25519"],
        }

    def tools(self) -> Sequence[ToolBinding]:
        """One diagnostic tool, contributed by the extension itself.

        Public by design: it reports what the caller presented, which is useless to an attacker and
        invaluable when a deployment is misconfigured.
        """
        return (
            ToolBinding(
                fn=self._whoami_tool,
                kwargs={"name": "vlei_whoami", "title": "Who am I, as this server sees me"},
            ),
        )

    def _whoami_tool(self) -> str:
        """Report the organizational identity this server established for the caller.

        Returns the LEI, role, holder AID, delegated AID, credential SAID and the root the chain
        terminated at — or `unverified` when no credential was presented.
        """
        # The body is replaced per-request by intercept_tool_call, which is the only place with
        # access to the caller's credential. This text is the fallback when it is called outside
        # that path.
        return _whoami_text(None)

    # ------------------------------------------------------------------------------------- #
    # Enforcement
    # ------------------------------------------------------------------------------------- #

    async def requirement_for(self, name: str) -> dict[str, Any] | None:
        """The ``org.gleif.vlei/requires`` a tool declares, read from the server's registry."""
        if name in self._requirements:
            return self._requirements[name]
        if self._server is None:
            return None
        for tool in await self._server.list_tools():
            meta = getattr(tool, "meta", None) or getattr(tool, "_meta", None) or {}
            requirement = meta.get(META_REQUIRES)
            if requirement:
                self._requirements[getattr(tool, "name", "")] = requirement
        return self._requirements.get(name)

    async def intercept_tool_call(
        self,
        params: CallToolRequestParams,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        """Verify before the tool runs; never let a tool see an unverified caller as verified."""
        name = params.name
        meta: dict[str, Any] = dict(params.meta or {})

        if name == "_whoami_tool" or name == "vlei_whoami":
            result = await self._try_verify(params, meta)
            return _text_result(_whoami_text(result))

        requirement = await self.requirement_for(name)
        if not requirement:
            self._audit(name, None, allowed=True, note="public tool")
            return await call_next(ctx)

        try:
            result = await self._verify(params, meta, requirement)
        except VleiError as exc:
            self._audit(name, None, allowed=False, note=exc.layer.value)
            return _text_result(exc.to_text(), is_error=True, detail=exc.to_detail())

        self._audit(name, result, allowed=True)
        return await call_next(ctx)

    async def _try_verify(
        self, params: CallToolRequestParams, meta: dict[str, Any]
    ) -> VerificationResult | None:
        try:
            return await self._verify(params, meta, None)
        except VleiError:
            return None

    async def _verify(
        self,
        params: CallToolRequestParams,
        meta: dict[str, Any],
        requirement: dict[str, Any] | None,
    ) -> VerificationResult:
        credential = meta.get(META_CREDENTIAL)
        signature = meta.get(META_SIGNATURE)
        delegated = meta.get(META_DELEGATED_AID)

        if not credential or not signature:
            raise MissingCredential(
                "this tool requires an ECR credential and a signed request; the caller presented "
                + ("no signature" if credential else "no credential")
            )

        aid = signature.get("aid", "")
        said = meta.get("org.gleif.vlei/credentialSaid") or _said_of(credential)

        # Ask about the credential's **issuee**, not the signing AID. The agent signs with its
        # delegated AID, but the credential was issued to — and presented by — the person. The
        # verifier's record is keyed by that holder, so querying the delegate asks about an AID it
        # has never seen.
        #
        # The issuee is read from the credential itself rather than taken from `_meta`, so a caller
        # cannot point the question at someone else's record.
        holder = _issuee_of(credential, said) or aid

        # Chain, revocation and root first: a signature that verifies under a revoked credential
        # is still worthless, and checking it first would report the wrong layer.
        result = await self.verifier.verify(
            credential, said=said, aid=holder, source="presented"
        )
        if delegated and delegated != holder:
            # Record who actually acted, while the identity established stays the holder's.
            result.aid = delegated

        verkey = meta.get("org.gleif.vlei/verkey")
        if verkey:
            verify_request(
                signature,
                "tools/call",
                params.model_dump(by_alias=True, exclude_none=True),
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


def _issuee_of(cesr: str, said: str = "") -> str:
    """The AID a credential was issued to — the `i` inside its attribute block.

    A `--full` CESR export carries the whole chain, so the first attribute block belongs to the
    QVI credential, not the one being presented. Anchor on the credential whose `d` is the SAID in
    question and read the attribute block that follows it.
    """
    import re

    text = cesr
    if said:
        anchor = text.find(f'"d":"{said}"')
        if anchor < 0:
            anchor = text.find(f'"d": "{said}"')
        if anchor >= 0:
            text = text[anchor:]

    match = re.search(r'"a"\s*:\s*\{[^{}]*?"i"\s*:\s*"([A-Za-z0-9_-]{44})"', text)
    return match.group(1) if match else ""


def _text_result(
    text: str, *, is_error: bool = False, detail: dict[str, Any] | None = None
) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        is_error=is_error,
        meta={META_FAILURE: detail} if detail else None,
    )


def _whoami_text(result: VerificationResult | None) -> str:
    if result is None:
        return (
            "unverified: no organizational identity was established for this caller. "
            "Public tools remain available; tools declaring org.gleif.vlei/requires do not."
        )
    return "\n".join(
        [
            f"LEI:            {result.lei}",
            f"role:           {result.role or '(none)'}",
            f"holder AID:     {result.holder_aid}",
            f"delegate AID:   {result.aid if result.aid != result.holder_aid else '(none)'}",
            f"credential:     {result.credential_said}",
            f"root of trust:  {result.root_aid or '(as configured)'}",
            f"source:         {result.source}",
        ]
    )
