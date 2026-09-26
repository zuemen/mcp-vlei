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

import logging

from pathlib import Path
from typing import Any, Callable, Sequence

from mcp.server.extension import CallNext, Extension, HandlerResult, ToolBinding
from mcp.server.context import ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, TextContent

from .chain import VLEI_SCHEMAS, Acdc, parse_stream
from .errors import (
    ChainInvalid,
    InvalidSignature,
    MissingCredential,
    RoleMismatch,
    ScopeExceeded,
    VleiError,
)
from .kel import KeyState, WitnessKeyStates
from .signing import (
    DEFAULT_FRESHNESS_SECONDS,
    ReplayCache,
    precheck_request,
    scope_satisfied,
    verify_request,
)
from .report import VerificationReport
from .revocation import TelRevocationChecker
from .verifier import OfflineVerifier, VerificationResult, VleiVerifier, _last_in_chain

EXTENSION_ID = "org.gleif.vlei/identity"
META_CREDENTIAL = "org.gleif.vlei/credential"
META_DELEGATED_AID = "org.gleif.vlei/delegatedAid"
META_SIGNATURE = "org.gleif.vlei/signature"
META_ATTESTATION = "org.gleif.vlei/attestation"
logger = logging.getLogger(__name__)

META_REQUIRES = "org.gleif.vlei/requires"
META_FAILURE = "org.gleif.vlei/failure"
META_REPORT = "org.gleif.vlei/report"
META_CREDENTIAL_SAID = "org.gleif.vlei/credentialSaid"

#: Credential type -> the WebOfTrust/vLEI schema SAID it must carry. A tool's `requires.credential`
#: is checked against the presented credential's `s`, because anything else — the role attribute,
#: the position in the stream — is a claim the credential's author chose.
CREDENTIAL_SCHEMAS = VLEI_SCHEMAS

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
        revocation_source: str = "tel",
        witness_url: str = "",
        requirements: dict[str, dict[str, Any]] | None = None,
        on_decision: Callable[[dict[str, Any]], None] | None = None,
        witness_client: Any = None,
        witness_urls: Sequence[str] | None = None,
    ) -> None:
        self.le_credential = Path(le_credential).read_text(encoding="utf-8").strip()
        self.requires = requires
        self.accepted_roots = list(accepted_roots or [])
        self.well_known = well_known
        self.freshness_seconds = freshness_seconds
        self.verifier = verifier or (
            VleiVerifier(verifier_url, accepted_roots=self.accepted_roots, ttl_ms=ttl_ms)
            if verifier_url
            else None
        )
        #: Establishes the chain, the SAIDs and the root without asking anyone.
        self.offline = OfflineVerifier(self.accepted_roots)

        #: Where revocation is established. See `mcp_vlei.revocation` for why there are three.
        if revocation_source not in ("tel", "verifier", "none"):
            raise ValueError("revocation_source must be 'tel', 'verifier' or 'none'")
        self.revocation_source = revocation_source
        if not witness_url:
            raise ValueError(
                "witness_url is required: a caller's current key state is read from a witness's "
                "copy of its key event log, and without it no request signature can be verified"
            )
        if revocation_source == "verifier" and self.verifier is None:
            raise ValueError(
                "revocation_source='verifier' needs a verifier or a verifier_url; without one, "
                "revocation would silently not be established"
            )
        #: Where each caller's current keys come from. Never from the request: whoever sends a
        #: call would otherwise choose the key it is verified under.
        #: Given several witnesses, each caller's log is compared across them and a fork refused
        #: (see `mcp_vlei.kel.WitnessKeyStates`); given one, there is nothing to compare.
        self.key_states = WitnessKeyStates(witness_urls or witness_url, client=witness_client)
        # The `verifier` source reads each issuer's log too: a vlei-verifier answers about the leaf
        # only, and its own revocation check ships switched off, so a 200 from it establishes
        # authorization, not that no link above the ECR was withdrawn.
        self.tel = (
            TelRevocationChecker(witness_url, client=witness_client)
            if revocation_source in ("tel", "verifier")
            else None
        )
        if revocation_source == "none":
            logger.warning(
                "revocation_source='none': revocation is NOT checked. A withdrawn credential will "
                "be accepted until it expires; the decision record says revocationChecked=false."
            )
        self._replay = ReplayCache(window_seconds=freshness_seconds)
        #: Tool name -> requirement. Populated from the bound server's tool list, or supplied
        #: directly for a deployment that keeps its policy elsewhere (a gateway, for instance).
        self._requirements: dict[str, dict[str, Any]] = dict(requirements or {})
        self._server: Any = None
        #: Called with an audit record for every decision. The reference dashboard uses this to
        #: render each connection's layer-by-layer outcome live.
        self.on_decision = on_decision
        #: The most recent allowed verification, for a caller that wants to print it.
        self.last_report: VerificationReport | None = None

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
            "ttlMs": getattr(self.verifier, "ttl_ms", 0),
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

        if self._server is None and not self._requirements:
            # An extension that cannot read its server's tools cannot tell a protected tool from a
            # public one. Treating every tool as public was the old behaviour; refuse instead.
            self._audit(name, None, allowed=False, note="unbound")
            return _text_result(
                "chain_invalid: this server's vLEI extension was never given its tools — call "
                "vlei.bind(server) after creating the server, or pass requirements=",
                is_error=True,
            )

        requirement = await self.requirement_for(name)
        report = VerificationReport(tool=name)
        if not requirement:
            self._audit(name, None, allowed=True, note="public tool")
            return await call_next(ctx)

        try:
            result = await self._verify(params, meta, requirement, report)
        except VleiError as exc:
            self._audit(name, None, allowed=False, note=exc.layer.value, report=report)
            return _text_result(exc.to_text(), is_error=True, detail=exc.to_detail(), report=report)

        self._audit(name, result, allowed=True, report=report)
        self.last_report = report
        return await call_next(ctx)

    async def verify_call(
        self,
        params: CallToolRequestParams,
        requirement: dict[str, Any] | None = None,
        *,
        report: VerificationReport | None = None,
    ) -> VerificationResult:
        """Verify a ``tools/call`` without executing anything — for a gateway or a console.

        The same checks, in the same order, as a call through :meth:`intercept_tool_call`. Raises
        the :class:`~mcp_vlei.errors.VleiError` for the layer that failed; ``report``, when given,
        is filled in either way, so a caller can show what passed before the failure.
        """
        report = report or VerificationReport(tool=params.name)
        return await self._verify(params, dict(params.meta or {}), requirement, report)

    async def _try_verify(
        self, params: CallToolRequestParams, meta: dict[str, Any]
    ) -> VerificationResult | None:
        try:
            return await self._verify(params, meta, None, VerificationReport(tool="vlei_whoami"))
        except VleiError:
            return None

    async def _verify(
        self,
        params: CallToolRequestParams,
        meta: dict[str, Any],
        requirement: dict[str, Any] | None,
        report: VerificationReport,
    ) -> VerificationResult:
        """Run the checks in order, recording each, and stop at the first failure.

        Who is calling is established before what they presented: the request must verify under the
        **current key state of the AID that signed it**, read from a witness, and that AID must be
        the credential's holder or delegated by them in the holder's own key event log. A key the
        caller sends along is never used — whoever sends a call would otherwise choose the key it
        is verified under, and any credential anyone had seen could be presented as theirs.
        """
        credential = meta.get(META_CREDENTIAL)
        signature = meta.get(META_SIGNATURE)
        delegated = meta.get(META_DELEGATED_AID)

        report.start("credential_present")
        if not credential or not signature:
            missing = "no signature" if credential else "no credential"
            report.failed(
                "credential_present", "missing_credential",
                f"this tool requires an ECR credential and a signed request; the caller presented {missing}",
            )
            raise MissingCredential(
                "this tool requires an ECR credential and a signed request; the caller presented "
                + missing
            )
        # The credential being presented: the one named, or the leaf of the chain. Its issuee is the
        # holder — read from the credential, never from the caller (spec/SPEC.md §Delegation).
        try:
            presented = _presented(credential, meta.get(META_CREDENTIAL_SAID))
        except VleiError as exc:
            report.failed("credential_present", exc.layer.value, exc.message)
            raise
        said, holder = presented.said, presented.issuee
        report.holder_aid = holder
        report.credential_said = said
        report.passed("credential_present")

        signer = signature.get("aid", "") if isinstance(signature, dict) else ""
        if signer and signer != holder:
            report.delegate_aid = signer

        serialized = params.model_dump(by_alias=True, exclude_none=True)
        for name in ("freshness", "digest", "signature"):
            report.start(name)
        try:
            # Everything decidable from the request alone first, so a stale or altered call costs
            # no round trip to a witness.
            precheck_request(signature, serialized, freshness_seconds=self.freshness_seconds)
            state = await self._key_state(signer)
            verify_request(
                signature, "tools/call", serialized, state.keys,
                freshness_seconds=self.freshness_seconds,
                replay_cache=self._replay,
            )
        except VleiError as exc:
            stage = {
                "stale_signature": "freshness",
                "digest_mismatch": "digest",
            }.get(exc.layer.value, "signature")
            for earlier in ("freshness", "digest")[: ("freshness", "digest", "signature").index(stage)]:
                report.passed(earlier)
            report.failed(stage, exc.layer.value, exc.message)
            raise
        report.passed("freshness")
        report.passed("digest")
        report.passed(
            "signature",
            f"under the current key state of {signer} (key event log at sn {state.sn})",
        )

        report.start("delegation")
        try:
            detail = _authorized(signer, delegated, holder, state)
        except VleiError as exc:
            report.failed("delegation", exc.layer.value, exc.message)
            raise
        report.passed("delegation", detail)

        report.start("chain")
        try:
            result = await self.offline.verify(
                credential, said=said, aid=holder, source="presented"
            )
            # A tool that names no credential type still gets the one this server requires: the
            # capability advertises it, and a tool declaring only a role or scope, or no
            # requirement at all (vlei_whoami), must not accept an OOR or LE in its place.
            wanted = (requirement or {}).get("credential") or self.requires
            if wanted:
                _check_type({"credential": wanted}, presented)
        except VleiError as exc:
            report.failed("chain", exc.layer.value, exc.message)
            raise
        result.aid = signer
        report.lei, report.role = result.lei, result.role
        report.passed(
            "chain",
            f"root {result.root_aid}; each issuance anchored in its issuer's key event log",
        )

        # Revocation is the one thing the presented stream cannot settle: it lives in each issuer's
        # transaction event log as it is now, and a holder presenting a withdrawn credential would
        # simply omit the withdrawal. Every link is checked — an ECR under a withdrawn LE stands on
        # nothing, whatever its own log says.
        report.start("revocation")
        try:
            if self.revocation_source == "tel" and self.tel is not None:
                links = result.chain_saids or [result.credential_said or said]
                for link in links:
                    await self.tel.check(link, aid=holder)
                result.revocation_checked = True
                report.passed(
                    "revocation", f"issuers' transaction event logs, all {len(links)} credentials"
                )
            elif self.revocation_source == "verifier" and self.verifier is not None:
                live = await self.verifier.verify(
                    credential, said=said, aid=holder, source="presented"
                )
                links = result.chain_saids or [result.credential_said or said]
                for link in links:
                    await self.tel.check(link, aid=holder)
                # The presented credential decides the entity and the role; the service's summary
                # of its own record may confirm them, never supply or replace them. Letting it
                # fill in a role let an ECR carrying only an `officialRole` pass as that role.
                for what, theirs, ours in (("LEI", live.lei, result.lei),
                                           ("role", live.role, result.role)):
                    if theirs and theirs != ours:
                        raise ChainInvalid(
                            f"the verifier's record gives {what} {theirs!r}; the presented "
                            f"credential carries {ours!r}",
                            aid=holder,
                            credential_said=result.credential_said,
                        )
                result.revocation_checked = True
                report.passed(
                    "revocation",
                    f"vlei-verifier, and issuers' transaction event logs, all {len(links)} credentials",
                )
            else:
                report.skipped("revocation", "no revocation source configured")
        except VleiError as exc:
            report.failed("revocation", exc.layer.value, exc.message)
            raise

        report.start("authority")
        if requirement:
            wanted_role = requirement.get("role")
            if wanted_role and result.role != wanted_role:
                detail = (
                    f"tool requires role {wanted_role!r}; "
                    f"the presented credential carries {result.role!r}"
                )
                report.failed("authority", "role_mismatch", detail)
                raise RoleMismatch(
                    detail, aid=result.aid, credential_said=result.credential_said
                )
            ok, reason = scope_satisfied(requirement.get("scope"), result.scope)
            if not ok:
                report.failed("authority", "scope_exceeded", reason)
                raise ScopeExceeded(
                    reason, aid=result.aid, credential_said=result.credential_said
                )
            report.passed("authority", f"role {result.role!r}")
        else:
            report.skipped("authority", "this tool declares no requirement")
        return result

    async def _key_state(self, aid: str) -> KeyState:
        """The signer's current key state, from a witness — or the reason it could not be had."""
        if not aid:
            raise InvalidSignature("the signature names no signing AID")
        try:
            state = await self.key_states.resolve(aid)
        except ChainInvalid as exc:
            raise InvalidSignature(
                f"the key state of {aid} was not established: {exc.message}", aid=aid
            ) from exc
        if state.threshold != 1:
            raise InvalidSignature(
                f"{aid} requires {state.threshold} signatures; a single-pass request carries one",
                aid=aid,
            )
        return state

    def _audit(
        self,
        tool: str,
        result: VerificationResult | None,
        *,
        allowed: bool,
        note: str = "",
        report: "VerificationReport | None" = None,
    ) -> None:
        if self.on_decision is None:
            return
        record: dict[str, Any] = {"tool": tool, "allowed": allowed, "note": note}
        if report is not None:
            record["report"] = report.as_dict()
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
        # On every record, allowed or not: a reader must be able to tell a decision taken with
        # revocation checked from one taken with it off, and "passed" does not distinguish them.
        record["revocationChecked"] = bool(result and result.revocation_checked)
        self.on_decision(record)


# ------------------------------------------------------------------------------------------- #

def _presented(cesr: Any, said: str | None) -> Acdc:
    """The credential being presented: the one named, or else the leaf of the chain."""
    if not isinstance(cesr, str):
        raise ChainInvalid("the presented credential is not a CESR stream")
    credentials = parse_stream(cesr)
    if not credentials:
        raise ChainInvalid("no credential was found in the presented stream")
    target = said or _last_in_chain(credentials)
    if target not in credentials:
        raise ChainInvalid(
            f"credential {target} is not present in the stream it was presented with",
            credential_said=target,
        )
    presented = credentials[target]
    if not presented.issuee:
        raise ChainInvalid(
            f"credential {target} names no issuee, so it has no holder", credential_said=target
        )
    return presented


def _authorized(signer: str, delegated: Any, holder: str, state: KeyState) -> str:
    """Is the AID that signed allowed to act on the holder's credential? Returns the reason."""
    if delegated and delegated != signer:
        raise InvalidSignature(
            f"delegatedAid names {delegated}, but the request was signed by {signer}", aid=signer
        )
    if signer == holder:
        return "signed by the holder"
    if state.delegator == holder:
        return f"delegated AID {signer}, anchored in the holder's key event log"
    raise InvalidSignature(
        f"the request was signed by {signer}, which is neither the credential's holder {holder} "
        "nor delegated by them in the holder's key event log",
        aid=signer,
    )


def _check_type(requirement: dict[str, Any], presented: Acdc) -> None:
    """The tool's `requires.credential`, against the schema the presented credential carries."""
    wanted = requirement.get("credential")
    if not wanted:
        return
    schema = CREDENTIAL_SCHEMAS.get(wanted)
    if schema is None:
        raise ChainInvalid(f"this tool requires an unknown credential type {wanted!r}")
    if presented.schema != schema:
        actual = next((k for k, v in CREDENTIAL_SCHEMAS.items() if v == presented.schema), None)
        raise ChainInvalid(
            f"this tool requires an {wanted} credential; the presented credential "
            f"{presented.said} is {'an ' + actual if actual else 'of schema ' + presented.schema}",
            credential_said=presented.said,
        )


def _said_of(cesr: str) -> str:
    """The SAID of the credential a stream presents: its leaf. Empty when there is none."""
    try:
        return _presented(cesr, None).said
    except VleiError:
        return ""


def _text_result(
    text: str,
    *,
    is_error: bool = False,
    detail: dict[str, Any] | None = None,
    report: "VerificationReport | None" = None,
) -> CallToolResult:
    result_meta: dict[str, Any] = {}
    if detail:
        result_meta[META_FAILURE] = detail
    if report is not None:
        # The caller gets the whole sequence, not just the verdict: which checks ran, which one
        # stopped the call, and what each cost. The dashboard renders this; a log keeps it.
        result_meta[META_REPORT] = report.as_dict()
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        is_error=is_error,
        meta=result_meta or None,
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
