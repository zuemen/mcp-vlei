"""An MCP server for the org.gleif.vlei/identity extension, written from the skill alone.

Source of truth: ``skills/implementing-vlei/SKILL.md``. Nothing in this file was taken from the
reference extension (``mcp_vlei.extension``) or client (``mcp_vlei.client``); the verification
pipeline is assembled here from the components the skill names, in the order the skill fixes
(section 4, checks 0-10), and failures are reported in the two shapes of section 5.

Tools
-----
``list_events``    public. Served to any client, including one that never heard of the extension.
``submit_filing``  protected. Requires ``{"credential": "ECR", "role": $VLEI_ROLE}``.

Configuration (environment only)
--------------------------------
``VLEI_LE_CREDENTIAL``   path to this server's LE credential, a CESR stream with its chain (required)
``VLEI_ACCEPTED_ROOTS``  comma-separated root AIDs; empty is refused, never read as "any" (required)
``VLEI_WITNESS_URL``     keripy witness used for KELs (check 3) and TELs (check 9) (required)
``VLEI_ROLE``            role submit_filing requires (default ``regulatory-filing``)
``PORT``                 listen port on 127.0.0.1 (default 8082)
``VLEI_PUBLIC_URL``      base URL advertised in ``discovery.wellKnown`` (default http://127.0.0.1:$PORT)
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import logging
import os
import sys
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# `mcp_vlei` is not installed as a distribution in this repository; fall back to its source tree.
try:  # pragma: no cover - depends on the environment
    import mcp_vlei  # noqa: F401
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "mcp-vlei" / "src"))

import httpx
import mcp.types as types
from mcp.server.extension import Extension
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolRequestParams, CallToolResult, TextContent
from starlette.requests import Request
from starlette.responses import JSONResponse

# Only the components the skill names (plus their error and report types). Deliberately NOT
# `mcp_vlei.extension` or `mcp_vlei.client`.
from mcp_vlei.chain import Acdc, parse_stream, recompute_said, verify_issuance
from mcp_vlei.errors import (
    ChainInvalid,
    DigestMismatch,
    FailureLayer,
    InvalidSignature,
    MissingCredential,
    RoleMismatch,
    ScopeExceeded,
    UnknownRoot,
    VleiError,
)
from mcp_vlei.kel import (
    KeyState,
    Message,
    StreamKeyStates,
    WitnessKeyStates,
    delegator_of,
    parse_messages,
    verify_kel,
)
from mcp_vlei.report import VerificationReport
from mcp_vlei.revocation import TelRevocationChecker
from mcp_vlei.signing import (
    DEFAULT_FRESHNESS_SECONDS,
    ReplayCache,
    canonicalize,
    precheck_request,
    verify_request,
)

logger = logging.getLogger("skill-server")

# --------------------------------------------------------------------------------------------- #
# Wire names (SKILL.md, "What the extension adds" and "Sign the request")
# --------------------------------------------------------------------------------------------- #

EXTENSION_ID = "org.gleif.vlei/identity"
META_CREDENTIAL = "org.gleif.vlei/credential"
META_CREDENTIAL_SAID = "org.gleif.vlei/credentialSaid"
META_DELEGATED_AID = "org.gleif.vlei/delegatedAid"
META_SIGNATURE = "org.gleif.vlei/signature"
META_REQUIRES = "org.gleif.vlei/requires"
META_FAILURE = "org.gleif.vlei/failure"
#: Not defined by the skill: the task for this server asks for the report under this key.
META_REPORT = "org.gleif.vlei/report"

#: The signed method is the JSON-RPC method, never the tool name.
SIGNED_METHOD = "tools/call"

#: Credential type -> published vLEI schema SAID. The skill gives the ECR SAID; a type the server
#: cannot map to a schema is refused at construction rather than guessed at call time.
SCHEMA_BY_TYPE = {"ECR": "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"}
#: Published vLEI Legal Entity schema SAID. NOT in the skill (taken from mcp_vlei.testing, which
#: mints the published SAIDs); used only for the ECR-LEI consistency check, see REPORT.md.
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"

DEFAULT_ROLE = "regulatory-filing"
DEFAULT_PORT = 8082

#: The verified identity, visible to the protected tool for the duration of one call.
_VERIFIED: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "vlei_verified_identity", default=None
)


# --------------------------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------------------------- #

class ConfigError(ValueError):
    """The server refuses to start rather than run with a trust decision it was not given."""


@dataclass(frozen=True)
class Config:
    le_credential_path: Path
    accepted_roots: list[str]
    witness_url: str
    role: str
    port: int
    public_url: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        path = env.get("VLEI_LE_CREDENTIAL", "").strip()
        if not path:
            raise ConfigError("VLEI_LE_CREDENTIAL must name this server's LE credential (CESR file)")
        roots = [r.strip() for r in env.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r.strip()]
        if not roots:
            # SKILL.md section 1: an empty set is never "accept any root". Raise at construction.
            raise ConfigError(
                "VLEI_ACCEPTED_ROOTS is empty: it is the entire trust decision and has no default"
            )
        witness = env.get("VLEI_WITNESS_URL", "").strip()
        if not witness:
            raise ConfigError(
                "VLEI_WITNESS_URL is required: request signatures are verified under key state "
                "read from a witness, and revocation is read from one"
            )
        role = env.get("VLEI_ROLE", "").strip() or DEFAULT_ROLE
        port = int(env.get("PORT", "").strip() or DEFAULT_PORT)
        public = (env.get("VLEI_PUBLIC_URL", "").strip() or f"http://127.0.0.1:{port}").rstrip("/")
        return cls(Path(path), roots, witness, role, port, public)


# --------------------------------------------------------------------------------------------- #
# The extension
# --------------------------------------------------------------------------------------------- #

class VleiIdentity(Extension):
    """org.gleif.vlei/identity: declares the capability and gates protected tools.

    Public tools (no entry in ``requirements``) are passed through untouched, so a client that
    does not support the extension is served normally.
    """

    identifier = EXTENSION_ID

    def __init__(
        self,
        *,
        le_credential: str,
        accepted_roots: list[str],
        witness_url: str,
        well_known_url: str,
        requirements: Mapping[str, Mapping[str, Any]],
        freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        if not accepted_roots or not all(isinstance(r, str) and r for r in accepted_roots):
            raise ValueError("accepted_roots must be a non-empty list of AIDs: it is the entire trust decision")
        if not le_credential or not le_credential.strip():
            raise ValueError("the server's own LE credential is required: it is published at the well-known URL")
        for tool, requirement in requirements.items():
            kind = requirement.get("credential")
            if kind not in SCHEMA_BY_TYPE:
                raise ValueError(f"tool {tool!r} requires credential {kind!r}, which has no known schema SAID")
            if not isinstance(requirement.get("role"), str) or not requirement["role"]:
                raise ValueError(f"tool {tool!r} must name the role it requires")
        if freshness_seconds <= 0:
            raise ValueError("the freshness window must be positive")

        self._le_credential = le_credential
        self._accepted_roots = list(accepted_roots)
        self._well_known_url = well_known_url
        self._requirements = {name: dict(req) for name, req in requirements.items()}
        self._freshness = freshness_seconds
        self._http = http if http is not None else httpx.AsyncClient(timeout=15.0)
        self._key_states = WitnessKeyStates(witness_url, client=self._http)
        self._revocation = TelRevocationChecker(witness_url, client=self._http)
        # Retains (aid, digest, ts) for twice the freshness window: it must outlive the window.
        self._replay = ReplayCache(window_seconds=freshness_seconds)

    # -- section 1: the capability ---------------------------------------------------------- #

    def settings(self) -> dict[str, Any]:
        # The capability *value*; the SDK keys it by `identifier`.
        return {
            "presents": ["LE"],
            "requires": "ECR",
            "acceptedRoots": list(self._accepted_roots),
            "signatureAlgs": ["Ed25519"],
            # Nothing is cached here - chain, key state and revocation are established per call.
            "ttlMs": 0,
            "discovery": {"wellKnown": self._well_known_url},
        }

    # -- section 2: our own credential ------------------------------------------------------- #

    def well_known_document(self) -> dict[str, Any]:
        return {
            "extension": EXTENSION_ID,
            "credential": self._le_credential,
            "acceptedRoots": list(self._accepted_roots),
            "signatureAlgs": ["Ed25519"],
        }

    # -- section 3: per-tool requirements ----------------------------------------------------- #

    def tool_meta(self, tool: str) -> dict[str, Any]:
        return {META_REQUIRES: dict(self._requirements[tool])}

    # -- the interceptor ----------------------------------------------------------------------- #

    async def intercept_tool_call(self, params: CallToolRequestParams, ctx: Any, call_next: Any) -> Any:
        requirement = self._requirements.get(params.name)
        if requirement is None:
            return await call_next(ctx)  # public tool: untouched

        self._require_declared(ctx)  # section 5, first shape: JSON-RPC -32021

        report = VerificationReport(tool=params.name)
        try:
            identity = await self._verify(params, ctx.params, requirement, report)
        except VleiError as error:
            logger.info(
                "refused tool=%s layer=%s credential=%s delegate=%s",
                params.name, error.layer.value, report.credential_said, report.delegate_aid,
            )
            return _refusal(error, report)

        logger.info(
            "allowed tool=%s lei=%s role=%s credential=%s delegate=%s",
            params.name, report.lei, report.role, report.credential_said, report.delegate_aid,
        )
        token = _VERIFIED.set(identity)
        try:
            result = await call_next(ctx)
        finally:
            _VERIFIED.reset(token)
        if isinstance(result, CallToolResult):
            meta = dict(result.meta or {})
            meta[META_REPORT] = report.as_dict()
            result = result.model_copy(update={"meta": meta})
        return result

    @staticmethod
    def _require_declared(ctx: Any) -> None:
        capabilities = getattr(ctx.session, "client_capabilities", None)
        declared = getattr(capabilities, "extensions", None) or {}
        if EXTENSION_ID in declared:
            return
        data = types.MissingRequiredClientCapabilityErrorData(
            required_capabilities=types.ClientCapabilities(extensions={EXTENSION_ID: {}})
        )
        raise MCPError(
            code=types.MISSING_REQUIRED_CLIENT_CAPABILITY,
            message=f"this tool requires the {EXTENSION_ID} extension; declare it and try again",
            data=data.model_dump(by_alias=True, mode="json", exclude_none=True),
        )

    # -- section 4: verify, in this order ------------------------------------------------------ #

    async def _verify(
        self,
        params: CallToolRequestParams,
        wire_params: Mapping[str, Any] | None,
        requirement: Mapping[str, Any],
        report: VerificationReport,
    ) -> dict[str, Any]:
        meta: Mapping[str, Any] = params.meta or {}
        check = _Checks(report)

        # 0. a credential and a signature were presented at all -> missing_credential
        with check("credential_present", FailureLayer.MISSING_CREDENTIAL):
            credential = meta.get(META_CREDENTIAL)
            signature = meta.get(META_SIGNATURE)
            absent = [k for k, v in ((META_CREDENTIAL, credential), (META_SIGNATURE, signature)) if not v]
            if absent:
                raise MissingCredential(
                    "this tool requires an ECR and a request signature; not presented: " + ", ".join(absent)
                )
            if not isinstance(credential, str):
                raise ChainInvalid("the presented credential is not a CESR string")
            if not isinstance(signature, dict):
                raise InvalidSignature("the presented signature is not an object")
            report.passed("credential_present", "credential and request signature presented")

        # The digest covers the parameters as received on the wire (minus `_meta`), not a
        # re-serialization of the validated model.
        received = (
            dict(wire_params)
            if isinstance(wire_params, Mapping)
            else params.model_dump(by_alias=True, exclude_unset=True, mode="json")
        )

        # 1. ts within the freshness window -> stale_signature
        # 2. digest matches the received parameters -> digest_mismatch
        # Both are decided from the request alone, before any round trip.
        digest_error: DigestMismatch | None = None
        with check("freshness", FailureLayer.STALE_SIGNATURE):
            try:
                precheck_request(signature, received, freshness_seconds=self._freshness)
            except DigestMismatch as exc:
                digest_error = exc
            report.passed("freshness", f"signed at {signature['ts']}, within {self._freshness}s")
        with check("digest", FailureLayer.DIGEST_MISMATCH):
            if digest_error is not None:
                raise digest_error
            report.passed("digest", "arguments match the signed digest")

        signer: str = signature["aid"]

        # 3. signature verifies under the signer's current key state, read from its KEL at a
        #    witness - never under a key the request carries -> invalid_signature
        with check("signature", FailureLayer.INVALID_SIGNATURE):
            try:
                state, inception, delegator_state = await self._key_state(signer)
            except ChainInvalid as exc:
                raise InvalidSignature(
                    f"the key state of {signer} could not be established from its key event log "
                    f"at the witness, so the signature cannot be checked: {exc.message}",
                    aid=signer,
                ) from exc
            if state.threshold > 1:
                raise InvalidSignature(
                    f"{signer} requires {state.threshold} signatures; a request carries one", aid=signer
                )
            # replay_cache=None on purpose: replay is check 4, recorded only after this passes.
            verify_request(signature, SIGNED_METHOD, received, state.keys, freshness_seconds=self._freshness)
            report.passed("signature", f"verifies under {signer}'s key state at sn {state.sn}, read from the witness")

        # 4. not seen before - recorded only after check 3 passed -> stale_signature
        with check("freshness", FailureLayer.STALE_SIGNATURE):
            self._replay.check_and_record(signer, signature["digest"], signature["ts"])
            report.passed("freshness", f"signed at {signature['ts']}, within {self._freshness}s, not seen before")

        # 5. the signer IS the issuee, or is delegated by the issuee in the issuee's own KEL
        #    -> invalid_signature
        with check("delegation", FailureLayer.INVALID_SIGNATURE):
            credentials = _parse_credentials(credential)
            leaf = _presented(credentials, meta.get(META_CREDENTIAL_SAID))
            holder = leaf.issuee  # read from the credential, never from the caller
            claimed = meta.get(META_DELEGATED_AID)
            if claimed is not None and claimed != signer:
                raise InvalidSignature(
                    f"delegatedAid names {claimed}, but the request was signed by {signer}", aid=signer
                )
            if signer == holder:
                detail = f"signer {signer} is the credential's issuee"
            else:
                seal = {"i": signer, "s": "0", "d": inception.body.get("d")}
                if inception.ilk != "dip" or inception.body.get("di") != holder:
                    raise InvalidSignature(
                        f"{signer} is neither the credential's issuee {holder} nor an identifier "
                        f"whose inception names {holder} as its delegator",
                        aid=signer,
                    )
                if delegator_state is None or delegator_state.pre != holder or not delegator_state.anchors(seal):
                    raise InvalidSignature(
                        f"{signer} claims {holder} as its delegator, but {holder}'s key event log "
                        "does not anchor that delegation",
                        aid=signer,
                    )
                detail = f"signer {signer} is delegated by the issuee {holder}, anchored in {holder}'s log"
            report.holder_aid = holder
            report.delegate_aid = signer if signer != holder else None
            report.passed("delegation", detail)

        # 6. SAIDs, continuity, leaf schema -> chain_invalid
        # 7. every issuance anchored in its issuer's KEL -> chain_invalid
        # 8. the chain terminates at an accepted root -> unknown_root
        with check("chain", FailureLayer.CHAIN_INVALID):
            chain, reached_root = self._walk(credentials, leaf)
            wanted = SCHEMA_BY_TYPE[requirement["credential"]]
            if leaf.schema != wanted:
                raise ChainInvalid(
                    f"credential {leaf.said} has schema {leaf.schema}; this tool requires "
                    f"{requirement['credential']} ({wanted})",
                    credential_said=leaf.said,
                )
            _check_lei(chain, report)
            messages = _parse_messages(credential)
            key_states = StreamKeyStates(messages)
            for link in chain:
                verify_issuance(link, messages, key_states)
            if not reached_root:
                top = chain[-1]
                raise UnknownRoot(
                    f"the chain ends at {top.said}, issued by {top.issuer}, which is not an accepted root",
                    credential_said=top.said,
                )
            report.credential_said = leaf.said
            report.lei = leaf.lei
            report.role = leaf.attributes.get("engagementContextRole")
            report.passed(
                "chain",
                f"{len(chain)} credential(s): SAIDs recompute, links continuous, each issuance "
                f"anchored in its issuer's log, root {chain[-1].issuer} accepted",
            )

        # 9. for every credential in the chain, the issuer's live TEL records issuance and no
        #    revocation -> revoked (chain_invalid if no issuance, or the log cannot be read)
        with check("revocation", FailureLayer.CHAIN_INVALID):
            for link in chain:
                await self._revocation.check(link.said, aid=signer)
            report.passed("revocation", f"issued and not revoked, all {len(chain)} credential(s), read live from the witness")

        # 10. role satisfies the tool's requirement; the credential's scope covers the tool's scope
        #     -> role_mismatch / scope_exceeded
        with check("authority", FailureLayer.ROLE_MISMATCH):
            held_role = leaf.attributes.get("engagementContextRole")
            if held_role != requirement["role"]:
                raise RoleMismatch(
                    f"tool requires role {requirement['role']!r}; credential carries {held_role!r}",
                    credential_said=leaf.said,
                )
            ok, reason = _scope_covers(requirement.get("scope"), leaf.attributes.get("scope"))
            if not ok:
                raise ScopeExceeded(reason, credential_said=leaf.said)
            report.passed("authority", f"role {held_role!r} matches; scope covered")

        return {
            "lei": leaf.lei,
            "role": held_role,
            "credentialSaid": leaf.said,
            "holderAid": holder,
            "delegateAid": signer if signer != holder else None,
        }

    async def _key_state(self, aid: str) -> tuple[KeyState, Message, KeyState | None]:
        """The signer's key state from the witness, with its inception and its delegator's state.

        ``verify_kel`` already refuses a ``dip`` its delegator did not anchor; the inception and
        the delegator's state are returned so check 5 can state the rule explicitly as well.
        """
        messages = await self._key_states.messages(aid)
        named = delegator_of(messages, aid)
        delegator_state = await self._key_states.resolve(named) if named else None
        state = verify_kel(messages, aid, delegator=delegator_state)
        inception = next(m for m in messages if m.ilk in ("icp", "dip") and m.body.get("i") == aid)
        return state, inception, delegator_state

    def _walk(self, credentials: dict[str, Acdc], leaf: Acdc) -> tuple[list[Acdc], bool]:
        """Follow the edges from the leaf, checking SAIDs and continuity (check 6).

        Stops at the first credential issued by an accepted root. A chain that runs out of edges
        without reaching one is returned with ``False`` so that the anchoring check (7) still runs
        before the root check (8), in the skill's order.
        """
        chain: list[Acdc] = []
        seen: set[str] = set()
        current = leaf
        while True:
            if current.said in seen:
                raise ChainInvalid(f"the chain loops back to {current.said}", credential_said=current.said)
            seen.add(current.said)
            recomputed = recompute_said(current)
            if recomputed != current.said:
                raise ChainInvalid(
                    f"credential {current.said} does not hash to its own SAID (recomputed "
                    f"{recomputed}); its contents were altered",
                    credential_said=current.said,
                )
            chain.append(current)
            if current.issuer in self._accepted_roots:
                return chain, True
            if not current.edges:
                return chain, False
            parent = next(
                (
                    credentials[target]
                    for _, target in sorted(current.edges.items())
                    if target in credentials and credentials[target].issuee == current.issuer
                ),
                None,
            )
            if parent is None:
                missing = sorted(t for t in current.edges.values() if t not in credentials)
                raise ChainInvalid(
                    f"credential {current.said} was issued by {current.issuer}, but no presented "
                    f"credential it points at was issued to that identifier"
                    + (f" (not presented: {', '.join(missing)})" if missing else ""),
                    credential_said=current.said,
                )
            current = parent


# --------------------------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------------------------- #

class _Checks:
    """Runs one report check, recording its outcome. Any unexpected error fails closed."""

    def __init__(self, report: VerificationReport) -> None:
        self.report = report

    @contextmanager
    def __call__(self, name: str, default_layer: FailureLayer) -> Iterator[None]:
        self.report.start(name)
        try:
            yield
        except VleiError as exc:
            self.report.failed(name, exc.layer.value, exc.message)
            raise
        except Exception as exc:  # a bug or malformed input must refuse, never allow
            logger.warning("check %s raised %s; refusing", name, type(exc).__name__)
            error = VleiError(default_layer, f"the {name} check could not be completed ({type(exc).__name__})")
            self.report.failed(name, default_layer.value, error.message)
            raise error from exc


def _refusal(error: VleiError, report: VerificationReport) -> CallToolResult:
    """Section 5, second shape: the layer first and unadorned in the text, and in `_meta`."""
    layer = error.layer.value
    return CallToolResult(
        content=[TextContent(type="text", text=f"{layer}: {error.message}")],
        is_error=True,
        meta={
            META_FAILURE: {"layer": layer, "message": error.message},
            META_REPORT: report.as_dict(),
        },
    )


def _parse_credentials(cesr: str) -> dict[str, Acdc]:
    try:
        credentials = parse_stream(cesr)
    except Exception as exc:
        raise ChainInvalid(f"the presented credential stream could not be parsed ({type(exc).__name__})") from exc
    if not credentials:
        raise ChainInvalid("no credential was found in the presented stream")
    return credentials


def _parse_messages(cesr: str) -> list[Message]:
    try:
        return parse_messages(cesr)
    except VleiError:
        raise
    except Exception as exc:
        raise ChainInvalid(f"the presented stream could not be parsed ({type(exc).__name__})") from exc


def _presented(credentials: dict[str, Acdc], said: Any) -> Acdc:
    """The credential being presented: the one `credentialSaid` names, else the only leaf."""
    if said is not None:
        if not isinstance(said, str) or said not in credentials:
            raise ChainInvalid(f"credentialSaid {said!r} is not a credential in the presented stream")
        return credentials[said]
    referenced = {target for c in credentials.values() for target in c.edges.values()}
    leaves = [c for s, c in credentials.items() if s not in referenced]
    if len(leaves) != 1:
        raise ChainInvalid("the stream does not have exactly one leaf credential; name it with credentialSaid")
    return leaves[0]


def _check_lei(chain: list[Acdc], report: VerificationReport) -> None:
    """Bind the ECR's LEI to a Legal Entity credential in its chain (NOT in the skill; REPORT.md).

    Without this, every check the skill lists passes for an ECR that names someone else's LEI:
    an LE can issue one for a competitor's LEI, and a QVI can issue one edged straight to its own
    QVI credential with no LE in the chain at all.
    """
    leaf = chain[0]
    if not leaf.lei:
        raise ChainInvalid(f"credential {leaf.said} carries no LEI", credential_said=leaf.said)
    entity = next((c for c in chain[1:] if c.schema == LE_SCHEMA), None)
    if entity is None:
        if len(chain) > 1:
            raise ChainInvalid(
                f"credential {leaf.said} does not chain through a Legal Entity credential, so the "
                f"LEI it names ({leaf.lei}) is not bound to any legal entity",
                credential_said=leaf.said,
            )
        # The ECR's issuer is itself an accepted root: the operator trusts it directly.
        report.caveats.append("the ECR's issuer is an accepted root; its LEI was not cross-checked against an LE credential")
        return
    if entity.lei != leaf.lei:
        raise ChainInvalid(
            f"credential {leaf.said} names LEI {leaf.lei}, but its issuer's LE credential "
            f"{entity.said} is for LEI {entity.lei}",
            credential_said=leaf.said,
        )


def _scope_covers(required: Any, held: Any) -> tuple[bool, str]:
    """SKILL.md section 3: numeric -> held >= required; list -> held is a superset; otherwise
    equality. A key the credential does not carry is not satisfied."""
    if not required:
        return True, ""
    if not isinstance(required, Mapping):
        return False, "the tool's scope requirement is not an object"
    held = held if isinstance(held, Mapping) else {}
    for key, want in required.items():
        if key not in held:
            return False, f"credential carries no {key!r} scope"
        have = held[key]
        if isinstance(want, bool) or not isinstance(want, (int, float, list)):
            if have != want:
                return False, f"{key}: requires {want!r}, credential carries {have!r}"
        elif isinstance(want, list):
            if not isinstance(have, list) or not all(item in have for item in want):
                return False, f"{key}: credential does not cover {want!r}"
        elif isinstance(have, bool) or not isinstance(have, (int, float)) or have < want:
            return False, f"{key}: requires at least {want}, credential carries {have!r}"
    return True, ""


def _own_credential_summary(cesr: str) -> str:
    """For the startup log only: the published credential's SAID and LEI, never its content."""
    credentials = parse_stream(cesr)
    if not credentials:
        raise ConfigError("VLEI_LE_CREDENTIAL contains no ACDC credential")
    referenced = {t for c in credentials.values() for t in c.edges.values()}
    leaves = [c for s, c in credentials.items() if s not in referenced]
    leaf = leaves[0] if len(leaves) == 1 else next(iter(credentials.values()))
    if leaf.schema != LE_SCHEMA:
        logger.warning("VLEI_LE_CREDENTIAL leaf %s does not carry the LE schema", leaf.said)
    return f"{leaf.said} (LEI {leaf.lei})"


# --------------------------------------------------------------------------------------------- #
# The server
# --------------------------------------------------------------------------------------------- #

FILING_EVENTS: list[dict[str, str]] = [
    {"id": "2026-Q3-CAP", "form": "CAP-1", "period": "2026-Q3", "opens": "2026-10-01", "due": "2026-10-31",
     "title": "Quarterly capital adequacy return"},
    {"id": "2026-Q3-LIQ", "form": "LIQ-2", "period": "2026-Q3", "opens": "2026-10-01", "due": "2026-10-15",
     "title": "Liquidity coverage report"},
    {"id": "2026-OWN", "form": "OWN-A", "period": "2026", "opens": "2027-01-04", "due": "2027-03-31",
     "title": "Annual beneficial-ownership filing"},
]


def build_server(
    *,
    le_credential: str,
    accepted_roots: list[str],
    witness_url: str,
    role: str = DEFAULT_ROLE,
    public_url: str = f"http://127.0.0.1:{DEFAULT_PORT}",
    http: httpx.AsyncClient | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> MCPServer:
    requirements = {"submit_filing": {"credential": "ECR", "role": role}}
    extension = VleiIdentity(
        le_credential=le_credential,
        accepted_roots=accepted_roots,
        witness_url=witness_url,
        well_known_url=f"{public_url.rstrip('/')}/.well-known/vlei",
        requirements=requirements,
        freshness_seconds=freshness_seconds,
        http=http,
    )
    server = MCPServer(
        name="skill-server",
        version="0.1.0",
        instructions="Regulatory filing desk. list_events is public; submit_filing requires an ECR.",
        extensions=[extension],
    )

    @server.tool(description="List the open regulatory filing events. Public: no credential required.")
    def list_events() -> list[dict[str, str]]:
        return [dict(event) for event in FILING_EVENTS]

    @server.tool(
        description=f"Submit a regulatory filing. Requires an ECR with role {role!r}, presented and signed "
        "under the org.gleif.vlei/identity extension.",
        meta=extension.tool_meta("submit_filing"),
    )
    def submit_filing(form: str, period: str, payload: dict) -> dict[str, Any]:
        identity = _VERIFIED.get()
        if identity is None:
            # Defence in depth: reachable only if the interceptor was bypassed. Refuse.
            raise RuntimeError("submit_filing reached without a verified identity")
        digest = hashlib.sha256(canonicalize(payload)).digest()
        return {
            "filingId": f"FIL-{uuid.uuid4().hex[:12].upper()}",
            "form": form,
            "period": period,
            "receivedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "payloadDigest": base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
            "filedBy": {k: v for k, v in identity.items() if v is not None},
        }

    @server.custom_route("/.well-known/vlei", methods=["GET"])
    async def well_known(request: Request) -> JSONResponse:
        # No session: a counterparty verifies us before it sends anything.
        return JSONResponse(extension.well_known_document())

    return server


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        config = Config.from_env()
        le_credential = config.le_credential_path.read_text(encoding="utf-8")
        summary = _own_credential_summary(le_credential)
    except (ConfigError, OSError) as exc:
        raise SystemExit(f"skill-server: {exc}") from exc
    server = build_server(
        le_credential=le_credential,
        accepted_roots=config.accepted_roots,
        witness_url=config.witness_url,
        role=config.role,
        public_url=config.public_url,
    )
    logger.info("presenting LE credential %s", summary)
    logger.info("accepted roots: %s", ", ".join(config.accepted_roots))
    logger.info("witness: %s; submit_filing requires ECR role %r", config.witness_url, config.role)
    logger.info("MCP at http://127.0.0.1:%d/mcp, well-known at %s/.well-known/vlei", config.port, config.public_url)
    server.run("streamable-http", host="127.0.0.1", port=config.port)


if __name__ == "__main__":
    main()
