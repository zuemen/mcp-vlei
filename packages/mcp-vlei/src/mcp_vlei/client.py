"""Client-side wrapper: ``VleiClient``.

Three lines in an agent::

    from mcp_vlei import VleiClient

    session = VleiClient(session, credential="credentials/ecr.cesr",
                         key_store="./keys", verify_server=True)

It wraps an existing MCP client session and does three things the agent should never have to think
about: verify the server before anything is called, sign every outgoing request, and verify an
attestation before letting the agent believe it.

What it deliberately does *not* do is decide whether the agent is entitled to call a tool. That
decision belongs to the model, guided by ``skills/vlei-identity/``, and it happens before the call —
a refusal the agent can explain is more useful than a rejection it has to interpret, and it keeps a
failed attempt out of the counterparty's audit log. :meth:`entitlement_for` gives the model the
facts to make it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .attest import verify_attestation
from .errors import ChainInvalid, MissingCredential, VleiError
from .extension import (
    EXTENSION_ID,
    META_ATTESTATION,
    META_CREDENTIAL,
    META_DELEGATED_AID,
    META_REQUIRES,
    META_SIGNATURE,
)
from .signing import Signer, scope_satisfied, sign_request
from .verifier import VerificationResult, VleiVerifier

__all__ = ["VleiClient", "Entitlement"]


class Entitlement:
    """The answer to "may I call this tool?", with the reason spelled out for the user."""

    __slots__ = ("allowed", "reason", "required_role", "held_role")

    def __init__(
        self,
        allowed: bool,
        reason: str = "",
        required_role: str | None = None,
        held_role: str | None = None,
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.required_role = required_role
        self.held_role = held_role

    def __bool__(self) -> bool:
        return self.allowed

    def __str__(self) -> str:
        return "entitled" if self.allowed else f"not entitled: {self.reason}"


class VleiClient:
    """Wraps an MCP client session with vLEI presentation and verification."""

    def __init__(
        self,
        session: Any,
        *,
        credential: str | Path,
        key_store: str | Path,
        aid: str | None = None,
        delegated_aid: str | None = None,
        accepted_roots: list[str] | None = None,
        verifier_url: str | None = None,
        verify_server: bool = True,
        on_unverified_server: str = "stop",
        role: str | None = None,
        scope: dict[str, Any] | None = None,
        verifier: VleiVerifier | None = None,
        mirror_headers: bool = False,
    ) -> None:
        self._session = session
        self.credential = Path(credential).read_text(encoding="utf-8").strip()
        self.delegated_aid = delegated_aid or aid
        if not self.delegated_aid:
            raise ValueError("aid or delegated_aid is required: it is what the signature speaks for")
        self.signer = Signer.from_key_store(str(key_store), self.delegated_aid)
        self.verify_server = verify_server
        if on_unverified_server not in ("stop", "warn"):
            raise ValueError("on_unverified_server must be 'stop' or 'warn'")
        self.on_unverified_server = on_unverified_server
        self.role = role
        self.scope = scope or {}
        self.accepted_roots = list(accepted_roots or [])
        #: Also send the vLEI ``_meta`` values as ``x-vlei-*`` request headers.
        #:
        #: Needed when an HTTP-level gateway does the verifying: such a gateway sees headers, and
        #: the credential and signature live in the JSON-RPC body. This does not weaken anything —
        #: the signature's digest still covers the canonicalized ``params``, so a mirrored header
        #: that disagrees with the body fails on the digest rather than being believed.
        self.mirror_headers = mirror_headers
        self._verifier = verifier
        if self._verifier is None and verifier_url and self.accepted_roots:
            self._verifier = VleiVerifier(verifier_url, accepted_roots=self.accepted_roots)

        #: Populated by :meth:`connect`. ``None`` means the server presented no identity — which is
        #: "unverified", a different thing from "verified".
        self.server_identity: VerificationResult | None = None
        self.server_capability: dict[str, Any] | None = None
        self._requirements: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------------------------- #
    # Stage 1-2: discover and verify the server
    # ------------------------------------------------------------------------------------- #

    async def connect(self) -> VerificationResult | None:
        """Discover the server, obtain its LE credential, and verify it before anything is called.

        Raises on verification failure. Returns ``None`` when the server presented no identity at
        all and policy permits continuing — the caller must then describe it as unverified, never
        as verified.
        """
        discover = await self._discover()
        self.server_capability = (
            (discover.get("serverInfo", {}).get("extensions") or {}).get(EXTENSION_ID)
        )

        credential = (discover.get("_meta") or {}).get(META_CREDENTIAL)
        source = "discover"
        if not credential:
            well_known = (self.server_capability or {}).get("discovery", {}).get("wellKnown")
            if well_known:
                credential = await self._fetch_well_known(well_known)
                source = "well-known"

        if not credential:
            if self.on_unverified_server == "stop":
                raise MissingCredential(
                    "the server presented no organizational identity, and policy is to stop. "
                    "It is unverified, not untrusted — but nothing here proves who operates it."
                )
            return None

        if not self.verify_server or self._verifier is None:
            return None

        self.server_identity = await self._verifier.verify(
            credential,
            said=_said_of(credential),
            aid=(self.server_capability or {}).get("aid", ""),
            source=source,
        )
        return self.server_identity

    async def _discover(self) -> dict[str, Any]:
        for attr in ("discover", "server_discover", "initialize"):
            fn = getattr(self._session, attr, None)
            if callable(fn):
                out = await fn()
                return out if isinstance(out, dict) else _as_dict(out)
        raise ChainInvalid("the session exposes no discover/initialize method")

    @staticmethod
    async def _fetch_well_known(url: str) -> str | None:
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.get(url)
            if resp.status_code != 200:
                return None
            body = resp.json()
        return body.get("credential")

    # ------------------------------------------------------------------------------------- #
    # Stage 3-4: read requirements, decide entitlement
    # ------------------------------------------------------------------------------------- #

    async def list_tools(self) -> Any:
        tools = await self._session.list_tools()
        for tool in _iter_tools(tools):
            meta = (getattr(tool, "_meta", None) or (tool.get("_meta") if isinstance(tool, dict) else None)) or {}
            requirement = meta.get(META_REQUIRES)
            if requirement:
                name = getattr(tool, "name", None) or tool.get("name")
                self._requirements[name] = requirement
        return tools

    def entitlement_for(self, tool_name: str) -> Entitlement:
        """Whether this agent's credential covers ``tool_name`` — checked **before** calling.

        The requirement is declared in the tool's schema precisely so this question can be answered
        here rather than by attempting the call and reading the rejection.
        """
        requirement = self._requirements.get(tool_name)
        if not requirement:
            return Entitlement(True, "tool declares no credential requirement")

        wanted = requirement.get("role")
        if wanted and self.role != wanted:
            return Entitlement(
                False,
                f"requires the {wanted!r} role; this credential carries "
                f"{self.role!r}. A new ECR credential must be issued by the legal entity.",
                required_role=wanted,
                held_role=self.role,
            )
        ok, reason = scope_satisfied(requirement.get("scope"), self.scope)
        if not ok:
            return Entitlement(False, reason, required_role=wanted, held_role=self.role)
        return Entitlement(True)

    # ------------------------------------------------------------------------------------- #
    # Stage 5-7: sign, call, handle the response
    # ------------------------------------------------------------------------------------- #

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        present: bool | None = None,
    ) -> Any:
        """Sign and send a tool call.

        A credential is presented only when the tool requires one: presenting an ECR discloses the
        entity, the role and the holder's AID, and there is no reason to disclose that to a tool
        that did not ask.
        """
        params: dict[str, Any] = {"name": name, "arguments": arguments or {}}
        needs = present if present is not None else bool(self._requirements.get(name))

        if needs:
            meta = {
                META_CREDENTIAL: self.credential,
                META_SIGNATURE: sign_request(self.signer, "tools/call", params),
            }
            if self.delegated_aid:
                meta[META_DELEGATED_AID] = self.delegated_aid
            params["_meta"] = meta

        kwargs: dict[str, Any] = {"meta": params.get("_meta")}
        if needs and self.mirror_headers:
            kwargs["headers"] = self.header_mirror(name, params["_meta"])

        result = await self._session.call_tool(name, params.get("arguments"), **kwargs)
        await self._maybe_accept_attestation(result)
        return result

    def header_mirror(self, tool_name: str, meta: dict[str, Any]) -> dict[str, str]:
        """The ``_meta`` values as headers, for an HTTP-level authorizer."""
        import json as _json

        headers = {
            "x-vlei-tool": tool_name,
            "x-vlei-credential": meta[META_CREDENTIAL],
            "x-vlei-signature": _json.dumps(meta[META_SIGNATURE], separators=(",", ":")),
            "x-vlei-verkey": self.signer.verkey,
        }
        if meta.get(META_DELEGATED_AID):
            headers["x-vlei-delegated-aid"] = meta[META_DELEGATED_AID]
        return headers

    async def _maybe_accept_attestation(self, result: Any) -> None:
        meta = getattr(result, "_meta", None) or (result.get("_meta") if isinstance(result, dict) else None)
        attestation = (meta or {}).get(META_ATTESTATION)
        if not attestation:
            return
        if self.server_identity is None:
            raise ChainInvalid(
                "an attestation arrived from a party whose own identity is unverified; "
                "discarding it. Accepting it would be trusting an unverified party's judgment."
            )
        verkey = (self.server_capability or {}).get("verkey")
        if not verkey:
            raise ChainInvalid(
                "no verification key established for the attesting party; discarding the "
                "attestation rather than accepting the claim unverified"
            )
        self.attested = verify_attestation(
            attestation,
            verifier_verkey=verkey,
            max_age_seconds=3600,
        )

    def __getattr__(self, item: str) -> Any:
        """Anything not overridden passes through to the wrapped session unchanged."""
        return getattr(self._session, item)


# ------------------------------------------------------------------------------------------- #

def _iter_tools(tools: Any):
    if isinstance(tools, dict):
        return tools.get("tools", [])
    return getattr(tools, "tools", tools) or []


def _as_dict(obj: Any) -> dict[str, Any]:
    for attr in ("model_dump", "dict"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            return fn(by_alias=True) if attr == "model_dump" else fn()
    return dict(getattr(obj, "__dict__", {}))


def _said_of(cesr: str) -> str:
    from .extension import _said_of as impl

    return impl(cesr)
