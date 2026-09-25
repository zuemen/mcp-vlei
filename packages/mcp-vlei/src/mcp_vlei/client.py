"""Client-side wrapper: ``VleiClient``.

Written against the MCP Python SDK 2.2.0 ``mcp.client.session.ClientSession``.

Three lines in an agent::

    from mcp_vlei import VleiClient

    session = VleiClient(session, credential="credentials/ecr.cesr",
                         key_store="./keys", aid=cfg["ecrAid"], verify_server=True)
    await session.connect()

It wraps an existing client session and does three things the agent should never have to think
about: verify the server before anything is called, sign every outgoing call, and verify an
attestation before letting the agent believe it.

What it deliberately does *not* do is decide whether the agent is entitled to call a tool. That
decision belongs to the model, guided by ``skills/vlei-identity/``, and it happens before the call
— a refusal the agent can explain is more useful than a rejection it has to interpret, it saves the
counterparty the verification work, and it keeps a foreseeable failure out of their audit log.
:meth:`entitlement_for` gives the model the facts to make it.

The SDK's own ``ClientExtension`` is declarative — it advertises capabilities and claims result
shapes, and never sees an outgoing call — so :class:`VleiCapability` handles the advertisement and
this wrapper handles the signing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx
from mcp.client.extension import ClientExtension

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
from .kel import WitnessKeyStates
from .revocation import TelRevocationChecker
from .signing import Signer, scope_satisfied, sign_request
from .verifier import OfflineVerifier, VerificationResult, VleiVerifier

logger = logging.getLogger(__name__)

__all__ = ["VleiClient", "VleiCapability", "Entitlement"]


class VleiCapability(ClientExtension):
    """Advertises ``org.gleif.vlei/identity`` in ``ClientCapabilities.extensions``.

    Pass it to the SDK's client so a server can tell, at ``initialize``, that this client
    understands the extension. Without it a server that requires the extension answers ``-32021``
    — which is a configuration problem, not a rejected credential, and the distinction matters to
    whoever has to fix it.
    """

    identifier = EXTENSION_ID

    def __init__(self, presents: list[str] | None = None, accepted_roots: list[str] | None = None):
        self._presents = presents or ["ECR"]
        self._accepted_roots = list(accepted_roots or [])

    def settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = {"presents": self._presents, "signatureAlgs": ["Ed25519"]}
        if self._accepted_roots:
            settings["acceptedRoots"] = self._accepted_roots
        return settings


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
        credential_said: str | None = None,
        key_store: str | Path | None = None,
        signer: Any = None,
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
        witness_url: str | None = None,
        witness_client: Any = None,
    ) -> None:
        self._session = session
        self.credential = Path(credential).read_text(encoding="utf-8").strip()
        #: Which credential in the presented chain is the one being presented. A `--full` CESR
        #: export carries the whole chain, so "the first `d` in the stream" is the QVI credential,
        #: not this one. The holder knows which is theirs; saying so removes the guess.
        self.credential_said = credential_said
        self.delegated_aid = delegated_aid or aid or getattr(signer, "aid", None)
        if not self.delegated_aid:
            raise ValueError("aid or delegated_aid is required: it is what the signature speaks for")
        if signer is None:
            if key_store is None:
                raise ValueError("pass either a signer or a key_store")
            signer = Signer.from_key_store(str(key_store), self.delegated_aid)
        #: Anything with `.aid`, `.verkey` and `.sign(bytes) -> str`. A `CommandSigner` backed by a
        #: keystore keeps the private key out of this process entirely, which is the arrangement a
        #: production deployment should use.
        self.signer = signer
        self.verify_server = verify_server
        if on_unverified_server not in ("stop", "warn"):
            raise ValueError("on_unverified_server must be 'stop' or 'warn'")
        self.on_unverified_server = on_unverified_server
        self.role = role
        self.scope = scope or {}
        self.accepted_roots = list(accepted_roots or [])
        if verify_server and not self.accepted_roots:
            # Without roots there is nothing to verify the server against, and the old behaviour
            # was to skip verification without saying so. Choose explicitly instead.
            raise ValueError(
                "verify_server=True needs accepted_roots: they are the whole trust decision. "
                "Pass verify_server=False to connect without verifying the server."
            )
        #: Where an attesting party's current keys come from — never from what it declares.
        self._key_states = (
            WitnessKeyStates(witness_url, client=witness_client) if witness_url else None
        )
        #: Where the server's credentials are checked for revocation. Without a witness the result
        #: says revocation was not checked, rather than assuming it.
        self._tel = TelRevocationChecker(witness_url, client=witness_client) if witness_url else None
        self._verifier = verifier
        if self._verifier is None and verifier_url and self.accepted_roots:
            self._verifier = VleiVerifier(verifier_url, accepted_roots=self.accepted_roots)

        #: Used for the *server's* credential. Deliberately not the same verifier: a relying party
        #: cannot hand a counterparty's credential to `/presentations`, which requires headers
        #: signed by the AID the credential was issued to. Mode (a) says the relying party checks
        #: it, so that is what happens — and the result reports what it could not establish.
        self._server_verifier = (
            OfflineVerifier(self.accepted_roots) if self.accepted_roots else None
        )

        #: A fallback for deployments whose gateway cannot forward the request body. agentgateway
        #: can (``extAuthz.includeRequestBody``), so this is off by default and the body is
        #: preferred wherever one is available. This does not weaken anything — the signature's
        #: digest covers the canonicalized ``params``, so a mirrored header that disagrees with the
        #: body fails on the digest rather than being believed.
        self.mirror_headers = mirror_headers

        #: Populated by :meth:`connect`. ``None`` means the server presented no identity — which is
        #: "unverified", a different thing from "verified".
        self.server_identity: VerificationResult | None = None
        #: What the server presented, whether or not it could be verified.
        self.server_credential: str | None = None
        self.server_capability: dict[str, Any] | None = None
        self.attested: VerificationResult | None = None
        #: Why the last attestation was not accepted, when one was not. The tool result it came
        #: with is still returned: the call already happened.
        self.attestation_rejected: VleiError | None = None
        self._requirements: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------------------------- #
    # Stages 1-2: initialize and verify the server
    # ------------------------------------------------------------------------------------- #

    async def connect(self) -> VerificationResult | None:
        """Initialize, obtain the server's LE credential, and verify it before anything is called.

        Raises on verification failure. Returns ``None`` when the server presented no identity at
        all and policy permits continuing — the caller must then describe it as unverified, never
        as verified.
        """
        # `Client` has already negotiated by the time it is handed over; a bare `ClientSession`
        # has not. Extensions are only active at protocol 2026-07-28, which `Client` reaches and
        # the bare handshake does not — so a session that never saw the capability is not a broken
        # server, it is an older protocol, and the message has to say so.
        capabilities = getattr(self._session, "server_capabilities", None)
        meta: dict[str, Any] = {}
        if capabilities is None:
            result = await self._session.initialize()
            capabilities, meta = result.capabilities, dict(result.meta or {})
        else:
            discover = getattr(self._session, "prior_discover", None)
            meta = dict(getattr(discover, "meta", None) or {})

        self.server_capability = (getattr(capabilities, "extensions", None) or {}).get(
            EXTENSION_ID
        )

        credential = meta.get(META_CREDENTIAL)
        source = "discover"
        if not credential:
            well_known = (self.server_capability or {}).get("discovery", {}).get("wellKnown")
            if well_known:
                credential = await self._fetch_well_known(well_known)
                source = "well-known"

        # The server may state how long its counterparties should cache verification results. A
        # server that revokes often says so here rather than hoping clients guessed a short TTL.
        ttl_ms = (self.server_capability or {}).get("ttlMs")
        if ttl_ms is not None and self._verifier is not None:
            self._verifier.ttl_ms = int(ttl_ms)

        if not credential:
            if self.on_unverified_server == "stop":
                raise MissingCredential(
                    "the server presented no organizational identity, and policy is to stop. "
                    "It is unverified, not untrusted — but nothing here proves who operates it."
                )
            return None

        # Record what the server presented even when we cannot check it: "presented but
        # unverified" is a third state, and conflating it with either of the other two is exactly
        # the mistake this project exists to point out.
        self.server_credential = credential

        if not self.verify_server or self._server_verifier is None:
            return None

        # Mode (a): check the counterparty's credential here rather than asking anyone. This
        # establishes the chain, the SAIDs and the root; it does not establish issuer signatures
        # or revocation, and `server_identity` carries flags saying so. A caller that needs those
        # must pass a verifier that can reach the issuer's logs.
        from .extension import _check_type, _presented

        # A server speaks for a legal entity, so it presents the entity's LE credential. Any other
        # chain that reaches the root would pass the checks below — including the ECR chain every
        # agent hands a server on each protected call, which a server could replay as its own.
        _check_type({"credential": "LE"}, _presented(credential, None))
        identity = await self._server_verifier.verify(credential, source=source)
        if self._tel is not None:
            for link in identity.chain_saids or [identity.credential_said]:
                await self._tel.check(link, aid=identity.holder_aid)
            identity.revocation_checked = True
        self.server_identity = identity
        return self.server_identity

    @staticmethod
    async def _fetch_well_known(url: str) -> str | None:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.get(url)
            if response.status_code != 200:
                return None
        return response.json().get("credential")

    # ------------------------------------------------------------------------------------- #
    # Stages 3-4: read requirements, decide entitlement
    # ------------------------------------------------------------------------------------- #

    async def list_tools(self) -> Any:
        result = await self._session.list_tools()
        for tool in result.tools:
            requirement = (tool.meta or {}).get(META_REQUIRES)
            if requirement:
                self._requirements[tool.name] = requirement
        return result

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
                f"requires the {wanted!r} role; this credential carries {self.role!r}. "
                "A new ECR credential must be issued by the legal entity.",
                required_role=wanted,
                held_role=self.role,
            )
        ok, reason = scope_satisfied(requirement.get("scope"), self.scope)
        if not ok:
            return Entitlement(False, reason, required_role=wanted, held_role=self.role)
        return Entitlement(True)

    # ------------------------------------------------------------------------------------- #
    # Stages 5-7: sign, call, handle the response
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
        needs = present if present is not None else bool(self._requirements.get(name))
        meta: dict[str, Any] | None = None

        if needs and self.verify_server and self.on_unverified_server == "stop"                 and self.server_identity is None:
            # The signature and the credential are what make a call the holder's, and a server that
            # receives them can present them onward. Asked to verify servers and stop otherwise,
            # the client does not hand them to one it has not verified — whether connect() was
            # never called or failed and the failure was caught.
            raise ChainInvalid(
                f"the server has not been verified; not presenting a credential or a signature to "
                f"it for {name!r}. Call connect() first, or construct the client with "
                "verify_server=False to talk to unverified servers deliberately."
            )

        if needs:
            # Sign exactly what goes on the wire: the params object the SDK will serialize. No
            # arguments are sent as no `arguments` member, so none are signed that way either —
            # signing `{}` for them made every protected tool without parameters fail its digest.
            params: dict[str, Any] = {"name": name}
            if arguments is not None:
                params["arguments"] = arguments
            meta = {
                META_CREDENTIAL: self.credential,
                META_SIGNATURE: sign_request(self.signer, "tools/call", params),
            }
            if self.credential_said:
                meta["org.gleif.vlei/credentialSaid"] = self.credential_said
            if self.delegated_aid:
                meta[META_DELEGATED_AID] = self.delegated_aid

        result = await self._session.call_tool(name, arguments, meta=meta)
        try:
            await self._maybe_accept_attestation(result)
        except VleiError as exc:
            # The tool has run. Raising here told the agent the call failed, and it would retry an
            # action that already happened; a malformed attestation is the server's problem.
            self.attestation_rejected = exc
            logger.warning("attestation from the server not accepted: %s", exc.message)
        return result

    def header_mirror(self, tool_name: str, meta: dict[str, Any]) -> dict[str, str]:
        """The ``_meta`` values as headers, for an HTTP-level authorizer that cannot see a body."""
        import json as _json

        headers = {
            "x-vlei-tool": tool_name,
            "x-vlei-credential": meta[META_CREDENTIAL],
            "x-vlei-signature": _json.dumps(meta[META_SIGNATURE], separators=(",", ":")),
        }
        if meta.get(META_DELEGATED_AID):
            headers["x-vlei-delegated-aid"] = meta[META_DELEGATED_AID]
        return headers

    async def _maybe_accept_attestation(self, result: Any) -> None:
        attestation = (getattr(result, "meta", None) or {}).get(META_ATTESTATION)
        if not attestation:
            return
        if self.server_identity is None:
            raise ChainInvalid(
                "an attestation arrived from a party whose own identity is unverified; "
                "discarding it. Accepting it would be trusting an unverified party's judgment."
            )
        # Who signed it must be the server this client verified — its LE's AID, or an AID that LE
        # delegated to (a gateway, say) — and the key must come from that AID's own log. A key the
        # server declares about itself is a key the attester chose.
        attester = attestation.get("verifierAid", "")
        if self._key_states is None:
            raise ChainInvalid(
                "no witness is configured to establish the attesting party's key state; "
                "discarding the attestation rather than accepting it unverified"
            )
        state = await self._key_states.resolve(attester)
        server = self.server_identity.holder_aid or self.server_identity.aid
        if attester != server and state.delegator != server:
            raise ChainInvalid(
                f"the attestation is signed by {attester}, which is neither the verified server "
                f"{server} nor delegated by it"
            )
        subject = attestation.get("subjectAid")
        if subject not in {self.delegated_aid, getattr(self.signer, "aid", None), self._holder()}:
            raise ChainInvalid(
                f"the attestation is about {subject}, not about this client"
            )
        self.attested = verify_attestation(
            attestation, verifier_verkey=state.keys, threshold=state.threshold
        )

    def _holder(self) -> str | None:
        from .extension import _presented

        try:
            return _presented(self.credential, self.credential_said).issuee
        except VleiError:
            return None

    def __getattr__(self, item: str) -> Any:
        """Anything not overridden passes through to the wrapped session unchanged."""
        return getattr(self._session, item)


def _said_of(cesr: str) -> str:
    from .extension import _said_of as impl

    return impl(cesr)
