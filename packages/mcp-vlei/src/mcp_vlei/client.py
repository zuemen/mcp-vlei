"""Client-side wrapper: ``VleiClient``.

Written against the MCP Python SDK 2.2.0 ``mcp.client.session.ClientSession``.

Three lines in an agent::

    from mcp_vlei import VleiClient

    session = VleiClient(session, credential="credentials/ecr.cesr", signer=signer,
                         endpoint_url="http://localhost:8080/mcp", accepted_roots=[root],
                         witness_url=["http://wan:5642", "http://wil:5643", "http://wes:5644"])
    await session.connect()

It wraps an existing client session and does three things the agent should never have to think
about: verify the server before anything is called — its LE chain, revocation, and that it holds
the LE's key (proof of possession), with every key state read from a quorum of witnesses — sign
every outgoing call for that server (``vlei-sig/0.3``), and verify an attestation before letting the
agent believe it. The server is verified again before a credential is presented once the last
verification is older than ``recheck_seconds`` (or the server's ``ttlMs``), and after any refusal
that says the call was meant for someone else.

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
import math
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import httpx
from mcp.client.extension import ClientExtension

from .attest import verify_attestation
from .audience import Audience, is_qb64_identifier, normalise_endpoint
from .errors import ChainInvalid, MissingCredential, Revoked, UnsupportedVersion, VleiError
from .kel import WitnessKeyStates
from .namespace import Keys
from .namespace import keys as namespace_keys
from .pop import PopProof, prove_server
from .revocation import TelRevocationChecker
from .signing import SIGNATURE_FORMAT, Signer, scope_satisfied, sign_request
from .verifier import OfflineVerifier, VerificationResult, VleiVerifier

#: Re-verify the server at least this often before presenting a credential to it.
DEFAULT_RECHECK_SECONDS = 300

#: Default ports dropped the same way `mcp_vlei.audience.normalise_endpoint` drops them, so an
#: origin comparison agrees with how the endpoint itself was signed.
_DEFAULT_PORTS = {"http": 80, "https": 443}

logger = logging.getLogger(__name__)

__all__ = ["VleiClient", "VleiCapability", "Entitlement", "published_audience"]


def _require_non_negative_finite(name: str, value: Any) -> float:
    """A constructor argument that must be a non-negative, finite number — never a bool, never
    NaN or infinity, never negative. Zero is accepted on purpose: ``recheck_seconds=0`` means
    "re-check before every presentation" (spec §6.3). (A value a *peer* sends, like a received
    ``ttlMs``, is read far more leniently — see :meth:`VleiClient.recheck_due` — because refusing
    to talk to a sloppy counterparty is not this check's job; this one guards what this process
    configures.)
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or value < 0:
        raise ValueError(f"{name} must be a non-negative, finite number, not {value!r}")
    return value


def _same_origin(a: str, b: str) -> bool:
    """Whether two URLs share a scheme, host and (explicit-or-default) port — never a path.

    Used to check a server-declared path against the endpoint it was declared for: a pop URL that
    resolves off that origin (an absolute URL, or a ``//host`` network-path reference) must never
    be dialled, however the challenge would otherwise be signed.
    """
    pa, pb = urlsplit(a), urlsplit(b)
    scheme_a, scheme_b = pa.scheme.lower(), pb.scheme.lower()
    port_a = pa.port if pa.port is not None else _DEFAULT_PORTS.get(scheme_a)
    port_b = pb.port if pb.port is not None else _DEFAULT_PORTS.get(scheme_b)
    return (scheme_a, pa.hostname, port_a) == (scheme_b, pb.hostname, port_b)


class VleiCapability(ClientExtension):
    """Advertises ``<namespace>/identity`` in ``ClientCapabilities.extensions``.

    Pass it to the SDK's client so a server can tell, at ``initialize``, that this client
    understands the extension. Without it a server that requires the extension answers ``-32021``
    — which is a configuration problem, not a rejected credential, and the distinction matters to
    whoever has to fix it.
    """

    def __init__(self, presents: list[str] | None = None, accepted_roots: list[str] | None = None,
                 namespace: str | None = None):
        #: Declared under `MCP_VLEI_NAMESPACE`, or the provisional default, unless given. It must
        #: be the server's: a declaration under another name is no declaration (-32021).
        self.identifier = namespace_keys(namespace).extension
        self._presents = presents or ["ECR"]
        self._accepted_roots = list(accepted_roots or [])

    def settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = {"presents": self._presents, "signatureAlgs": ["Ed25519"],
                                    "signatureFormats": [SIGNATURE_FORMAT]}
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
        on_unchecked_revocation: str = "stop",
        role: str | None = None,
        scope: dict[str, Any] | None = None,
        verifier: VleiVerifier | None = None,
        mirror_headers: bool = False,
        witness_url: str | Sequence[str] | None = None,
        witness_client: Any = None,
        namespace: str | None = None,
        endpoint_url: str | None = None,
        witness_quorum: int | None = None,
        pop: str = "required",
        pop_client: Any = None,
        recheck_seconds: float = DEFAULT_RECHECK_SECONDS,
        clock: Callable[[], float] | None = None,
        audience_aid: str | None = None,
    ) -> None:
        #: Every name this client puts on or reads from the wire; the server's must match.
        self.keys: Keys = namespace_keys(namespace)
        self._session = session
        self.credential = Path(credential).read_text(encoding="utf-8").strip()
        #: Which credential in the presented chain is the one being presented. A `--full` CESR
        #: export carries the whole chain, so "the first `d` in the stream" is the QVI credential,
        #: not this one. The holder knows which is theirs; saying so removes the guess. A v0.3
        #: signature names it, so without one the chain's leaf is named.
        self.credential_said = credential_said or _said_of(self.credential)
        if not self.credential_said:
            raise ValueError("credential_said is required: the stream has no single leaf to present")
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
        if on_unchecked_revocation not in ("stop", "warn"):
            raise ValueError("on_unchecked_revocation must be 'stop' or 'warn'")
        #: What to do when the server's credentials cannot be checked for revocation — the logs
        #: unreadable, or not served by this client's witness. "stop" by default: whoever can
        #: blank or block the path to the logs must not be able to make a withdrawn credential
        #: look like a clean one. "warn" connects anyway, with `revocation_checked=False`.
        self.on_unchecked_revocation = on_unchecked_revocation
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
        if verify_server and not witness_url and on_unchecked_revocation == "stop":
            # Without a witness no log can be read, so the server's credentials would never be
            # checked for revocation — the silent version of "warn". Choose it explicitly instead.
            raise ValueError(
                "verify_server=True needs witness_url to check the server's credentials for "
                "revocation. Pass on_unchecked_revocation='warn' to verify without that check."
            )
        if pop not in ("required", "off"):
            raise ValueError("pop must be 'required' or 'off'")
        #: Whether the server must prove it holds its LE's key before anything is presented.
        #: "off" is a stated choice: the server is then known by a public credential anyone can copy.
        self.pop = pop
        if verify_server and pop == "required" and not witness_url:
            raise ValueError(
                "verify_server=True needs witness_url: the server's proof of possession is checked "
                "under its key state, read from witnesses. Pass pop='off' to skip that proof."
            )
        if verify_server and pop == "off":
            logger.warning("pop='off': the server will not be asked to prove it holds its LE's key")
        #: Where an attesting party's, and the server's, current keys come from — never from what
        #: it declares. Several witnesses are compared and a quorum (a majority by default) must
        #: serve one valid log, as on the server side.
        self._key_states = (
            WitnessKeyStates(witness_url, quorum=witness_quorum, client=witness_client)
            if witness_url else None
        )
        if self._key_states is not None and len(self._key_states.witness_urls) == 1:
            logger.warning("one witness configured: duplicity is not checked")
        #: Where the server's credentials are checked for revocation. Without a witness the result
        #: says revocation was not checked, rather than assuming it.
        self._tel = (
            TelRevocationChecker(
                self._key_states.witness_url, client=witness_client, key_states=self._key_states,
            )
            if witness_url else None
        )
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

        if not endpoint_url:
            raise ValueError(
                "endpoint_url is required: a v0.3 signature names the URL the call is sent to"
            )
        #: The URL calls are sent to, as signed: one spelling (`mcp_vlei.audience`).
        self.endpoint_url = normalise_endpoint(endpoint_url)
        #: The recipient's LE AID, when this client does not verify the server and the server
        #: presents no credential it could be read from (an in-process server; a gateway known by
        #: configuration). A verified server's own AID always wins.
        self.audience_aid = audience_aid
        self._pop_client = pop_client
        self.recheck_seconds = _require_non_negative_finite("recheck_seconds", recheck_seconds)
        self._clock = clock or time.monotonic
        #: When the server was last verified (clock seconds); None: never, or it must be redone.
        self._verified_at: float | None = None
        #: What the server's proof of possession established at the last verification.
        self.server_proof: PopProof | None = None
        #: The well-known document or capability the server offered (formats, pop, ttlMs).
        self._offered: dict[str, Any] = {}
        #: Populated by :meth:`connect`. ``None`` means the server presented no identity — which is
        #: "unverified", a different thing from "verified".
        self.server_identity: VerificationResult | None = None
        #: What the server presented, whether or not it could be verified.
        self.server_credential: str | None = None
        self.server_capability: dict[str, Any] | None = None
        self.attested: VerificationResult | None = None
        #: Why the last attestation was not accepted, when one was not. The tool result it came
        #: with is still returned: the call already happened. Both describe the most recent call
        #: only; with concurrent calls on one client, read them per call or not at all.
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
        # A second connect() that fails before reaching `_verify_server_identity` — no credential
        # this time, or a server that stopped declaring v0.3 — must not leave a previous success's
        # identity, proof, verified-at or *credential* looking current: `server_credential` is
        # established fresh, below, only when THIS connect finds one — `_recipient_aid`'s
        # unverified fallback must never reach back into an earlier connect's. Cleared
        # unconditionally, every call.
        self.server_identity, self.server_proof, self._verified_at = None, None, None
        self.server_credential = None
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
            self.keys.extension
        )

        credential = meta.get(self.keys.credential)
        source = "discover"
        self._offered = dict(self.server_capability or {})
        if not credential:
            well_known = (self.server_capability or {}).get("discovery", {}).get("wellKnown")
            if well_known:
                document = await self._fetch_well_known(well_known)
                credential = document.get("credential") if document else None
                self._offered.update({k: document[k] for k in ("signatureFormats", "pop", "ttlMs")
                                      if document and k in document})
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
        if self.pop == "required" and SIGNATURE_FORMAT not in (self._offered.get("signatureFormats") or []):
            # A v0.2 server: it would refuse a v0.3 signature, and it offers no proof of
            # possession. Nothing has been presented; say why, by name.
            raise UnsupportedVersion(
                f"the server does not declare {SIGNATURE_FORMAT} (signatureFormats: "
                f"{self._offered.get('signatureFormats')!r}); nothing was presented to it"
            )
        self.server_identity = await self._verify_server_identity(credential, source)
        return self.server_identity

    async def _verify_server_identity(self, credential: str, source: str) -> VerificationResult:
        """Chain, revocation of every link, and proof of possession — or the layer that failed."""
        self._verified_at, self.server_identity, self.server_proof = None, None, None
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
        if self._tel is None:
            logger.warning("the server's credentials were not checked for revocation: "
                           "no witness is configured")
        else:
            try:
                from .extension import _links_and_issuers

                links, issuers = _links_and_issuers(identity, identity.credential_said or "")
                for link, issuer in zip(links, issuers):
                    await self._tel.check(link, aid=identity.holder_aid, issuer=issuer)
            except Revoked:
                raise
            except ChainInvalid as exc:
                # Not established: the logs could not be read, or this client's witness does not
                # serve the issuers' registries. An unreachable log and a withdrawn credential are
                # different facts, but only the second can be told from a clean one by reading, so
                # by default this is a refusal too.
                if self.on_unchecked_revocation == "stop":
                    raise ChainInvalid(
                        f"the server's credentials could not be checked for revocation "
                        f"({exc.message}); refusing. Pass on_unchecked_revocation='warn' to "
                        "connect to servers whose issuers' logs this client cannot read."
                    ) from exc
                logger.warning("the server's credentials were not checked for revocation: %s",
                               exc.message)
            else:
                identity.revocation_checked = True
        if self.pop == "required":
            path = self._offered.get("pop")
            if not path:
                raise UnsupportedVersion(
                    "the server offers no proof of possession (no 'pop' in its capability or "
                    "well-known document); nothing was presented to it"
                )
            pop_url = urljoin(self.endpoint_url, path)
            if not _same_origin(pop_url, self.endpoint_url):
                # An absolute URL, or a `//host` network-path reference, resolves off the
                # endpoint's own origin — a declaration this client must not follow, since nothing
                # in §6 lets a server send its own challenge to somewhere else to be answered.
                # Nothing is sent. The spec's failure-layer table names no layer for a bad
                # declaration of this kind, so this is the same refusal as any other server that
                # does not hold up its end of vlei-sig/0.3.
                raise UnsupportedVersion(
                    f"the server's declared pop path {path!r} resolves to {pop_url}, off this "
                    f"endpoint's own origin ({self.endpoint_url}); nothing was presented to it"
                )
            http = self._pop_client or httpx.AsyncClient(timeout=15.0)
            try:
                self.server_proof = await prove_server(
                    http=http, pop_url=pop_url,
                    endpoint_url=self.endpoint_url, holder=identity.holder_aid or identity.aid,
                    key_states=self._key_states,
                )
            finally:
                if self._pop_client is None:
                    await http.aclose()
        self._verified_at = self._clock()
        return identity

    def recheck_due(self) -> bool:
        """Whether the server must be verified again before a credential is presented to it."""
        if self._verified_at is None:
            return True
        ttl_ms = self._offered.get("ttlMs")
        limit = self.recheck_seconds
        if isinstance(ttl_ms, (int, float)) and not isinstance(ttl_ms, bool) and ttl_ms >= 0:
            limit = min(limit, ttl_ms / 1000)
        return self._clock() - self._verified_at >= limit

    @staticmethod
    async def _fetch_well_known(url: str) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.get(url)
            if response.status_code != 200:
                return None
        document = response.json()
        return document if isinstance(document, dict) else None

    # ------------------------------------------------------------------------------------- #
    # Stages 3-4: read requirements, decide entitlement
    # ------------------------------------------------------------------------------------- #

    async def list_tools(self) -> Any:
        result = await self._session.list_tools()
        for tool in result.tools:
            requirement = (tool.meta or {}).get(self.keys.requires)
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
        # Each call reports its own attestation: a rejected one must not leave an earlier accepted
        # one looking current.
        self.attested = None
        self.attestation_rejected = None

        if needs and self.verify_server and self.server_identity is None:
            # "warn" tolerates a server that presented no identity at all (on_unverified_server
            # governs exactly that case, in connect()); it never excuses a credential that WAS
            # presented but whose chain, revocation or proof of possession could not be
            # established — §6.1 says a failed proof of possession refuses under every
            # on_unverified_server setting, "warn" included.
            unverifiable = self.pop == "required" and self.server_credential is not None
            if self.on_unverified_server == "stop" or unverifiable:
                # The signature and the credential are what make a call the holder's, and a server
                # that receives them can present them onward. Asked to verify servers and stop
                # otherwise, the client does not hand them to one it has not verified — whether
                # connect() was never called, or it failed and the failure was caught.
                raise ChainInvalid(
                    f"the server has not been verified; not presenting a credential or a signature "
                    f"to it for {name!r}. Call connect() first, or construct the client with "
                    "verify_server=False to talk to unverified servers deliberately."
                )

        if needs and self.verify_server and self.server_identity is not None and self.recheck_due():
            # Re-established before anything is presented: chain, revocation, proof of possession.
            # A failure leaves the server unverified, and nothing is sent.
            try:
                self.server_identity = await self._verify_server_identity(
                    self.server_credential or "", self.server_identity.source)
            except VleiError:
                self.server_identity = None
                raise

        if needs:
            # Sign exactly what goes on the wire: the params object the SDK will serialize. No
            # arguments are sent as no `arguments` member, so none are signed that way either —
            # signing `{}` for them made every protected tool without parameters fail its digest.
            params: dict[str, Any] = {"name": name}
            if arguments is not None:
                params["arguments"] = arguments
            meta = {
                self.keys.credential: self.credential,
                self.keys.signature: sign_request(
                    self.signer, "tools/call", params,
                    audience=Audience(self._recipient_aid(name), self.endpoint_url),
                    credential_said=self.credential_said,
                ),
                self.keys.credential_said: self.credential_said,
            }
            if self.delegated_aid:
                meta[self.keys.delegated_aid] = self.delegated_aid

        result = await self._session.call_tool(name, arguments, meta=meta)
        failure = ((getattr(result, "meta", None) or {}).get(self.keys.failure) or {})
        if isinstance(failure, dict) and failure.get("layer") == "audience_mismatch":
            # The server says the call was meant for someone else: who it is must be established
            # again before anything more is presented to it.
            self._verified_at = None
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
            "x-vlei-credential": meta[self.keys.credential],
            "x-vlei-signature": _json.dumps(meta[self.keys.signature], separators=(",", ":")),
        }
        if meta.get(self.keys.delegated_aid):
            headers["x-vlei-delegated-aid"] = meta[self.keys.delegated_aid]
        return headers

    async def _maybe_accept_attestation(self, result: Any) -> None:
        attestation = (getattr(result, "meta", None) or {}).get(self.keys.attestation)
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

    def _recipient_aid(self, tool: str) -> str:
        """The AID a call is signed for: the verified server's LE issuee — or, when this client
        chose not to verify servers, the issuee of the credential the server presented.

        Raises ``ChainInvalid`` — never a bare ``ValueError`` — for no recipient at all, or one
        that is not a CESR identifier: ``Audience`` itself raises plain ``ValueError`` for the
        latter, and a caller catching this client's own error vocabulary must not have to catch
        that too.
        """
        aid = ""
        if self.server_identity is not None:
            aid = self.server_identity.holder_aid or self.server_identity.aid
        elif self.audience_aid:
            aid = self.audience_aid
        elif self.server_credential:
            from .extension import _presented

            try:
                aid = _presented(self.server_credential, None).issuee
            except VleiError:
                aid = ""
            if aid:
                logger.warning("signing %r for %s, taken from an unverified credential", tool, aid)
        if not aid:
            raise ChainInvalid(
                f"no recipient to sign {tool!r} for: the server presented no credential, so a v0.3 "
                "signature could name no one"
            )
        if not is_qb64_identifier(aid):
            raise ChainInvalid(f"no recipient to sign {tool!r} for: {aid!r} is not a CESR identifier")
        return aid

    def _holder(self) -> str | None:
        from .extension import _presented

        try:
            return _presented(self.credential, self.credential_said).issuee
        except VleiError:
            return None

    def __getattr__(self, item: str) -> Any:
        """Anything not overridden passes through to the wrapped session unchanged."""
        return getattr(self._session, item)


def published_audience(document: dict[str, Any], endpoint_url: str) -> Audience:
    """The recipient a server's published document names, **unverified**: the issuee of its LE.

    For a tool that calls a gateway it trusts by configuration (a console, a script). A client that
    must know who it is talking to verifies the server instead — :meth:`VleiClient.connect`. Either
    way the signature is bound to this AID and URL, so no other recipient can use it.
    """
    from .extension import _presented

    credential = document.get("credential") if isinstance(document, dict) else None
    if not isinstance(credential, str) or not credential:
        raise ChainInvalid("the server's published document carries no credential")
    audience = Audience(_presented(credential, None).issuee, endpoint_url)
    logger.warning(
        "treating %s at %s as the recipient for signed calls, taken from a published document "
        "rather than a server this client verified: unverified, per spec §5.3",
        audience.aid, audience.url,
    )
    return audience


def _said_of(cesr: str) -> str:
    from .extension import _said_of as impl

    return impl(cesr)
