"""Credential verification: a thin adapter over GLEIF-IT/vlei-verifier, plus an offline fallback.

Design rule from ``spec/SPEC.md``: **verification logic lives in the package, never hard-coded in a
server.** A server states what it requires; it does not decide what "valid" means. That separation
is what lets the same requirement be enforced by an in-process extension, by a gateway, or by a
regulator's own infrastructure without the tool code changing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .chain import Acdc, parse_stream, verify_issuance, verify_vlei_chain, walk_chain
from .kel import StreamKeyStates, parse_messages
from .errors import ChainInvalid, MissingCredential, Revoked, RoleMismatch, UnknownRoot

__all__ = ["VerificationResult", "VleiVerifier", "OfflineVerifier"]


@dataclass
class VerificationResult:
    """What a successful verification establishes."""

    aid: str
    lei: str
    role: str | None = None
    credential_said: str | None = None
    holder_aid: str | None = None
    #: Scope carried by the credential, compared against a tool's declared scope.
    scope: dict[str, Any] = field(default_factory=dict)
    #: Which root the chain terminated at — recorded so an audit can show what was trusted.
    root_aid: str | None = None
    #: Where the credential came from: "presented", "well-known", "discover", "attestation".
    source: str = "presented"
    #: Whether revocation was actually established. False means the chain was checked but the
    #: issuer's transaction event log was not reached — a distinction a relying party must be able
    #: to see, because "valid as far as we could tell" is not "valid".
    #: True only where a transaction event log was actually read. Defaulting to True made a
    #: vlei-verifier answer — whose own revocation check ships switched off — say otherwise.
    revocation_checked: bool = False
    #: Whether issuance was established — each credential anchored in its issuer's key event log.
    signatures_checked: bool = True
    #: Every credential in the chain, leaf first. Revocation is established for each of them: an
    #: ECR under a withdrawn LE is withdrawn authority, whatever its own log says.
    chain_saids: list[str] = field(default_factory=list)
    #: When `source == "attestation"`, the AID whose judgment this rests on. A relying party that
    #: accepted someone else's verification must be able to say whose — `spec/SPEC.md`
    #: §Security Considerations requires the decision to record it.
    attested_by: str | None = None

    def to_headers(self) -> dict[str, str]:
        """The headers a gateway passes downstream so a legacy system needs no vLEI code at all."""
        headers = {"x-vlei-lei": self.lei, "x-vlei-holder-aid": self.holder_aid or self.aid}
        if self.role:
            headers["x-vlei-role"] = self.role
        if self.aid != (self.holder_aid or self.aid):
            headers["x-vlei-delegate-aid"] = self.aid
        return headers


@dataclass
class _CacheEntry:
    result: VerificationResult
    expires_at: float


class VleiVerifier:
    """Adapter over a running ``vlei-verifier``.

    Verification results are cached for ``ttl_ms``. A revocation therefore takes effect no later
    than cache expiry — set ``ttl_ms=0`` for high-value tools, where a stale "valid" is worse than
    the extra round trip.
    """

    def __init__(
        self,
        url: str,
        *,
        accepted_roots: list[str] | None = None,
        ttl_ms: int = 30_000,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not accepted_roots:
            # An empty accepted-roots list is a configuration error, not "accept anything". The
            # whole trust decision is this list.
            raise ValueError(
                "accepted_roots must be non-empty: it is the entire trust decision"
            )
        self.url = url.rstrip("/")
        self.accepted_roots = list(accepted_roots)
        self.ttl_ms = ttl_ms
        self._timeout = timeout
        self._client = client
        self._cache: dict[tuple[str, str], _CacheEntry] = {}

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------------------------------- #

    async def wait_ready(self, *, timeout: float = 60.0, initial_delay: float = 0.5) -> None:
        """Block until the verifier answers, with exponential backoff, or raise.

        vlei-verifier 1.0.0 and 0.1.5 crash on their own revocation path and are restarted by the
        container runtime, so "is it up?" is a real question between calls rather than only at
        startup. Probing explicitly — with a timeout and a message that says what was waited for —
        replaces racing the restart policy and hoping.

        Bounded on purpose: an unbounded wait turns a dead service into a hung test, which is
        harder to diagnose than a failure.
        """
        import asyncio

        http = await self._http()
        deadline = time.monotonic() + timeout
        delay = initial_delay
        last = ""
        while time.monotonic() < deadline:
            try:
                response = await http.get(f"{self.url}/health")
                if response.status_code < 500:
                    return
                last = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                last = type(exc).__name__
            await asyncio.sleep(delay)
            delay = min(delay * 2, 5.0)
        raise ChainInvalid(
            f"the verifier at {self.url} did not become ready within {timeout:.0f}s "
            f"(last: {last or 'no response'})"
        )

    async def present(self, said: str, cesr: str) -> None:
        """Submit a credential for verification. 200/202 means accepted for processing."""
        http = await self._http()
        resp = await http.put(
            f"{self.url}/presentations/{said}",
            content=cesr,
            headers={"Content-Type": "application/json+cesr"},
        )
        if resp.status_code in (404, 405):  # released versions have used both verbs
            resp = await http.post(
                f"{self.url}/presentations/{said}",
                content=cesr,
                headers={"Content-Type": "application/json+cesr"},
            )
        if resp.status_code not in (200, 202):
            raise ChainInvalid(
                f"verifier rejected the presentation (HTTP {resp.status_code}): {resp.text[:200]}",
                credential_said=said,
            )

    async def authorizations(self, aid: str) -> dict[str, Any]:
        http = await self._http()
        resp = await http.get(f"{self.url}/authorizations/{aid}")
        if resp.status_code == 404:
            raise MissingCredential(
                "the verifier holds no record for this AID: the holder has not presented this "
                "credential to it. Presentation is the holder's step, not the relying party's.",
                aid=aid,
            )
        if resp.status_code == 401:
            # The verifier's considered "no": revoked, unauthorized, or a chain that did not
            # validate. It states which, and that text is more useful than anything we could add.
            detail = resp.text[:300]
            if "revok" in detail.lower():
                raise Revoked(detail, aid=aid)
            raise ChainInvalid(detail, aid=aid)
        if resp.status_code != 200:
            raise ChainInvalid(
                f"verifier returned HTTP {resp.status_code}: {resp.text[:200]}", aid=aid
            )
        return resp.json()

    async def verify(
        self,
        cesr: str,
        *,
        said: str,
        aid: str,
        expected_role: str | None = None,
        source: str = "presented",
    ) -> VerificationResult:
        """Present, then read back the authorization, then apply our own root and role checks.

        The verifier answers "does this chain validate and is it unrevoked". It does not answer
        "is this a root *we* accept" or "is this the role *this tool* needs" — those are the
        relying party's decisions, and they are made here.
        """
        if not cesr:
            raise MissingCredential("no credential was presented", aid=aid)

        # Keyed by the credential as well as the holder: an answer about one of a holder's
        # credentials is not an answer about another.
        cached = self._cache.get((aid, said))
        if cached and cached.expires_at > time.monotonic():
            result = cached.result
        else:
            try:
                # Query only — do not present. `/presentations` is the **holder's** endpoint: it
                # requires headers signed by the AID the credential was issued to, so a relying
                # party cannot present someone else's credential on their behalf, and
                # vlei-verifier rejects the attempt as "did not cryptographically verify".
                #
                # The division of labour this implies is the right one: the holder presents once,
                # the relying party asks what that established. It is also how GLEIF's regulatory
                # filing pilot works, where the filer logs in and the regulator reads the result.
                body = await self.authorizations(aid)
            except httpx.HTTPError as exc:
                # An unreachable verifier is a failure to verify, not a pass and not a crash. It
                # gets its own message because the operator's next step is entirely different from
                # every other layer: nothing is wrong with the credential.
                raise ChainInvalid(
                    f"the verifier at {self.url} could not be reached ({type(exc).__name__}); "
                    "no verification was performed",
                    aid=aid,
                    credential_said=said,
                ) from exc
            result = self._interpret(body, aid=aid, said=said, source=source)
            if self.ttl_ms > 0:
                self._cache[(aid, said)] = _CacheEntry(
                    result, time.monotonic() + self.ttl_ms / 1000.0
                )

        if result.root_aid and result.root_aid not in self.accepted_roots:
            raise UnknownRoot(
                f"chain terminates at {result.root_aid}, which is not an accepted root",
                aid=aid,
                credential_said=said,
            )
        if expected_role is not None and result.role != expected_role:
            raise RoleMismatch(
                f"tool requires role {expected_role!r}; credential carries {result.role!r}",
                aid=aid,
                credential_said=said,
            )
        return result

    def invalidate(self, aid: str) -> None:
        """Drop every cached result for ``aid`` — used by the dashboard's revoke button."""
        for key in [k for k in self._cache if k[0] == aid]:
            del self._cache[key]

    # -------------------------------------------------------------------------------------- #

    @staticmethod
    def _interpret(
        body: dict[str, Any], *, aid: str, said: str, source: str
    ) -> VerificationResult:
        """Map the verifier's response onto a :class:`VerificationResult`.

        Field names have varied across vlei-verifier releases, so each is read from a small set of
        aliases rather than one hard-coded key. Anything genuinely absent fails loudly.
        """

        def pick(*names: str, default: Any = None) -> Any:
            for n in names:
                if n in body and body[n] not in (None, ""):
                    return body[n]
            nested = body.get("credential") or body.get("cred") or {}
            attrs = nested.get("sad", {}).get("a", {}) if isinstance(nested, dict) else {}
            for n in names:
                if n in attrs and attrs[n] not in (None, ""):
                    return attrs[n]
            return default

        # The verifier answers about the credential this AID presented to it. If that is not the
        # one in front of us, its answer — revoked or not — is about something else.
        reported = pick("said", "credentialSaid", "d")
        if said and not reported:
            # An answer about the holder that does not say which credential it is about cannot be
            # an answer about this one: a holder re-issued after a revocation would otherwise pass
            # the old credential on the new one's record.
            raise ChainInvalid(
                f"the verifier's answer about {aid} does not say which credential it is about; "
                f"it cannot establish the presented {said}",
                aid=aid,
                credential_said=said,
            )
        if said and reported and reported != said:
            raise ChainInvalid(
                f"the verifier's record for {aid} is credential {reported}, not the presented "
                f"{said}; the holder has not presented this one to it",
                aid=aid,
                credential_said=said,
            )

        if str(pick("revoked", default=False)).lower() in ("true", "1"):
            raise Revoked("the credential has been revoked", aid=aid, credential_said=said)

        status = str(pick("status", "state", default="")).lower()
        if status in ("revoked", "invalid", "failed"):
            raise Revoked(
                f"the verifier reports status {status!r}", aid=aid, credential_said=said
            )

        lei = pick("LEI", "lei")
        if not lei:
            raise ChainInvalid(
                "the verifier returned no LEI for this AID", aid=aid, credential_said=said
            )

        scope = pick("scope", default={}) or {}
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except json.JSONDecodeError:
                scope = {}

        return VerificationResult(
            aid=aid,
            lei=str(lei),
            role=pick("engagementContextRole", "role", "officialRole"),
            credential_said=said,
            holder_aid=pick("holderAid", "holder", "issuee", default=aid),
            scope=scope if isinstance(scope, dict) else {},
            root_aid=pick("rootOfTrust", "root", "rootAid"),
            source=source,
        )


class OfflineVerifier:
    """Verifies a counterparty's credential without asking a verification service.

    This is mode (a) of ``spec/SPEC.md``, and it is the only option for a **counterparty's**
    credential: ``/presentations`` requires headers signed by the AID the credential was issued to,
    so a relying party cannot hand someone else's credential to a verifier and ask about it.

    It establishes that the chain is internally sound, that every credential in it was issued by the
    identifier it names — anchored in that issuer's key event log, carried in the stream — and that
    it terminates at a root this party accepts. It does **not** establish revocation, and it says so
    in the result rather than letting a caller assume otherwise — see :mod:`mcp_vlei.chain`.

    Use it to decide who you are talking to. Use :class:`VleiVerifier` for anything that turns on a
    credential still being valid.
    """

    def __init__(self, accepted_roots: list[str]) -> None:
        if not accepted_roots:
            raise ValueError(
                "accepted_roots must be non-empty: it is the entire trust decision"
            )
        self.accepted_roots = list(accepted_roots)
        #: Present for interface parity with VleiVerifier; nothing is cached, because nothing is
        #: fetched.
        self.ttl_ms = 0

    async def verify(
        self,
        cesr: str,
        *,
        said: str = "",
        aid: str = "",
        expected_role: str | None = None,
        source: str = "presented",
    ) -> VerificationResult:
        if not cesr:
            raise MissingCredential("no credential was presented", aid=aid)

        credentials = parse_stream(cesr)
        if not credentials:
            raise ChainInvalid(
                "no credential was found in the presented stream", aid=aid
            )

        target = said or _last_in_chain(credentials)
        chain = walk_chain(credentials, target, self.accepted_roots)
        # The walk may carry past the root: a role credential brings its LE credential with it.
        leaf = chain[0]

        messages = parse_messages(cesr)
        key_states = StreamKeyStates(messages)
        for link in chain:
            verify_issuance(link, messages, key_states)
        verify_vlei_chain(chain)

        if expected_role is not None and leaf.role != expected_role:
            raise RoleMismatch(
                f"tool requires role {expected_role!r}; credential carries {leaf.role!r}",
                aid=leaf.issuee,
                credential_said=leaf.said,
            )

        lei = next((link.lei for link in chain if link.lei), None)
        if not lei:
            raise ChainInvalid(
                "no LEI appears anywhere in the chain", credential_said=leaf.said
            )

        return VerificationResult(
            aid=aid or leaf.issuee,
            lei=lei,
            role=leaf.role,
            credential_said=leaf.said,
            holder_aid=leaf.issuee,
            scope=leaf.attributes.get("scope") or {},
            root_aid=next(link.issuer for link in chain if link.issuer in self.accepted_roots),
            source=source,
            revocation_checked=False,
            signatures_checked=True,
            chain_saids=[link.said for link in chain],
        )

    def invalidate(self, aid: str) -> None:  # pragma: no cover - nothing is cached
        return None


def _last_in_chain(credentials: dict[str, Acdc]) -> str:
    """The credential nothing else points at — the end of the chain, when no SAID was named.

    A `--full` export carries the whole chain, so "the first credential in the stream" is the root
    of it, not the one being presented. Naming the SAID is better; this is the fallback.
    """
    referenced = {target for cred in credentials.values() for target in cred.edges.values()}
    leaves = [said for said in credentials if said not in referenced]
    if len(leaves) != 1:
        raise ChainInvalid(
            "the stream does not contain exactly one leaf credential; "
            "name the SAID being presented"
        )
    return leaves[0]
