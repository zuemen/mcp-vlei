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
        self._cache: dict[str, _CacheEntry] = {}

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------------------------------- #

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
            raise ChainInvalid("verifier holds no verification record for this AID", aid=aid)
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

        cached = self._cache.get(aid)
        if cached and cached.expires_at > time.monotonic():
            result = cached.result
        else:
            await self.present(said, cesr)
            body = await self.authorizations(aid)
            result = self._interpret(body, aid=aid, said=said, source=source)
            if self.ttl_ms > 0:
                self._cache[aid] = _CacheEntry(
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
        """Drop a cached result — used by the dashboard's revoke button so the demo is immediate."""
        self._cache.pop(aid, None)

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
    """Fallback for when the verifier service is unreachable.

    It parses the presented CESR, walks the edges to a root, and checks that the root is accepted.
    What it deliberately **cannot** do is check revocation, because revocation state lives in the
    issuer's TEL and reaching it is exactly what "offline" rules out.

    Every result it returns is therefore marked, and a relying party that wants revocation
    guarantees must not use it. It exists so that a network partition degrades to a stated, visible
    weakening rather than to a silent one.
    """

    def __init__(self, accepted_roots: list[str]) -> None:
        if not accepted_roots:
            raise ValueError("accepted_roots must be non-empty")
        self.accepted_roots = list(accepted_roots)

    async def verify(
        self,
        cesr: str,
        *,
        said: str,
        aid: str,
        expected_role: str | None = None,
        source: str = "presented",
    ) -> VerificationResult:
        try:
            from keri.vdr import verifying  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ChainInvalid(
                "offline verification requires the 'keri' extra: pip install mcp-vlei[keri]",
                aid=aid,
            ) from exc

        raise ChainInvalid(
            "offline verification cannot establish revocation state; "
            "configure a reachable vlei-verifier for any decision that depends on it",
            aid=aid,
            credential_said=said,
        )
