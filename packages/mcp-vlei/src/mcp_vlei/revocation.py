"""Revocation, read from where it actually lives.

Revocation is recorded in the issuer's transaction event log: an `iss` event when a credential is
issued, a `rev` event when it is withdrawn. Witnesses serve that log, which means a relying party
can establish revocation for itself — it does not have to ask a verification service, and it must
not take the holder's word for it, since a holder presenting a revoked credential would simply omit
the withdrawal.

Three sources, selectable, because each fails differently:

``"tel"``
    Query a witness for the credential's transaction event log. No dependency on any verification
    service. This is the default for the reference deployment.

``"verifier"``
    Ask a running ``vlei-verifier``. Correct in principle and the right answer in production, where
    the verifier is an operated service with its own view of the ecosystem. Blocked today by an
    upstream defect — see ``docs/upstream/issue.md``.

``"none"``
    Do not establish revocation. Every result then says ``revocation_checked=False``, and a relying
    party that acts on it is choosing to.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .errors import ChainInvalid, Revoked

__all__ = ["RevocationSource", "TelRevocationChecker"]

RevocationSource = str  # "tel" | "verifier" | "none"


class TelRevocationChecker:
    """Establishes revocation from a witness's copy of the issuer's transaction event log.

    The witness is asked, not the presenter. A holder who has had a credential withdrawn can
    present the credential and omit the withdrawal; the log is what settles it.
    """

    def __init__(
        self,
        witness_url: str,
        *,
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not witness_url:
            raise ValueError("witness_url is required to read a transaction event log")
        self.witness_url = witness_url.rstrip("/")
        self._timeout = timeout
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def check(self, said: str, *, aid: str | None = None) -> None:
        """Raise :class:`Revoked` if the credential has been withdrawn.

        Raises :class:`ChainInvalid` when the log cannot be read at all: an unreachable witness
        means revocation was not established, and reporting that as "not revoked" would be the one
        failure mode this project exists to prevent.
        """
        http = await self._http()
        try:
            response = await http.get(
                f"{self.witness_url}/query", params={"typ": "tel", "vcid": said}
            )
        except httpx.HTTPError as exc:
            raise ChainInvalid(
                f"the transaction event log for {said} could not be read from "
                f"{self.witness_url} ({type(exc).__name__}); revocation was not established",
                aid=aid,
                credential_said=said,
            ) from exc

        if response.status_code != 200:
            raise ChainInvalid(
                f"witness returned HTTP {response.status_code} for the transaction event log "
                f"of {said}; revocation was not established",
                aid=aid,
                credential_said=said,
            )

        events = _events(response.text)
        if not _has_issuance(events, said):
            # A witness that has never seen the issuance is not saying "valid". It is saying
            # nothing, and reading silence as "not revoked" is the failure this checker exists
            # to prevent.
            raise ChainInvalid(
                f"the issuer's transaction event log at {self.witness_url} records no issuance "
                f"of {said}; its status was not established",
                aid=aid,
                credential_said=said,
            )
        if _has_revocation(events, said):
            raise Revoked(
                "the credential has been revoked in the issuer's transaction event log",
                aid=aid,
                credential_said=said,
            )


def _has_issuance(events: list[dict[str, Any]], said: str) -> bool:
    return any(e.get("t") in ("iss", "bis") and e.get("i") == said for e in events)


def _has_revocation(events: list[dict[str, Any]], said: str) -> bool:
    """Is there a `rev` event for this credential in the log?"""
    return any(e.get("t") in ("rev", "brv") and e.get("i") == said for e in events)


def _events(stream: str) -> list[dict[str, Any]]:
    backslash = chr(92)
    events: list[dict[str, Any]] = []
    i = 0
    while i < len(stream):
        start = stream.find("{", i)
        if start < 0:
            break
        depth, k, in_string, escaped = 0, start, False, False
        while k < len(stream):
            char = stream[k]
            if in_string:
                if escaped:
                    escaped = False
                elif char == backslash:
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        try:
            events.append(json.loads(stream[start : k + 1]))
        except json.JSONDecodeError:
            pass
        i = k + 1
    return events
