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
    Ask a running ``vlei-verifier`` as well — and still read every link's transaction event log, as
    ``"tel"`` does. The service answers about the leaf only, and its own revocation check ships
    switched off, so its 200 establishes that the holder presented the credential to it, not that
    nothing in the chain was withdrawn. Its record may confirm the LEI and role the presented
    credential carries; a disagreement is a refusal. It needs a witness that serves every link's
    log, exactly like ``"tel"``. See also ``docs/upstream/issue-final.md``.

``"none"``
    Do not establish revocation. Every result then says ``revocation_checked=False``, every decision
    record says ``revocationChecked: false``, a warning is logged at construction, and a relying
    party that acts on it is choosing to.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .errors import ChainInvalid, Revoked

__all__ = [
    "RevocationSource",
    "TelRevocationChecker",
    "WITHDRAWN",
    "withdrawal_seal",
    "is_withdrawal",
    "check_delegation",
]

RevocationSource = str  # "tel" | "verifier" | "none"


class TelRevocationChecker:
    """Establishes revocation from the issuer's transaction event log.

    The witness is asked, not the presenter. A holder who has had a credential withdrawn can
    present the credential and omit the withdrawal; the log is what settles it.

    Given ``key_states`` and a credential's issuer, the log is read where it is authenticated: every
    event of an issuer's registry is anchored in the issuer's key event log as a seal
    ``{i: credential, s: n, d: event}``, and that log comes from several witnesses, compared for
    duplicity and verified. Issuance is an anchored event 0; withdrawal is any anchored event after
    it. A witness's copy of the registry is not consulted then — it could leave the withdrawal out,
    or add one the issuer never made. Without them, the witness's copy is read, and its word taken.
    """

    def __init__(
        self,
        witness_url: str,
        *,
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
        key_states: Any = None,
    ) -> None:
        if not witness_url:
            raise ValueError("witness_url is required to read a transaction event log")
        self.witness_url = witness_url.rstrip("/")
        self._timeout = timeout
        self._client = client
        #: A resolver of verified key states (`mcp_vlei.kel.WitnessKeyStates`), for the anchors.
        self._key_states = key_states

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def check(self, said: str, *, aid: str | None = None, issuer: str | None = None) -> None:
        """Raise :class:`Revoked` if the credential has been withdrawn.

        Raises :class:`ChainInvalid` when the log cannot be read at all: an unreachable witness
        means revocation was not established, and reporting that as "not revoked" would be the one
        failure mode this project exists to prevent.
        """
        if self._key_states is not None:
            if not issuer:
                # Falling back to the witness's copy here would quietly undo the point of the
                # anchors: that copy is exactly what a witness can leave a withdrawal out of.
                raise ChainInvalid(
                    f"the issuer of {said} is not known, so its key event log cannot be read; "
                    "revocation was not established",
                    aid=aid,
                    credential_said=said,
                )
            await self._check_anchors(said, issuer, aid)
            return
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


    async def _check_anchors(self, said: str, issuer: str, aid: str | None) -> None:
        # The issuer's own log, from several witnesses, compared and verified: a ChainInvalid
        # from here means the issuer's key state was not established, and so neither was this.
        events = await _anchored_events(self._key_states, issuer, said)
        if "0" not in events:
            raise ChainInvalid(
                f"the key event log of {issuer} anchors no issuance of {said}; its status was "
                "not established",
                aid=aid,
                credential_said=said,
            )
        if events - {"0"}:
            raise Revoked(
                "the credential has been revoked: its issuer's key event log anchors a withdrawal",
                aid=aid,
                credential_said=said,
            )

    async def check_delegation(self, holder: str, agent: str) -> Any:
        """Raise :class:`Revoked` if ``holder`` has withdrawn its delegation to ``agent``.

        See :func:`check_delegation`. Without a key-state resolver there is no authenticated copy
        of the holder's log to read, so the withdrawal was not established — a refusal, not a pass.
        """
        if self._key_states is None:
            raise ChainInvalid(
                f"no witness-backed key state source is configured, so whether {holder} withdrew "
                f"the delegation of {agent} was not established",
                aid=agent,
            )
        return await check_delegation(self._key_states, holder, agent)


# ------------------------------------------------------------------------------------------- #
# Delegation withdrawal (proposal — spec/SPEC.md "Withdrawing an agent's delegation")
# ------------------------------------------------------------------------------------------- #

#: The field that makes a seal a withdrawal. A delegation approval is ``{i, s, d}`` — at ``s: "0"``
#: for the inception and at the rotation's sn for every later ``drt`` — so a withdrawal must not be
#: spelled that way: an approved rotation would read as a withdrawal, or a withdrawal as approval.
WITHDRAWN = "withdrawn"


def withdrawal_seal(agent: str) -> dict[str, Any]:
    """The seal a holder anchors (``kli interact --data``) to withdraw its delegation to ``agent``.

    ``d`` is the agent's delegated inception SAID — for a self-addressing identifier, the AID
    itself. No ``s``: it is not an approval of any event of the agent's log.
    """
    return {"i": agent, "d": agent, WITHDRAWN: True}


def is_withdrawal(seal: Any, agent: str) -> bool:
    """Does ``seal`` withdraw the delegation to ``agent``?

    Fail closed on the details: a seal naming the agent with ``withdrawn: true`` is a withdrawal
    whatever its ``d`` says, because a holder who meant to withdraw must not be overruled by a
    typo. A seal without ``withdrawn: true`` — every delegation approval — never is.
    """
    return isinstance(seal, dict) and seal.get("i") == agent and seal.get(WITHDRAWN) is True


async def check_delegation(key_states: Any, holder: str, agent: str) -> Any:
    """Raise :class:`Revoked` if ``holder``'s key event log anchors a withdrawal of ``agent``.

    ``key_states`` must read from witnesses (`mcp_vlei.kel.WitnessKeyStates`), never from what the
    caller presented: an agent whose delegation was withdrawn would simply present the holder's log
    as it was before. The holder's log is resolved afresh here — compared across witnesses and
    verified — and a :class:`ChainInvalid` from that means the withdrawal was *not established*.
    Returns the holder's key state, for the report.
    """
    state = await key_states.resolve(holder)
    if any(is_withdrawal(seal, agent) for seal in state.seals):
        raise Revoked(
            f"the delegation of {agent} has been withdrawn: its delegator {holder} anchors a "
            "withdrawal in its own key event log",
            aid=agent,
        )
    return state


async def _anchored_events(key_states: Any, issuer: str, said: str) -> set[str]:
    state = await key_states.resolve(issuer)
    return {str(seal.get("s")) for seal in state.seals if seal.get("i") == said}


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
