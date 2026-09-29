"""Revocation read from the issuer's key event log, where each registry event is anchored.

A witness's copy of a transaction event log is only as honest as the witness: it can leave the
withdrawal out, or put one in that the issuer never made. The issuer's key event log anchors every
event of that registry — `{i: credential, s: n, d: event}` — and that log is already read from
several witnesses, compared for duplicity, and verified. So issuance is an anchored event 0, and
withdrawal any anchored event after it, whatever a witness's copy of the registry says. Each test
failed before this.
"""

from __future__ import annotations

import httpx
import pytest

from conftest import Ctx  # noqa: E402
from mcp_vlei.testing import World, serialize
from test_extension import ARGS, REQUIRES_REGISTRATION, build, call_next, layer_of, present


@pytest.fixture
def world() -> World:
    return World()


def _witness(world: World, tel_for: dict[str, str]) -> httpx.AsyncClient:
    """The world's witness, except that it answers the registry query for some credentials with
    the text given."""

    def handler(request: httpx.Request) -> httpx.Response:
        vcid = request.url.params.get("vcid", "")
        if request.url.params.get("typ") == "tel" and vcid in tel_for:
            return httpx.Response(200, text=tel_for[vcid])
        return world.witness_handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_a_witness_that_leaves_out_the_withdrawal_does_not_hide_it(world, tmp_path):
    ecr = world.ecr_credential.said
    world.le_registry.revoke(ecr)
    issuance_only = world.le_registry.tels[ecr][0].cesr()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                client=_witness(world, {ecr: issuance_only}))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_a_withdrawal_the_issuer_never_made_does_not_count(world, tmp_path):
    """A witness adding a `rev` could otherwise refuse any holder it liked."""
    ecr = world.ecr_credential.said
    forged = serialize({"v": "", "t": "rev", "d": "", "i": ecr, "s": "1",
                        "ri": world.le_registry.regk, "p": world.le_registry.tels[ecr][0].said,
                        "dt": "2026-09-28T00:00:00.000000+00:00"}, ("d",), proto="KERI")
    tel = world.le_registry.tels[ecr][0].cesr() + forged
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                client=_witness(world, {ecr: tel}))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert not result.is_error


async def test_a_witness_that_serves_no_registry_copy_does_not_stop_the_check(world, tmp_path):
    """The anchors are in the issuer's key event log; a witness without the registry's copy is no
    reason to leave revocation unestablished."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                client=_witness(world, {s: "" for s in (world.ecr_credential.said,
                                                         world.le_credential.said,
                                                         world.qvi_credential.said)}))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert not result.is_error
    assert ext.records[-1]["revocationChecked"] is True


async def test_a_withdrawn_link_above_the_ecr_is_found_the_same_way(world, tmp_path):
    le = world.le_credential.said
    world.qvi_registry.revoke(le)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                client=_witness(world, {le: world.qvi_registry.tels[le][0].cesr()}))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_the_client_finds_a_hidden_withdrawal_of_the_servers_credential(world, tmp_path):
    from mcp_vlei.errors import Revoked
    from test_client_verification import FakeSession, verifying_client

    le = world.le_credential.said
    world.qvi_registry.revoke(le)
    client = verifying_client(FakeSession(world.le_stream), world, tmp_path,
                              witness_client=_witness(world, {le: world.qvi_registry.tels[le][0].cesr()}))

    with pytest.raises(Revoked):
        await client.connect()


# --------------------------------------------------------------------------------------------- #
# From the review of the change above
# --------------------------------------------------------------------------------------------- #

async def test_an_unknown_issuer_is_not_a_reason_to_fall_back_to_the_witness_copy(world):
    """With a key-state resolver configured, a check without the credential's issuer would have
    quietly read the unauthenticated copy — the finding this change exists to close."""
    from mcp_vlei.errors import ChainInvalid
    from mcp_vlei.kel import WitnessKeyStates
    from mcp_vlei.revocation import TelRevocationChecker

    client = world.witness_client()
    checker = TelRevocationChecker("http://witness", client=client,
                                   key_states=WitnessKeyStates("http://witness", client=client))

    with pytest.raises(ChainInvalid, match="issuer"):
        await checker.check(world.ecr_credential.said)


async def test_several_witnesses_given_to_the_client_are_compared(world, tmp_path):
    """One witness serving the issuer's log from before the withdrawal was anchored is outvoted by
    two that serve it whole. The client takes several witnesses, like the server."""
    from mcp_vlei.errors import Revoked
    from test_client_verification import FakeSession, verifying_client

    le = world.le_credential.said
    world.qvi_registry.revoke(le)
    anchor = next(i for i, e in enumerate(world.qvi.events)
                  if any(s.get("i") == le and s.get("s") == "1" for s in e.body.get("a", [])))
    stale = "".join(e.cesr() for e in world.qvi.events[:anchor])

    def handler(request: httpx.Request) -> httpx.Response:
        if (request.url.host == "wan" and request.url.params.get("typ") == "kel"
                and request.url.params.get("pre") == world.qvi.pre):
            return httpx.Response(200, text=stale)
        return world.witness_handler(request)

    client = verifying_client(FakeSession(world.le_stream), world, tmp_path,
                              witness_url=["http://wan", "http://wil", "http://wes"],
                              witness_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    with pytest.raises(Revoked):
        await client.connect()
