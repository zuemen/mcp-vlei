"""Withdrawing one agent's delegation, without touching the holder's ECR (proposal).

spec/SPEC.md "Withdrawing an agent's delegation": the ECR holder anchors
``{"i": <agent AID>, "d": <agent dip SAID>, "withdrawn": true}`` in an interaction event of its own
key event log (``kli interact --data``). Check 7 (revocation) reads the holder's log again, from the
witnesses, and refuses with the existing ``revoked`` layer. The 8 checks and 11 layers are unchanged.

Every log here is shaped as `kli` writes it — `dip` anchored by the delegator's `ixn`, witness
receipts, a `drt` approved by `{i, s, d}` — and served by a mock witness, so the package's own KEL
code is what runs.
"""

from __future__ import annotations

import httpx
import pytest

from conftest import Ctx  # noqa: E402
from mcp_vlei.errors import ChainInvalid, Revoked
from mcp_vlei.kel import WitnessKeyStates
from mcp_vlei.report import CHECK_ORDER
from mcp_vlei.revocation import check_delegation, is_withdrawal, withdrawal_seal
from mcp_vlei.testing import World
from test_extension import (
    ARGS,
    REQUIRES_REGISTRATION,
    build,
    call_next,
    check,
    layer_of,
    present,
    signer_for,
    text_of,
)

TOOLS = {"register_member": REQUIRES_REGISTRATION}


@pytest.fixture
def world() -> World:
    return World()


def withdraw(world: World, agent) -> None:
    """What `scripts/revoke-agent.sh` does: the holder anchors the withdrawal seal."""
    world.holder.interact([withdrawal_seal(agent.pre)])


def call_as(world: World, agent):
    return present(world, "register_member", ARGS, signer=signer_for(agent), delegated=None,
                   **{"org.gleif.vlei/delegatedAid": agent.pre})


# --------------------------------------------------------------------------------------------- #
# The seal
# --------------------------------------------------------------------------------------------- #

def test_the_withdrawal_seal_has_its_own_shape(world):
    seal = withdrawal_seal(world.agent.pre)

    assert seal == {"i": world.agent.pre, "d": world.agent.pre, "withdrawn": True}
    assert "s" not in seal  # never (i, s, d): that is a delegation approval
    assert is_withdrawal(seal, world.agent.pre)
    assert not is_withdrawal(seal, world.holder.pre)


def test_a_delegation_approval_is_not_a_withdrawal(world):
    """The approvals of the agent's `dip` (s 0) and of a later `drt` (s 1) in the holder's log."""
    world.agent.rotate()
    approvals = [s for e in world.holder.events for s in e.body.get("a", [])
                 if s.get("i") == world.agent.pre]

    assert {s["s"] for s in approvals} == {"0", "1"}
    assert not any(is_withdrawal(s, world.agent.pre) for s in approvals)
    assert not is_withdrawal({"i": world.agent.pre, "d": world.agent.pre, "withdrawn": "true"},
                             world.agent.pre)


# --------------------------------------------------------------------------------------------- #
# Through the eight checks
# --------------------------------------------------------------------------------------------- #

async def test_a_withdrawn_agent_is_refused_at_revocation(world, tmp_path):
    ext = build(world, tmp_path, TOOLS)
    before = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)
    assert text_of(before) == "TOOL RAN"

    withdraw(world, world.agent)
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"
    assert check(result, "revocation")["layer"] == "revoked"
    for name in CHECK_ORDER[: CHECK_ORDER.index("revocation")]:
        assert check(result, name)["passed"] is True, name
    record = ext.records[-1]
    assert record["allowed"] is False
    assert record["revocationChecked"] is True


async def test_the_holder_and_its_ecr_still_pass_after_the_agent_is_withdrawn(world, tmp_path):
    """Withdrawing the agent does not touch the ECR: Bob signing directly is still allowed."""
    withdraw(world, world.agent)
    ext = build(world, tmp_path, TOOLS)
    params = present(world, "register_member", ARGS, signer=signer_for(world.holder), delegated=None)

    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert text_of(result) == "TOOL RAN"


async def test_withdrawing_one_agent_leaves_another_agent_of_the_same_holder(world, tmp_path):
    """The demo agent keeps working when a second agent, issued beside it, is withdrawn."""
    second = world.delegate("agent2", world.holder)
    ext = build(world, tmp_path, TOOLS)
    assert text_of(await ext.intercept_tool_call(call_as(world, second), Ctx(), call_next)) == "TOOL RAN"

    withdraw(world, second)

    assert layer_of(await ext.intercept_tool_call(call_as(world, second), Ctx(), call_next)) == "revoked"
    demo = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)
    assert text_of(demo) == "TOOL RAN"


async def test_an_agent_rotation_approved_by_the_holder_is_not_read_as_a_withdrawal(world, tmp_path):
    """A `drt` is approved by `{i: agent, s: "1", d}` — the same `i`, an `s` other than 0. The
    credentials' anchors read exactly that shape as a withdrawal; the delegation's must not."""
    world.agent.rotate()
    ext = build(world, tmp_path, TOOLS)

    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, signer=signer_for(world.agent)), Ctx(), call_next
    )

    assert text_of(result) == "TOOL RAN"
    row = ext.last_report.as_dict()["checks"][CHECK_ORDER.index("revocation")]
    assert "not withdrawn" in row["detail"]


async def test_a_withdrawal_seal_does_not_approve_a_delegation(world, tmp_path):
    """The other direction: a withdrawal seal for an agent the holder never approved is not an
    approval — the agent is refused at the delegation check, as before."""
    rogue = world.delegate("rogue", world.holder, approve=False)
    withdraw(world, rogue)
    ext = build(world, tmp_path, TOOLS)

    result = await ext.intercept_tool_call(call_as(world, rogue), Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"


async def test_a_withdrawal_cannot_be_undone(world, tmp_path):
    """Re-anchoring an approval afterwards does not bring the agent back: re-authorising is a new
    AID (spec/SPEC.md)."""
    withdraw(world, world.agent)
    world.holder.interact([{"i": world.agent.pre, "s": "0", "d": world.agent.pre}])
    ext = build(world, tmp_path, TOOLS)

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_a_withdrawal_after_the_agents_rotation_still_withdraws(world, tmp_path):
    world.agent.rotate()
    withdraw(world, world.agent)
    ext = build(world, tmp_path, TOOLS)

    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, signer=signer_for(world.agent)), Ctx(), call_next
    )

    assert layer_of(result) == "revoked"


async def test_the_verifier_source_reads_the_withdrawal_too(world, tmp_path):
    from conftest import StubVerifier

    withdraw(world, world.agent)
    ext = build(world, tmp_path, TOOLS, revocation_source="verifier",
                verifier=StubVerifier(role=None))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


# --------------------------------------------------------------------------------------------- #
# Read from witnesses; not established is not "not withdrawn"
# --------------------------------------------------------------------------------------------- #

async def test_one_witness_hiding_the_withdrawal_is_outvoted(world, tmp_path):
    stale = world.holder.kel()
    withdraw(world, world.agent)

    def handler(request: httpx.Request) -> httpx.Response:
        if (request.url.host == "wan" and request.url.params.get("typ") == "kel"
                and request.url.params.get("pre") == world.holder.pre):
            return httpx.Response(200, text=stale)
        return world.witness_handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ext = build(world, tmp_path, TOOLS, client=client,
                witness_urls=["http://wan", "http://wil", "http://wes"])

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_an_unreadable_holder_log_at_revocation_is_not_a_pass(world, tmp_path):
    """The holder's log is read at the delegation check and again at revocation. If the second
    read fails, the withdrawal was not established — the call is refused, not allowed."""
    reads = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if (request.url.params.get("typ") == "kel"
                and request.url.params.get("pre") == world.holder.pre):
            reads["n"] += 1
            if reads["n"] > 1:
                return httpx.Response(503)
        return world.witness_handler(request)

    ext = build(world, tmp_path, TOOLS,
                client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert reads["n"] >= 2
    assert layer_of(result) == "chain_invalid"
    assert check(result, "revocation")["passed"] is False
    assert ext.records[-1]["revocationChecked"] is False


async def test_the_holders_log_is_read_again_not_taken_from_the_call(world, tmp_path):
    """A caller that appends the holder's pre-withdrawal log to what it presents changes nothing."""
    stale = world.holder.kel()
    withdraw(world, world.agent)
    ext = build(world, tmp_path, TOOLS)

    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, stream=world.ecr_stream + stale), Ctx(), call_next
    )

    assert layer_of(result) == "revoked"


async def test_with_revocation_off_the_withdrawal_is_reported_not_established(world, tmp_path):
    withdraw(world, world.agent)
    ext = build(world, tmp_path, TOOLS, revocation_source="none")

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    row = ext.last_report.as_dict()["checks"][CHECK_ORDER.index("revocation")]
    assert text_of(result) == "TOOL RAN"  # as with any revocation, `none` is the operator's choice
    assert row.get("skipped") is True
    assert "withdrawal of a delegation was established" in row["detail"]
    assert row["detail"].startswith("no revocation source configured; neither")
    assert ext.records[-1]["revocationChecked"] is False


async def test_check_delegation_directly(world):
    client = world.witness_client()
    key_states = WitnessKeyStates("http://witness", client=client)

    state = await check_delegation(key_states, world.holder.pre, world.agent.pre)
    assert state.pre == world.holder.pre

    withdraw(world, world.agent)
    with pytest.raises(Revoked, match="withdrawn"):
        await check_delegation(key_states, world.holder.pre, world.agent.pre)


async def test_check_delegation_without_witness_key_states_is_not_established(world):
    from mcp_vlei.revocation import TelRevocationChecker

    checker = TelRevocationChecker("http://witness", client=world.witness_client())

    with pytest.raises(ChainInvalid, match="not established"):
        await checker.check_delegation(world.holder.pre, world.agent.pre)
