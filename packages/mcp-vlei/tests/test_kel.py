"""Key event log verification: whose key is current, established from the log itself.

This is what a request signature is checked against. Before it existed, the key came from the
request — whoever sent the call chose the key it was verified under — so any credential anyone had
ever seen could be presented as theirs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_vlei.testing import Controller, Key, Witness, serialize
from mcp_vlei.errors import ChainInvalid
from mcp_vlei.kel import (
    WitnessKeyStates,
    delegator_of,
    key_states_in,
    parse_messages,
    verify_kel,
)

REAL_EXPORT = Path(__file__).resolve().parents[3] / "credentials" / "ecr.cesr"


def state_of(controller: Controller, delegator: Controller | None = None):
    delegator_state = state_of(delegator) if delegator else None
    return verify_kel(parse_messages(controller.kel()), controller.pre, delegator=delegator_state)


def witnesses() -> list[Witness]:
    return [Witness(name) for name in ("wan", "wil", "wes")]


# --------------------------------------------------------------------------------------------- #
# What a log establishes
# --------------------------------------------------------------------------------------------- #

def test_inception_establishes_the_signing_key():
    alice = Controller("alice")
    state = state_of(alice)

    assert state.pre == alice.pre
    assert state.sn == 0
    assert state.keys == [alice.keys[0].qb64]


def test_interactions_extend_the_log_and_carry_their_seals():
    alice = Controller("alice")
    alice.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "b" * 43}])
    alice.interact([{"i": "E" + "c" * 43, "s": "0", "d": "E" + "d" * 43}])
    state = state_of(alice)

    assert state.sn == 2
    assert state.anchors({"i": "E" + "c" * 43, "s": "0", "d": "E" + "d" * 43})
    assert not state.anchors({"i": "E" + "c" * 43, "s": "0", "d": "E" + "x" * 43})


def test_rotation_moves_to_the_committed_keys():
    alice = Controller("alice")
    committed = alice.next[0]
    alice.rotate()
    state = state_of(alice)

    assert state.sn == 1
    assert state.keys == [committed.qb64]


def test_witness_receipts_are_accepted_at_threshold():
    alice = Controller("alice", witnesses=witnesses(), toad=2)
    alice.interact([])

    assert state_of(alice).sn == 1


def test_delegated_inception_is_valid_with_the_delegators_approval():
    person = Controller("person")
    agent = Controller("agent", delegator=person)
    state = state_of(agent, delegator=person)

    assert state.delegator == person.pre
    assert delegator_of(parse_messages(agent.kel()), agent.pre) == person.pre


# --------------------------------------------------------------------------------------------- #
# What a log must refuse
# --------------------------------------------------------------------------------------------- #

def test_a_prefix_that_does_not_derive_from_its_inception_is_refused():
    """The impersonation attempt at the KEL layer: claim someone's AID, bring your own key.

    A self-addressing prefix is the digest of the inception that created it. Any other inception
    — any other key — produces a different prefix, so a log that claims one is refused.
    """
    victim = Controller("victim")
    mallory = Key("mallory")
    forged = serialize(
        {
            "v": "", "t": "icp", "d": "", "i": victim.pre, "s": "0",
            "kt": "1", "k": [mallory.qb64], "nt": "1", "n": [Key("mallory:1").next_digest],
            "bt": "0", "b": [], "c": [], "a": [],
        },
        ("d",),
    )
    stream = forged + "-VAX-AAB" + mallory.indexed(forged.encode(), 0)

    with pytest.raises(ChainInvalid, match="prefix"):
        verify_kel(parse_messages(stream), victim.pre)


def test_an_altered_event_is_refused():
    alice = Controller("alice")
    alice.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "b" * 43}])
    tampered = alice.kel().replace("E" + "b" * 43, "E" + "z" * 43)

    with pytest.raises(ChainInvalid):
        verify_kel(parse_messages(tampered), alice.pre)


def test_a_signature_by_another_key_is_refused():
    alice = Controller("alice")
    event = alice.events[0]
    mallory = Key("mallory")
    resigned = event.raw + "-VAX-AAB" + mallory.indexed(event.raw.encode(), 0)

    with pytest.raises(ChainInvalid, match="signature"):
        verify_kel(parse_messages(resigned), alice.pre)


def test_rotation_to_keys_that_were_never_committed_is_refused():
    """Pre-rotation: whoever steals today's key cannot rotate to a key of their choosing."""
    alice = Controller("alice")
    alice.rotate(reveal=[Key("mallory")])

    with pytest.raises(ChainInvalid, match="commit"):
        state_of(alice)


def test_a_gap_in_the_log_is_refused():
    alice = Controller("alice")
    alice.interact([])
    alice.interact([])
    gapped = alice.events[0].cesr() + alice.events[2].cesr()

    with pytest.raises(ChainInvalid):
        verify_kel(parse_messages(gapped), alice.pre)


def test_too_few_witness_receipts_are_refused():
    alice = Controller("alice", witnesses=witnesses(), toad=2, receipts=1)

    with pytest.raises(ChainInvalid, match="witness"):
        state_of(alice)


def test_a_delegation_the_delegator_never_approved_is_refused():
    person = Controller("person")
    agent = Controller("agent", delegator=person, approve=False)

    with pytest.raises(ChainInvalid, match="delegat"):
        state_of(agent, delegator=person)


def test_a_delegation_checked_against_the_wrong_delegator_is_refused():
    person = Controller("person")
    someone_else = Controller("someone-else")
    agent = Controller("agent", delegator=person)

    with pytest.raises(ChainInvalid, match="delegat"):
        state_of(agent, delegator=someone_else)


def test_an_empty_log_is_refused():
    with pytest.raises(ChainInvalid):
        verify_kel(parse_messages(""), "E" + "a" * 43)


# --------------------------------------------------------------------------------------------- #
# Reading logs out of a presented stream, and from a witness
# --------------------------------------------------------------------------------------------- #

def test_key_states_in_a_stream_resolve_delegators_from_the_same_stream():
    root = Controller("root")
    qvi = Controller("qvi", delegator=root)
    states = key_states_in(parse_messages(root.kel() + qvi.kel()))

    assert states[qvi.pre].delegator == root.pre
    assert states[root.pre].keys == [root.keys[0].qb64]


async def test_a_witness_serves_the_current_key_state():
    from mcp_vlei.testing import World

    world = World()
    resolver = WitnessKeyStates("http://witness", client=world.witness_client())
    world.holder.rotate()
    state = await resolver.resolve(world.holder.pre)

    assert state.keys == [world.holder.keys[0].qb64]


async def test_a_delegate_resolves_through_its_delegator():
    from mcp_vlei.testing import World

    world = World()
    resolver = WitnessKeyStates("http://witness", client=world.witness_client())
    state = await resolver.resolve(world.agent.pre)

    assert state.delegator == world.holder.pre


async def test_an_identifier_the_witness_does_not_know_is_refused():
    from mcp_vlei.testing import World

    resolver = WitnessKeyStates("http://witness", client=World().witness_client())
    with pytest.raises(ChainInvalid):
        await resolver.resolve("E" + "q" * 43)


async def test_an_unreachable_witness_is_refused_not_trusted():
    import httpx

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    resolver = WitnessKeyStates("http://witness", client=client)
    with pytest.raises(ChainInvalid, match="could not be read"):
        await resolver.resolve("E" + "q" * 43)


# --------------------------------------------------------------------------------------------- #
# Interoperability: what `kli` actually wrote
# --------------------------------------------------------------------------------------------- #

@pytest.mark.skipif(not REAL_EXPORT.is_file(), reason="needs a bootstrapped credentials/ecr.cesr")
def test_logs_written_by_kli_verify():
    """Every key event log in a real `kli vc export --full` verifies, receipts included."""
    messages = parse_messages(REAL_EXPORT.read_text(encoding="utf-8"))
    states = key_states_in(messages)
    events = [m.body for m in messages if m.body.get("t") in ("icp", "dip")]

    assert len(states) == len(events) >= 3
    for body in events:
        assert states[body["i"]].keys == body["k"]


# --------------------------------------------------------------------------------------------- #
# More than one witness: duplicity
# --------------------------------------------------------------------------------------------- #

def _witnesses(world, views: dict[str, dict[str, str]] | None = None):
    """An httpx client that routes by host: each host is a witness, with optional per-AID
    overrides of the log it serves (a lagging witness, or a duplicitous controller's fork)."""
    import httpx

    views = views or {}

    def handler(request: httpx.Request) -> httpx.Response:
        override = views.get(request.url.host, {})
        pre = request.url.params.get("pre", "")
        if request.url.params.get("typ") == "kel" and pre in override:
            return httpx.Response(200, text=override[pre])
        if override.get("*") == "down":
            raise httpx.ConnectError("connection refused", request=request)
        return world.witness_handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


URLS = ["http://wan", "http://wil", "http://wes"]


async def test_witnesses_that_agree_establish_the_key_state():
    from mcp_vlei.testing import World

    world = World()
    world.agent.interact([])
    resolver = WitnessKeyStates(URLS, client=_witnesses(world))
    state = await resolver.resolve(world.agent.pre)

    assert state.sn == 1
    assert state.delegator == world.holder.pre


async def test_a_controller_showing_two_witnesses_two_logs_is_refused():
    """Duplicity: each log is valid on its own; they disagree at the same sequence number."""
    from mcp_vlei.testing import World

    world = World()
    world.agent.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "a" * 43}])
    fork = world.agent.forked_kel([{"i": "E" + "b" * 43, "s": "0", "d": "E" + "b" * 43}])
    resolver = WitnessKeyStates(URLS, client=_witnesses(world, {"wes": {world.agent.pre: fork}}))

    with pytest.raises(ChainInvalid, match="duplicit"):
        await resolver.resolve(world.agent.pre)


async def test_a_witness_that_is_behind_is_not_duplicity():
    """A shorter copy of the same log is a witness catching up, and the longest copy counts."""
    from mcp_vlei.testing import World

    world = World()
    behind = world.agent.kel()
    world.agent.rotate()
    resolver = WitnessKeyStates(URLS, client=_witnesses(world, {"wil": {world.agent.pre: behind}}))
    state = await resolver.resolve(world.agent.pre)

    assert state.keys == [world.agent.keys[0].qb64]


async def test_too_few_witnesses_answering_is_refused():
    from mcp_vlei.testing import World

    world = World()
    client = _witnesses(world, {"wil": {"*": "down"}, "wes": {"*": "down"}})
    resolver = WitnessKeyStates(URLS, client=client)

    with pytest.raises(ChainInvalid, match="witnesses"):
        await resolver.resolve(world.agent.pre)


async def test_one_witness_down_of_three_still_resolves():
    from mcp_vlei.testing import World

    world = World()
    resolver = WitnessKeyStates(URLS, client=_witnesses(world, {"wes": {"*": "down"}}))
    assert (await resolver.resolve(world.holder.pre)).pre == world.holder.pre
