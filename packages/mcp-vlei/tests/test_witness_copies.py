"""What several witnesses' copies of a log establish — and what one faulty witness cannot do.

A witness with no copy is not a witness of that log, so it cannot make up a quorum. A witness
that serves an invalid copy is faulty, not evidence of duplicity, so it cannot veto an identifier
the others agree on. Duplicity is two *valid* copies that disagree. Each test failed before its fix.
"""

from __future__ import annotations

import json

import pytest

from mcp_vlei.errors import ChainInvalid
from mcp_vlei.kel import WitnessKeyStates, parse_messages, verify_kel
from mcp_vlei.testing import Controller, Key, Witness, World, counter, group, serialize
from test_kel import URLS, _append_signed, _witnesses, state_of


def _bogus_interaction(controller: Controller, seals: list | None = None) -> str:
    """An interaction at the next sequence number, signed by a key the controller never had."""
    raw = serialize({"v": "", "t": "ixn", "d": "", "i": controller.pre,
                     "s": f"{controller.sn + 1:x}", "p": controller.events[-1].said,
                     "a": seals or []},
                    ("d",))
    mallory = Key("mallory")
    return raw + group(counter("A", 1) + mallory.indexed(raw.encode(), 0))


# --------------------------------------------------------------------------------------------- #
# RT2-1: an empty answer is not a copy
# --------------------------------------------------------------------------------------------- #

async def test_witnesses_with_no_copy_do_not_make_up_a_quorum():
    """Two witnesses have never seen the log; one serves a fork. Nothing was compared, so nothing
    is established."""
    world = World()
    world.agent.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "b" * 43}])
    fork = world.agent.forked_kel([{"i": "E" + "c" * 43, "s": "0", "d": "E" + "d" * 43}])
    client = _witnesses(world, {"wan": {world.agent.pre: ""}, "wil": {world.agent.pre: ""},
                                "wes": {world.agent.pre: fork}})

    with pytest.raises(ChainInvalid, match="not established"):
        await WitnessKeyStates(URLS, client=client).resolve(world.agent.pre)


# --------------------------------------------------------------------------------------------- #
# RT2-2: one faulty witness does not veto
# --------------------------------------------------------------------------------------------- #

async def test_a_witness_appending_an_invalid_event_does_not_veto_the_identifier():
    world = World()
    honest = world.agent.kel()
    client = _witnesses(world, {"wes": {world.agent.pre: honest + _bogus_interaction(world.agent)}})

    state = await WitnessKeyStates(URLS, client=client).resolve(world.agent.pre)

    assert state.sn == world.agent.sn


async def test_a_witness_serving_an_invalid_event_at_a_known_number_is_not_duplicity():
    """Duplicity is the controller signing two events at one number. A witness making one up is a
    faulty witness; the two that agree still establish the log."""
    world = World()
    base = "".join(event.cesr() for event in world.agent.events)
    world.agent.interact([])
    honest = world.agent.kel()
    world.agent.events.pop()
    forged = base + _bogus_interaction(world.agent, [{"i": "E" + "z" * 43, "s": "0", "d": "E" + "z" * 43}])
    world.agent.interact([])
    client = _witnesses(world, {"wan": {world.agent.pre: honest}, "wil": {world.agent.pre: honest},
                                "wes": {world.agent.pre: forged}})

    state = await WitnessKeyStates(URLS, client=client).resolve(world.agent.pre)

    assert state.sn == 1


async def test_too_few_valid_copies_are_not_established():
    world = World()
    bad = world.agent.kel() + _bogus_interaction(world.agent)
    client = _witnesses(world, {"wil": {world.agent.pre: bad}, "wes": {world.agent.pre: bad}})

    with pytest.raises(ChainInvalid, match="not established"):
        await WitnessKeyStates(URLS, client=client).resolve(world.agent.pre)


# --------------------------------------------------------------------------------------------- #
# RT2-3: a rotation is signed to the threshold the previous event committed to
# --------------------------------------------------------------------------------------------- #

def test_a_rotation_signed_below_the_prior_next_threshold_is_refused():
    """Two next keys were committed, both required. A thief with one device lists both, declares
    a new threshold of one, and signs with the key they have."""
    alice = Controller("alice")
    first, a, b = alice.next[0], Key("alice:a"), Key("alice:b")
    alice.keys = [first]
    _append_signed(alice, {"v": "", "t": "rot", "d": "", "i": alice.pre, "s": "1",
                           "p": alice.events[-1].said, "kt": "1", "k": [first.qb64],
                           "nt": "2", "n": [a.next_digest, b.next_digest],
                           "bt": "0", "br": [], "ba": [], "a": []})
    alice.keys = [a]  # only the thief's key signs
    _append_signed(alice, {"v": "", "t": "rot", "d": "", "i": alice.pre, "s": "2",
                           "p": alice.events[-1].said, "kt": "1", "k": [a.qb64, b.qb64],
                           "nt": "1", "n": [Key("thief:next").next_digest],
                           "bt": "0", "br": [], "ba": [], "a": []})

    with pytest.raises(ChainInvalid, match="prior"):
        state_of(alice)


# --------------------------------------------------------------------------------------------- #
# RT2-5: thresholds count distinct keys and witnesses
# --------------------------------------------------------------------------------------------- #

def test_a_witness_listed_twice_is_counted_once():
    wan = Witness("wan")
    alice = Controller("alice", witnesses=[wan, wan], toad=2)

    with pytest.raises(ChainInvalid, match="twice"):
        state_of(alice)


def test_a_key_listed_twice_is_counted_once():
    key = Key("alice:0")
    raw = serialize({"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "2",
                     "k": [key.qb64, key.qb64], "nt": "1", "n": [Key("alice:1").next_digest],
                     "bt": "0", "b": [], "c": [], "a": []}, ("d", "i"))
    stream = raw + group(counter("A", 2) + key.indexed(raw.encode(), 0)
                         + key.indexed(raw.encode(), 1))

    with pytest.raises(ChainInvalid, match="twice"):
        verify_kel(parse_messages(stream), json.loads(raw)["i"])


def test_witnesses_with_a_threshold_of_zero_are_refused():
    alice = Controller("alice", witnesses=[Witness("wan"), Witness("wil")], toad=0)

    with pytest.raises(ChainInvalid, match="witness threshold"):
        state_of(alice)


# --------------------------------------------------------------------------------------------- #
# RT2-6: an unreadable stream is a refusal with a layer
# --------------------------------------------------------------------------------------------- #

@pytest.mark.parametrize("junk", ["-A!!", "-V$$", "-AAB" + "!" * 88])
def test_an_unreadable_attachment_is_refused_not_crashed(junk):
    alice = Controller("alice")

    with pytest.raises(ChainInvalid):
        parse_messages(alice.kel() + junk)


# --------------------------------------------------------------------------------------------- #
# From the review of the fix above
# --------------------------------------------------------------------------------------------- #

async def test_a_duplicitous_delegator_is_reported_as_the_delegators_duplicity():
    """The strongest signal KERI has must not arrive as a quorum problem about the delegate."""
    world = World()
    world.holder.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "b" * 43}])
    fork = world.holder.forked_kel([{"i": "E" + "c" * 43, "s": "0", "d": "E" + "d" * 43}])
    client = _witnesses(world, {"wes": {world.holder.pre: fork}})

    with pytest.raises(ChainInvalid, match="duplicity") as caught:
        await WitnessKeyStates(URLS, client=client).resolve(world.agent.pre)
    assert caught.value.aid == world.holder.pre


async def test_an_unverified_inception_does_not_send_the_resolver_after_its_delegator():
    """One witness answers with a `dip` that does not derive the prefix, naming a delegator of its
    choosing. That delegator is never looked up."""
    import httpx

    world = World()
    lure = "E" + "L" * 43
    forged = serialize({"v": "", "t": "dip", "d": "", "i": "", "s": "0", "kt": "1",
                        "k": [Key("x").qb64], "nt": "1", "n": [Key("x:1").next_digest],
                        "bt": "0", "b": [], "c": [], "a": [], "di": lure}, ("d", "i"))
    forged = forged.replace(json.loads(forged)["i"], world.holder.pre)
    asked: list[str] = []
    honest = _witnesses(world)

    def handler(request: httpx.Request) -> httpx.Response:
        pre = request.url.params.get("pre", "")
        asked.append(pre)
        if request.url.host == "wes" and pre == world.holder.pre:
            return httpx.Response(200, text=forged)
        return world.witness_handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await WitnessKeyStates(URLS, client=client).resolve(world.holder.pre)

    assert lure not in asked
