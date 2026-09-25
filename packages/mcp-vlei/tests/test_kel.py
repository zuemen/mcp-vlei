"""Key event log verification: whose key is current, established from the log itself.

This is what a request signature is checked against. Before it existed, the key came from the
request — whoever sent the call chose the key it was verified under — so any credential anyone had
ever seen could be presented as theirs.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
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


# --------------------------------------------------------------------------------------------- #
# Checks that a mutation run found no test holding (packages/mcp-vlei/tools/mutate_checks.py)
#
# Each test below is the one input that only its check refuses: delete the check and every other
# test still passes. The events are signed with the controller's own current key — what a stolen
# signing key, or a controller showing different witnesses different logs, can produce. Those are
# the cases pre-rotation, delegated approval and the hash chain exist for.
# --------------------------------------------------------------------------------------------- #

def _append_signed(controller: Controller, body: dict) -> None:
    """Append an event whatever it says, signed with the controller's current keys."""
    controller._append(serialize(body, ("d",)))


def _rotation(controller: Controller, sn: int, revealed: list[Key], committed: list[Key], *,
              ilk: str = "rot", next_threshold: str = "1") -> dict:
    return {
        "v": "", "t": ilk, "d": "", "i": controller.pre, "s": f"{sn:x}",
        "p": controller.events[-1].said, "kt": "1", "k": [key.qb64 for key in revealed],
        "nt": next_threshold, "n": [key.next_digest for key in committed],
        "bt": "0", "br": [], "ba": [], "a": [],
    }


def test_an_event_with_a_skipped_sequence_number_is_refused():
    """kel.py — sequence continuity. The prior digest is right; only the number is wrong."""
    alice = Controller("alice")
    _append_signed(alice, {"v": "", "t": "ixn", "d": "", "i": alice.pre, "s": "2",
                           "p": alice.events[-1].said, "a": []})

    with pytest.raises(ChainInvalid, match="continuous"):
        state_of(alice)


def test_a_log_spliced_from_two_branches_of_a_fork_is_refused():
    """kel.py — prior digest. Every event is signed and numbered correctly; the history is not one.

    A controller that signed two different events at sequence 1 can show a verifier the start of
    one branch and the end of the other. Only the prior-digest chain tells them apart.
    """
    alice = Controller("alice")
    alice.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "b" * 43}])
    other_branch = alice.forked_kel([{"i": "E" + "c" * 43, "s": "0", "d": "E" + "d" * 43}])
    alice.interact([])

    spliced = other_branch + alice.events[2].cesr()
    with pytest.raises(ChainInvalid, match="follow"):
        verify_kel(parse_messages(spliced), alice.pre)


def test_an_event_that_does_not_hash_to_its_said_is_refused():
    """kel.py — event SAID. Signed by the right key, but its `d` names some other content."""
    alice = Controller("alice")
    raw = serialize({"v": "", "t": "ixn", "d": "", "i": alice.pre, "s": "1",
                     "p": alice.events[-1].said, "a": []}, ("d",))
    alice._append(raw.replace(json.loads(raw)["d"], "E" + "q" * 43))

    with pytest.raises(ChainInvalid, match="SAID"):
        state_of(alice)


def test_a_stolen_key_cannot_restart_the_log_to_escape_pre_rotation():
    """kel.py — a second inception. Pre-rotation says a stolen signing key cannot choose the next
    one. Signing a fresh inception mid-log would reset the commitment to the thief's key and let
    the rotation after it through; the log is refused at the second inception."""
    alice = Controller("alice")
    thief = Key("thief")
    _append_signed(alice, {"v": "", "t": "icp", "d": "", "i": alice.pre, "s": "1",
                           "p": alice.events[-1].said, "kt": "1", "k": [alice.keys[0].qb64],
                           "nt": "1", "n": [thief.next_digest], "bt": "0", "b": [], "c": [],
                           "a": []})
    alice.keys = [thief]
    _append_signed(alice, _rotation(alice, 2, [thief], [Key("thief:1")]))

    with pytest.raises(ChainInvalid, match="second inception"):
        state_of(alice)


def test_a_delegated_identifier_cannot_rotate_without_its_delegator():
    """kel.py — rotation type. A delegate that rotates with `rot` instead of `drt` skips the
    delegator's approval, which is what lets a person withdraw or recover their agent's keys."""
    person = Controller("person")
    agent = Controller("agent", delegator=person)
    committed = agent.next[0]
    agent.keys = [committed]
    _append_signed(agent, _rotation(agent, 1, [committed], [Key("agent:x")]))

    with pytest.raises(ChainInvalid, match="rotation type"):
        state_of(agent, delegator=person)


def test_a_rotation_below_the_committed_threshold_is_refused():
    """kel.py — next threshold. Two keys were committed, both required; revealing one is not a
    rotation the controller agreed to, whoever holds that one key."""
    alice = Controller("alice")
    first, a, b = alice.next[0], Key("alice:a"), Key("alice:b")
    alice.keys = [first]
    _append_signed(alice, _rotation(alice, 1, [first], [a, b], next_threshold="2"))
    alice.keys = [a]
    _append_signed(alice, _rotation(alice, 2, [a], [Key("alice:c")]))

    with pytest.raises(ChainInvalid, match="threshold"):
        state_of(alice)


def test_a_delegated_inception_without_its_delegator_is_refused_not_crashed():
    """kel.py — no delegator's log to check against is a refusal, not an AttributeError."""
    person = Controller("person")
    agent = Controller("agent", delegator=person)

    with pytest.raises(ChainInvalid, match="delegat"):
        verify_kel(parse_messages(agent.kel()), agent.pre)


def test_an_approval_from_someone_other_than_the_named_delegator_is_refused():
    """kel.py — the delegator must be the one the inception names, not anyone who anchored the
    seal. Mallory can anchor any seal she likes in her own log."""
    person = Controller("person")
    agent = Controller("agent", delegator=person)
    mallory = Controller("mallory")
    mallory.interact([{"i": agent.pre, "s": "0", "d": agent.pre}])

    with pytest.raises(ChainInvalid, match="delegat"):
        state_of(agent, delegator=mallory)


def test_a_delegation_chain_deeper_than_the_limit_is_refused():
    """kel.py — delegation depth. Anyone can create delegates of delegates; resolving them must
    stop somewhere."""
    from mcp_vlei.kel import MAX_DELEGATION_DEPTH, StreamKeyStates

    controllers = [Controller("root")]
    for depth in range(MAX_DELEGATION_DEPTH + 2):
        controllers.append(Controller(f"d{depth}", delegator=controllers[-1]))
    stream = "".join(c.kel() for c in controllers)

    with pytest.raises(ChainInvalid, match="terminate"):
        StreamKeyStates(parse_messages(stream)).resolve(controllers[-1].pre)


async def test_a_delegation_chain_deeper_than_the_limit_is_refused_from_witnesses():
    from mcp_vlei.kel import MAX_DELEGATION_DEPTH

    controllers = [Controller("root")]
    for depth in range(MAX_DELEGATION_DEPTH + 2):
        controllers.append(Controller(f"d{depth}", delegator=controllers[-1]))
    logs = {c.pre: c.kel() for c in controllers}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=logs.get(request.url.params.get("pre"), ""))

    resolver = WitnessKeyStates("http://witness",
                                client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ChainInvalid, match="terminate"):
        await resolver.resolve(controllers[-1].pre)


def test_a_quorum_that_cannot_be_met_is_a_configuration_error():
    """kel.py — fail at construction, not by quietly accepting fewer witnesses than configured."""
    with pytest.raises(ValueError):
        WitnessKeyStates([])
    with pytest.raises(ValueError):
        WitnessKeyStates(["http://a"], quorum=2)
    with pytest.raises(ValueError):
        WitnessKeyStates(["http://a", "http://b"], quorum=-1)  # 0 means the default majority
