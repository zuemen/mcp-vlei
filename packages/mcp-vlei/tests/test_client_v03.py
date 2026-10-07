"""The v0.3 client: proof of possession before anything is presented, a witness quorum, calls bound
to the verified server, and the server verified again when it is due."""

from __future__ import annotations

import pytest

from mcp_vlei.errors import (
    AudienceMismatch,
    ChainInvalid,
    InvalidSignature,
    MissingCredential,
    Revoked,
    UnsupportedVersion,
)
from mcp_vlei.extension import META_SIGNATURE
from mcp_vlei.testing import Controller, World
from test_client import SERVER_URL, signer_for
from test_client_verification import FakeSession, pop_server, verifying_client
from test_kel import URLS, _witnesses


@pytest.fixture
def world() -> World:
    return World()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def connected(world, tmp_path, session=None, **kwargs):
    session = session or FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, **kwargs)
    client._requirements = {"file_report": {"credential": "ECR"}}
    await client.connect()
    return client, session


async def test_calls_are_signed_for_the_verified_server_at_this_endpoint(world, tmp_path):
    client, session = await connected(world, tmp_path)
    await client.call_tool("file_report", {"period": "2026Q2"})

    signature = session.sent[0][META_SIGNATURE]
    assert signature["v"] == "vlei-sig/0.3"
    assert signature["aud"] == {"aid": world.le.pre, "url": SERVER_URL}
    assert session.sent[0]["org.gleif.vlei/credentialSaid"] == world.ecr_credential.said


async def test_nothing_is_presented_to_a_server_that_cannot_prove_its_key(world, tmp_path):
    """The impostor copied the operator's public credential; it does not have the key."""
    stranger = world.enrol(Controller("impostor", witnesses=world.witnesses, toad=2))
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, pop_client=pop_server(world, signer_for(stranger)))
    client._requirements = {"file_report": {"credential": "ECR"}}

    with pytest.raises(InvalidSignature, match="neither the server's LE"):
        await client.connect()
    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert client.server_identity is None and session.sent == []


async def test_a_failed_pop_refuses_even_when_warn_is_configured(world, tmp_path):
    """on_unverified_server='warn' excuses a server presenting no identity at all; §6.1 says it
    must not excuse a presented credential whose proof of possession could not be established."""
    stranger = world.enrol(Controller("impostor2", witnesses=world.witnesses, toad=2))
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, on_unverified_server="warn",
                              pop_client=pop_server(world, signer_for(stranger)))
    client._requirements = {"file_report": {"credential": "ECR"}}

    with pytest.raises(InvalidSignature, match="neither the server's LE"):
        await client.connect()
    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert client.server_identity is None and session.sent == []


async def test_a_pop_path_resolving_to_another_origin_is_refused(world, tmp_path):
    """An absolute pop URL in the server's own capability would send the client's challenge
    somewhere else entirely; nothing is sent there."""
    session = FakeSession(world.le_stream, capability={
        "signatureFormats": ["vlei-sig/0.3"], "pop": "http://evil.test/pop"})
    client = verifying_client(session, world, tmp_path)

    with pytest.raises(UnsupportedVersion, match="off this endpoint's own origin"):
        await client.connect()
    assert session.sent == []


async def test_a_network_relative_pop_path_is_refused(world, tmp_path):
    """A `//host/path` reference resolves against the endpoint's own scheme but still names
    another host — refused exactly as a fully absolute one is."""
    session = FakeSession(world.le_stream, capability={
        "signatureFormats": ["vlei-sig/0.3"], "pop": "//evil.test/pop"})
    client = verifying_client(session, world, tmp_path)

    with pytest.raises(UnsupportedVersion, match="off this endpoint's own origin"):
        await client.connect()
    assert session.sent == []


async def test_a_v02_server_is_unsupported_version_before_anything_is_presented(world, tmp_path):
    session = FakeSession(world.le_stream, capability={})
    client = verifying_client(session, world, tmp_path)

    with pytest.raises(UnsupportedVersion, match="does not declare vlei-sig/0.3"):
        await client.connect()
    assert session.sent == []


async def test_a_server_declaring_v03_without_a_pop_endpoint_is_unsupported_version(world, tmp_path):
    session = FakeSession(world.le_stream, capability={"signatureFormats": ["vlei-sig/0.3"]})
    with pytest.raises(UnsupportedVersion, match="no proof of possession"):
        await verifying_client(session, world, tmp_path).connect()


async def test_a_server_that_will_not_prove_itself_for_this_url_is_audience_mismatch(world, tmp_path):
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, endpoint_url="http://elsewhere.test/mcp")
    with pytest.raises(AudienceMismatch):
        await client.connect()


# --------------------------------------------------------------------------------------------- #
# A second connect() must not leave the first's identity, proof or verified-at looking current
# --------------------------------------------------------------------------------------------- #

async def test_a_second_connect_that_finds_no_credential_clears_the_first_connects_identity(world, tmp_path):
    """The server switched to presenting nothing (withdrawal, misconfiguration); the first
    connect's success must not go on authorizing calls."""
    session = FakeSession(world.le_stream)
    client, _ = await connected(world, tmp_path, session=session)
    assert client.server_identity is not None

    session.credential = None
    with pytest.raises(MissingCredential):
        await client.connect()

    assert client.server_identity is None and client.server_proof is None
    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert session.sent == []


async def test_a_second_connect_to_a_downgraded_server_clears_the_first_connects_identity(world, tmp_path):
    """The server switched to v0.2 (or stopped declaring vlei-sig/0.3); the first connect's
    success must not go on authorizing calls — the reviewer's probe: UnsupportedVersion raised,
    then the client must refuse to send anything, not reuse the stale identity."""
    session = FakeSession(world.le_stream)
    client, _ = await connected(world, tmp_path, session=session)
    assert client.server_identity is not None

    session.capability = {}
    with pytest.raises(UnsupportedVersion, match="does not declare vlei-sig/0.3"):
        await client.connect()

    assert client.server_identity is None and client.server_proof is None
    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert session.sent == []


async def test_a_second_connect_that_finds_no_credential_also_clears_the_stale_server_credential(
        world, tmp_path):
    """`pop='off'` + `on_unverified_server='warn'` is a legal, deliberately permissive
    construction: no proof of possession is required, and a server presenting no identity at all
    is tolerated. It must not let a STALE `server_credential` from an earlier, successful connect
    survive into a reconnect that found nothing — `_recipient_aid`'s unverified-credential
    fallback would otherwise sign for the OLD AID instead of refusing (the reviewer's probe:
    `session.sent` had an entry). `call_tool` refuses here rather than sending an unsigned call:
    `needs` is True (the tool requires a credential), and a v0.3 signature always names a
    recipient — with no credential presented this round there is nobody to name, exactly the
    refusal already given a client that was never told anyone's identity at all (see
    ``test_nothing_can_be_signed_for_a_server_that_names_no_one``, below). "warn" tolerates an
    unverified *session*; it does not fabricate a recipient a signature must name."""
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, pop="off", on_unverified_server="warn")
    client._requirements = {"file_report": {"credential": "ECR"}}
    await client.connect()
    assert client.server_identity is not None and client.server_credential is not None

    session.credential = None
    result = await client.connect()  # "warn": no credential at all is a tolerated outcome
    assert result is None
    assert client.server_identity is None and client.server_credential is None

    with pytest.raises(ChainInvalid, match="no recipient"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert session.sent == []


async def test_key_states_come_from_a_quorum_of_witnesses(world, tmp_path):
    """Two of three witnesses answering is enough, and the proof says so."""
    client, _ = await connected(world, tmp_path, witness_url=URLS,
                                witness_client=_witnesses(world, {"wes": {"*": "down"}}))
    proof = client.server_proof
    assert proof is not None and proof.responder_aid == world.le.pre
    assert (proof.agreeing, proof.configured) == (2, 3)


async def test_one_witness_of_three_is_not_enough(world, tmp_path):
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, witness_url=URLS,
                              witness_client=_witnesses(world, {"wil": {"*": "down"},
                                                                "wes": {"*": "down"}}))
    with pytest.raises(ChainInvalid, match="not established|only 1 of 3"):
        await client.connect()


async def test_the_pops_own_key_state_also_needs_a_quorum(world, tmp_path):
    """The responder's key state, read while checking its proof, goes through the same witness
    quorum as revocation and everything else. `on_unchecked_revocation='warn'` lets the chain
    through here so this isolates the proof's own quorum failure."""
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path, witness_url=URLS,
                              witness_client=_witnesses(world, {"wil": {"*": "down"},
                                                                "wes": {"*": "down"}}),
                              on_unchecked_revocation="warn")
    with pytest.raises(InvalidSignature, match="not established"):
        await client.connect()
    assert client.server_identity is None and session.sent == []


async def test_the_server_is_verified_again_when_it_is_due(world, tmp_path):
    clock, proofs = Clock(), []
    client, session = await connected(world, tmp_path, clock=clock,
                                      pop_client=pop_server(world, seen=proofs))
    await client.call_tool("file_report", {"period": "2026Q2"})
    assert len(proofs) == 1

    clock.now += 299
    await client.call_tool("file_report", {"period": "2026Q3"})
    assert len(proofs) == 1, "not yet due"

    clock.now += 2
    await client.call_tool("file_report", {"period": "2026Q4"})
    assert len(proofs) == 2 and len(session.sent) == 3


async def test_the_servers_ttl_shortens_the_recheck(world, tmp_path):
    clock, proofs = Clock(), []
    session = FakeSession(world.le_stream, capability={
        "signatureFormats": ["vlei-sig/0.3"], "pop": "/.well-known/vlei/pop", "ttlMs": 1000})
    client, _ = await connected(world, tmp_path, session=session, clock=clock,
                                pop_client=pop_server(world, seen=proofs))
    clock.now += 1.5
    await client.call_tool("file_report", {"period": "2026Q2"})
    assert len(proofs) == 2


async def test_a_withdrawn_le_found_at_a_recheck_stops_the_calls(world, tmp_path):
    clock = Clock()
    client, session = await connected(world, tmp_path, clock=clock)
    world.qvi_registry.revoke(world.le_credential.said)
    clock.now += 301

    with pytest.raises(Revoked):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert client.server_identity is None and session.sent == []


async def test_after_audience_mismatch_the_server_is_verified_again(world, tmp_path):
    """A refusal naming `audience_mismatch` must cost the next call a fresh proof of possession —
    not just flip a flag nothing else reads."""
    proofs: list = []
    session = FakeSession(world.le_stream, result_meta={
        "org.gleif.vlei/failure": {"layer": "audience_mismatch", "message": "not for me"}})
    client, _ = await connected(world, tmp_path, session=session,
                                pop_client=pop_server(world, seen=proofs))
    assert not client.recheck_due()
    assert len(proofs) == 1, "the initial connect already proved the server once"

    await client.call_tool("file_report", {"period": "2026Q2"})
    assert client.recheck_due()
    assert len(proofs) == 1, "no recheck yet: the mismatch was only reported by this call's result"

    session.result_meta = None
    await client.call_tool("file_report", {"period": "2026Q3"})
    assert len(proofs) == 2, "the second call re-proved the server before it was sent"
    assert len(session.sent) == 2


def test_a_client_must_say_where_it_sends_calls(world, tmp_path):
    from mcp_vlei import VleiClient
    from test_client import credential_file

    with pytest.raises(ValueError, match="endpoint_url"):
        VleiClient(object(), credential=credential_file(tmp_path, world),
                   signer=signer_for(world.agent), verify_server=False)


async def test_nothing_can_be_signed_for_a_server_that_names_no_one(world, tmp_path):
    from test_client import vlei_client

    client = vlei_client(FakeSession(None), world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}
    with pytest.raises(ChainInvalid, match="no recipient"):
        await client.call_tool("file_report", {"period": "2026Q2"})


# --------------------------------------------------------------------------------------------- #
# recheck_seconds: a non-negative, finite number — never a bool, never NaN or infinity. Zero is
# accepted: spec §6.3 gives it the meaning "re-check before every presentation".
# --------------------------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), True, None])
def test_recheck_seconds_must_be_a_non_negative_finite_number(world, tmp_path, bad):
    from test_client import vlei_client

    with pytest.raises(ValueError, match="recheck_seconds"):
        vlei_client(FakeSession(None), world, tmp_path, recheck_seconds=bad)


def test_recheck_seconds_default_still_constructs(world, tmp_path):
    from mcp_vlei.client import DEFAULT_RECHECK_SECONDS
    from test_client import vlei_client

    client = vlei_client(FakeSession(None), world, tmp_path)
    assert client.recheck_seconds == DEFAULT_RECHECK_SECONDS


def test_recheck_seconds_zero_is_accepted(world, tmp_path):
    from test_client import vlei_client

    client = vlei_client(FakeSession(None), world, tmp_path, recheck_seconds=0)
    assert client.recheck_seconds == 0


async def test_recheck_seconds_zero_rechecks_before_every_call(world, tmp_path):
    """0 means "re-check before every presentation" (spec §6.3) — not "never check again"."""
    proofs: list = []
    client, _ = await connected(world, tmp_path, recheck_seconds=0,
                                pop_client=pop_server(world, seen=proofs))
    assert len(proofs) == 1, "the initial connect already proved the server once"

    await client.call_tool("file_report", {"period": "2026Q2"})
    assert len(proofs) == 2, "due before every presentation: recheck_seconds=0"

    await client.call_tool("file_report", {"period": "2026Q3"})
    assert len(proofs) == 3


# --------------------------------------------------------------------------------------------- #
# The AID a call is signed for: never a bare ValueError, and never silently unverified
# --------------------------------------------------------------------------------------------- #

def test_a_malformed_recipient_is_chain_invalid_not_a_bare_value_error(world, tmp_path):
    """`Audience()` itself raises a bare `ValueError` for a malformed AID; a caller catching this
    client's own error vocabulary must not also have to catch that."""
    from test_client import vlei_client

    client = vlei_client(FakeSession(None), world, tmp_path, audience_aid="not-a-cesr-identifier")
    with pytest.raises(ChainInvalid, match="CESR identifier"):
        client._recipient_aid("file_report")


def test_published_audience_logs_that_it_is_unverified(world, caplog):
    """§5.3: a tool trusting a gateway by configuration must be told, in its own log, that this
    recipient was never verified — only taken from a document the gateway published about itself."""
    import logging

    from mcp_vlei.client import published_audience

    with caplog.at_level(logging.WARNING):
        audience = published_audience({"credential": world.le_stream}, SERVER_URL)

    assert audience.aid == world.le.pre and audience.url == SERVER_URL
    assert any("unverified" in r.message for r in caplog.records)
