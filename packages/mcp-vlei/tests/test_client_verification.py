"""What the client establishes about the server before it signs anything for it.

The question an official asks is the reverse of the talk's: how does the agent know the other side
is really the regulator? Each test here is a way the client used to answer "verified" too easily,
and failed before its fix.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcp_vlei import Signer, make_attestation
from mcp_vlei.attest import verify_attestation
from mcp_vlei.errors import ChainInvalid, InvalidSignature, Revoked
from mcp_vlei.extension import EXTENSION_ID, META_ATTESTATION, META_CREDENTIAL
from mcp_vlei.testing import Controller, Key, World
from mcp_vlei.verifier import VerificationResult
from test_client import signer_for, vlei_client


class FakeSession:
    """An MCP session whose server presents `credential` and records what the client sends."""

    def __init__(self, credential: str | None, result_meta: dict | None = None) -> None:
        self.credential = credential
        self.result_meta = result_meta
        self.sent: list[dict | None] = []

    async def initialize(self):
        meta = {META_CREDENTIAL: self.credential} if self.credential else {}
        return SimpleNamespace(capabilities=SimpleNamespace(extensions={EXTENSION_ID: {}}),
                               meta=meta)

    async def call_tool(self, name, arguments, meta=None):
        self.sent.append(meta)
        return SimpleNamespace(content=[], is_error=False, meta=self.result_meta)


@pytest.fixture
def world() -> World:
    return World()


def verifying_client(session, world, tmp_path, **kwargs):
    kwargs.setdefault("on_unverified_server", "stop")
    return vlei_client(session, world, tmp_path, verify_server=True,
                       accepted_roots=[world.root.pre], **kwargs)


# --------------------------------------------------------------------------------------------- #
# RT6-1: a server is an entity, so it presents an entity's credential
# --------------------------------------------------------------------------------------------- #

async def test_a_server_presenting_someones_role_credential_is_not_that_entity(world, tmp_path):
    """Every agent hands a server its ECR chain on every protected call. Presented back as the
    server's identity, it claimed to be a person in a role. What this does not settle: the same
    stream contains the employer's LE chain, and a server presenting that passes — no server proves
    it holds the LE's keys (a specification gap, not closed here)."""
    client = verifying_client(FakeSession(world.ecr_stream), world, tmp_path)

    with pytest.raises(ChainInvalid, match="LE"):
        await client.connect()
    assert client.server_identity is None


async def test_a_server_presenting_its_le_credential_is_verified(world, tmp_path):
    client = verifying_client(FakeSession(world.le_stream), world, tmp_path)

    identity = await client.connect()

    assert identity.lei == "984500ABCDEF12345678"
    assert identity.holder_aid == world.le.pre


# --------------------------------------------------------------------------------------------- #
# RT6-6: the server's credential is checked for revocation where a witness can say
# --------------------------------------------------------------------------------------------- #

async def test_a_server_whose_credential_was_withdrawn_is_not_verified(world, tmp_path):
    world.qvi_registry.revoke(world.le_credential.said)
    client = verifying_client(FakeSession(world.le_stream), world, tmp_path)

    with pytest.raises(Revoked):
        await client.connect()


async def test_a_verified_server_says_its_revocation_was_checked(world, tmp_path):
    client = verifying_client(FakeSession(world.le_stream), world, tmp_path)

    identity = await client.connect()

    assert identity.revocation_checked is True


# --------------------------------------------------------------------------------------------- #
# RT6-3: nothing is signed for a server the client was told to verify and has not
# --------------------------------------------------------------------------------------------- #

async def test_nothing_is_signed_for_a_server_that_was_never_verified(world, tmp_path):
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}

    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert session.sent == []


async def test_nothing_is_signed_after_verification_failed(world, tmp_path):
    session = FakeSession(world.ecr_stream)
    client = verifying_client(session, world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}
    with pytest.raises(ChainInvalid):
        await client.connect()

    with pytest.raises(ChainInvalid, match="not been verified"):
        await client.call_tool("file_report", {"period": "2026Q2"})
    assert session.sent == []


async def test_a_verified_server_gets_signed_calls(world, tmp_path):
    session = FakeSession(world.le_stream)
    client = verifying_client(session, world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}
    await client.connect()

    await client.call_tool("file_report", {"period": "2026Q2"})

    assert session.sent and META_CREDENTIAL in session.sent[0]


async def test_choosing_to_talk_to_unverified_servers_is_still_possible(world, tmp_path):
    session = FakeSession(None)
    client = vlei_client(session, world, tmp_path)  # verify_server=False, warn
    client._requirements = {"file_report": {"credential": "ECR"}}

    await client.call_tool("file_report", {"period": "2026Q2"})

    assert session.sent and META_CREDENTIAL in session.sent[0]


# --------------------------------------------------------------------------------------------- #
# RT6-5: a bad attestation is rejected, not allowed to throw away a result that already happened
# --------------------------------------------------------------------------------------------- #

async def test_a_rejected_attestation_does_not_discard_the_tool_result(world, tmp_path):
    """The tool has already run; raising here told the agent it failed, and it would retry."""
    session = FakeSession(None, result_meta={META_ATTESTATION: {"verifierAid": "garbage"}})
    client = vlei_client(session, world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}

    result = await client.call_tool("file_report", {"period": "2026Q2"})

    assert result is not None and not result.is_error
    assert client.attested is None
    assert client.attestation_rejected is not None


# --------------------------------------------------------------------------------------------- #
# RT6-7: an attester whose keys require several signatures has not attested with one
# --------------------------------------------------------------------------------------------- #

def test_an_attestation_from_a_multi_signature_attester_is_refused(world):
    about = VerificationResult(aid=world.agent.pre, lei="984500ABCDEF12345678",
                               holder_aid=world.holder.pre, credential_said="E" + "c" * 43)
    one, two = Key("board:1"), Key("board:2")
    attestation = make_attestation(Signer.from_seed(world.le.pre, one.seed), about)

    with pytest.raises(InvalidSignature, match="signatures"):
        verify_attestation(attestation, verifier_verkey=[one.qb64, two.qb64], threshold=2)


def test_a_single_signature_attester_still_attests(world):
    about = VerificationResult(aid=world.agent.pre, lei="984500ABCDEF12345678",
                               holder_aid=world.holder.pre, credential_said="E" + "c" * 43)
    one = Key("board:1")
    attestation = make_attestation(Signer.from_seed(world.le.pre, one.seed), about)

    assert verify_attestation(attestation, verifier_verkey=[one.qb64], threshold=1).lei


# --------------------------------------------------------------------------------------------- #
# From the review of the fix above
# --------------------------------------------------------------------------------------------- #

async def test_a_server_whose_revocation_cannot_be_read_is_verified_but_says_so(world, tmp_path):
    """The client's witness has never seen the issuer's registry — the usual case when issuers use
    their own witnesses. Refusing every such server would make the check a denial of service; the
    identity is established and says revocation was not."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("typ") == "tel":
            return httpx.Response(200, text="")
        return world.witness_handler(request)

    client = verifying_client(FakeSession(world.le_stream), world, tmp_path,
                              witness_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    identity = await client.connect()

    assert identity is not None and identity.revocation_checked is False


async def test_each_call_reports_its_own_attestation(world, tmp_path):
    """A rejected attestation must not leave an earlier accepted one looking current."""
    session = FakeSession(None, result_meta={META_ATTESTATION: {"verifierAid": "garbage"}})
    client = vlei_client(session, world, tmp_path)
    client._requirements = {"file_report": {"credential": "ECR"}}
    client.attested = VerificationResult(aid="E" + "x" * 43, lei="L")  # left from an earlier call

    await client.call_tool("file_report", {"period": "2026Q2"})

    assert client.attested is None and client.attestation_rejected is not None

    session.result_meta = None
    await client.call_tool("file_report", {"period": "2026Q3"})

    assert client.attestation_rejected is None
