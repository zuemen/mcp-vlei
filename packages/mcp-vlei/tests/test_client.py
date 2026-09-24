"""The client side: what a vLEI-aware agent signs, and whose word it takes about the server.

Integration where it matters: a real `MCPServer` with the `VleiIdentity` extension, reached through
the SDK's in-process `Client`, with every identifier backed by a real key event log served by an
in-process witness (`mcp_vlei.testing.World`).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_vlei import Signer, VleiCapability, VleiClient, VleiIdentity, make_attestation
from mcp_vlei.errors import ChainInvalid
from mcp_vlei.extension import META_ATTESTATION
from mcp_vlei.testing import Controller, World
from mcp_vlei.verifier import VerificationResult


def signer_for(controller: Controller) -> Signer:
    return Signer.from_seed(controller.pre, controller.seed)


def credential_file(tmp_path: Path, world: World) -> Path:
    path = tmp_path / "ecr.cesr"
    path.write_text(world.ecr_stream, encoding="utf-8")
    return path


def vlei_client(session, world: World, tmp_path: Path, **kwargs) -> VleiClient:
    kwargs.setdefault("verify_server", False)
    kwargs.setdefault("on_unverified_server", "warn")
    return VleiClient(
        session,
        credential=credential_file(tmp_path, world),
        credential_said=world.ecr_credential.said,
        signer=signer_for(world.agent),
        delegated_aid=world.agent.pre,
        witness_url="http://witness",
        witness_client=world.witness_client(),
        **kwargs,
    )


# --------------------------------------------------------------------------------------------- #
# Configuration that would silently verify nothing
# --------------------------------------------------------------------------------------------- #

def test_verifying_the_server_needs_accepted_roots(tmp_path):
    """`verify_server=True` with no roots used to skip server verification without a word."""
    world = World()
    with pytest.raises(ValueError, match="accepted_roots"):
        VleiClient(
            object(),
            credential=credential_file(tmp_path, world),
            signer=signer_for(world.agent),
            verify_server=True,
        )


# --------------------------------------------------------------------------------------------- #
# What gets signed is what gets sent
# --------------------------------------------------------------------------------------------- #

async def test_a_protected_tool_that_takes_no_arguments_verifies(tmp_path):
    """The client signed `arguments: {}`; the SDK sent no arguments; the digests differed, so every
    protected tool without parameters failed `digest_mismatch`."""
    from mcp.client.client import Client
    from mcp.server.mcpserver import MCPServer

    world = World()
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    vlei = VleiIdentity(
        le_credential=le,
        accepted_roots=[world.root.pre],
        witness_url="http://witness",
        witness_client=world.witness_client(),
    )
    server = MCPServer(name="t", version="0.1.0", extensions=[vlei])
    vlei.bind(server)

    @server.tool(meta={"org.gleif.vlei/requires": {"credential": "ECR", "role": "member-registration"}})
    def ping() -> str:
        return "pong"

    async with Client(server, extensions=[VleiCapability()]) as raw:
        client = vlei_client(raw, world, tmp_path)
        await client.list_tools()
        result = await client.call_tool("ping")

    assert not result.is_error, result.content[0].text
    assert result.content[0].text == "pong"


# --------------------------------------------------------------------------------------------- #
# Attestations: whose key
# --------------------------------------------------------------------------------------------- #

def _verified_server(world: World) -> VerificationResult:
    return VerificationResult(
        aid=world.le.pre, lei="984500ABCDEF12345678", holder_aid=world.le.pre,
        credential_said=world.le_credential.said, source="well-known",
    )


def _about_the_agent(world: World) -> VerificationResult:
    return VerificationResult(
        aid=world.agent.pre, lei="984500ABCDEF12345678", role="member-registration",
        credential_said=world.ecr_credential.said, holder_aid=world.holder.pre,
    )


def _result_carrying(attestation: dict) -> SimpleNamespace:
    return SimpleNamespace(meta={META_ATTESTATION: attestation})


async def test_an_attestation_from_the_verified_server_is_accepted(tmp_path):
    world = World()
    client = vlei_client(object(), world, tmp_path)
    client.server_identity = _verified_server(world)
    attestation = make_attestation(signer_for(world.le), _about_the_agent(world))

    await client._maybe_accept_attestation(_result_carrying(attestation))

    assert client.attested is not None
    assert client.attested.attested_by == world.le.pre


async def test_an_attestation_is_not_checked_under_a_key_the_server_claims(tmp_path):
    """The key came from the server's own capability declaration — a key the attester chose."""
    world = World()
    mallory = Controller("mallory")
    client = vlei_client(object(), world, tmp_path)
    client.server_identity = _verified_server(world)
    client.server_capability = {"verkey": signer_for(mallory).verkey}
    forged = make_attestation(
        Signer.from_seed(world.le.pre, mallory.seed), _about_the_agent(world)
    )

    with pytest.raises(Exception) as caught:
        await client._maybe_accept_attestation(_result_carrying(forged))
    assert client.attested is None
    assert getattr(caught.value, "layer", None) is not None


async def test_an_attestation_signed_by_someone_other_than_the_server_is_refused(tmp_path):
    world = World()
    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    client = vlei_client(object(), world, tmp_path)
    client.server_identity = _verified_server(world)
    attestation = make_attestation(signer_for(mallory), _about_the_agent(world))

    with pytest.raises(ChainInvalid, match="server"):
        await client._maybe_accept_attestation(_result_carrying(attestation))


async def test_an_attestation_about_someone_else_is_refused(tmp_path):
    world = World()
    client = vlei_client(object(), world, tmp_path)
    client.server_identity = _verified_server(world)
    about = _about_the_agent(world)
    about.aid = about.holder_aid = "E" + "q" * 43
    attestation = make_attestation(signer_for(world.le), about)

    with pytest.raises(ChainInvalid):
        await client._maybe_accept_attestation(_result_carrying(attestation))
