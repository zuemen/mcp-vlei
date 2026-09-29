"""Issuance: was each credential in the chain actually issued by the identifier it names?

A SAID proves a credential was not altered after it was made; it says nothing about who made it.
Anyone can write an ECR naming a real LE as its issuer and themselves as the issuee, and every SAID
in it will recompute. What they cannot do is make the LE's key event log anchor its issuance — that
takes the LE's keys. These tests are the forgeries that used to pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_vlei.testing import ECR_SCHEMA, LE_SCHEMA, LEI, Controller, Credential, Registry, World, acdc, export
from mcp_vlei.chain import parse_stream
from mcp_vlei.errors import ChainInvalid, UnknownRoot
from mcp_vlei.verifier import OfflineVerifier

REAL_EXPORT = Path(__file__).resolve().parents[3] / "credentials" / "ecr.cesr"

ECR_ATTRIBUTES = {
    "LEI": LEI,
    "personLegalName": "Mallory",
    "engagementContextRole": "member-registration",
}


@pytest.fixture(scope="module")
def world() -> World:
    return World()


async def test_a_chain_issued_through_registries_verifies(world: World):
    result = await OfflineVerifier([world.root.pre]).verify(
        world.ecr_stream, said=world.ecr_credential.said
    )

    assert result.signatures_checked is True
    assert result.holder_aid == world.holder.pre
    assert result.lei == LEI
    assert result.chain_saids == [c.said for c in world.chain]


async def test_a_credential_its_issuer_never_anchored_is_refused(world: World):
    """Written by someone else, naming the real LE as issuer — no issuance event anywhere."""
    mallory = Controller("mallory")
    forged = world.issue(
        world.le_registry, ECR_SCHEMA, mallory.pre, ECR_ATTRIBUTES,
        edge=("le", world.le_credential), anchor=False,
    )
    stream = export([forged, world.le_credential, world.qvi_credential])

    with pytest.raises(ChainInvalid, match="anchor"):
        await OfflineVerifier([world.root.pre]).verify(stream, said=forged.said)


async def test_an_issuance_from_someone_elses_registry_is_refused(world: World):
    """Mallory issues it properly — from Mallory's own registry — and names the LE as issuer."""
    mallory = Controller("mallory")
    registry = Registry(mallory, "mallory-registry")
    raw = acdc(
        ECR_SCHEMA, world.le.pre, mallory.pre, registry.regk, ECR_ATTRIBUTES,
        edge=("le", world.le_credential.said, LE_SCHEMA),
    )
    forged = Credential(raw, registry)
    registry.issue(forged.said)
    stream = export([forged, world.le_credential, world.qvi_credential])

    with pytest.raises(ChainInvalid, match="registry"):
        await OfflineVerifier([world.root.pre]).verify(stream, said=forged.said)


async def test_a_stream_without_the_issuers_log_is_refused(world: World):
    """Nothing to check the anchor against is not the same as the anchor being there."""
    stream = "".join(c.raw for c in reversed(world.chain))

    with pytest.raises(ChainInvalid):
        await OfflineVerifier([world.root.pre]).verify(stream, said=world.ecr_credential.said)


async def test_a_chain_to_a_root_we_do_not_accept_names_the_root(world: World):
    """`unknown_root`, not `chain_invalid`: nothing is wrong with the chain; the parties disagree."""
    with pytest.raises(UnknownRoot):
        await OfflineVerifier(["E" + "x" * 43]).verify(
            world.ecr_stream, said=world.ecr_credential.said
        )


async def test_an_upper_link_that_was_never_issued_is_refused():
    """Forging the QVI credential is the same attack one level up."""
    world = World(label="forged-qvi")
    world.qvi_registry.tels.clear()
    with pytest.raises(ChainInvalid):
        await OfflineVerifier([world.root.pre]).verify(
            world.ecr_stream, said=world.ecr_credential.said
        )


# --------------------------------------------------------------------------------------------- #
# Whose LEI: properly issued credentials, in a chain that does not mean what it claims
# --------------------------------------------------------------------------------------------- #

async def test_an_ecr_a_qvi_issued_without_any_le_is_refused(world: World):
    """A QVI issues an ECR straight off its own QVI credential, naming any LEI it likes.

    Every issuance is anchored, every SAID recomputes, the root is accepted — and no legal entity
    ever granted the role. An ECR is an LE's statement about its own staff; without an LE credential
    in the chain there is nobody whose statement it is.
    """
    forged = world.issue(
        world.qvi_registry, ECR_SCHEMA, world.holder.pre,
        {"LEI": "5299000000000000EVIL", "personLegalName": "Mallory",
         "engagementContextRole": "member-registration"},
        edge=("le", world.qvi_credential),
    )
    stream = export([forged, world.qvi_credential])

    with pytest.raises(ChainInvalid, match="LE"):
        await OfflineVerifier([world.root.pre]).verify(stream, said=forged.said)


async def test_an_ecr_naming_another_entitys_lei_is_refused(world: World):
    """A real LE, correctly anchored, issuing an ECR for someone else's LEI."""
    forged = world.issue(
        world.le_registry, ECR_SCHEMA, world.holder.pre,
        {"LEI": "5299000000000000EVIL", "personLegalName": "Mallory",
         "engagementContextRole": "member-registration"},
        edge=("le", world.le_credential),
    )
    stream = export([forged, world.le_credential, world.qvi_credential])

    with pytest.raises(ChainInvalid, match="LEI"):
        await OfflineVerifier([world.root.pre]).verify(stream, said=forged.said)


async def test_an_edge_must_point_at_the_type_it_declares(world: World):
    """The edge says "an LE credential"; what it resolves to is a QVI credential."""
    from mcp_vlei.testing import QVI_SCHEMA, acdc

    raw = acdc(
        ECR_SCHEMA, world.qvi.pre, world.holder.pre, world.qvi_registry.regk,
        {"LEI": LEI, "personLegalName": "Mallory", "engagementContextRole": "x"},
        edge=("le", world.qvi_credential.said, LE_SCHEMA),
    )
    forged = Credential(raw, world.qvi_registry)
    world.qvi_registry.issue(forged.said)
    stream = export([forged, world.qvi_credential])

    with pytest.raises(ChainInvalid):
        await OfflineVerifier([world.root.pre]).verify(stream, said=forged.said)
    assert QVI_SCHEMA != LE_SCHEMA


@pytest.mark.skipif(not REAL_EXPORT.is_file(), reason="needs a bootstrapped credentials/ecr.cesr")
async def test_a_chain_issued_by_kli_verifies():
    stream = REAL_EXPORT.read_text(encoding="utf-8")
    credentials = parse_stream(stream)
    root = next(c.issuer for c in credentials.values() if not c.edges)
    result = await OfflineVerifier([root]).verify(stream)

    assert result.signatures_checked is True
    assert len(result.chain_saids) == 3
