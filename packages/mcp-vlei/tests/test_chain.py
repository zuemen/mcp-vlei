"""Offline chain verification — mode (a).

The chains here are minted in the test rather than fixtured, which means the SAIDs are computed the
same way the verifier recomputes them. A bug in that computation fails these tests instead of
quietly agreeing with itself.

The real chain issued by ``scripts/bootstrap-credentials.sh`` is exercised by
``examples/association-server/tests``.
"""

from __future__ import annotations

import base64
import json

import pytest

from mcp_vlei.chain import parse_stream, recompute_said, walk_chain
from mcp_vlei.testing import World
from mcp_vlei.errors import ChainInvalid, MissingCredential, RoleMismatch, UnknownRoot
from mcp_vlei.verifier import OfflineVerifier

ROOT = "EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"
QVI_AID = "EDFRI3MOLPx4mOQNKlHOS1O_JLWMGRFiaiwO1FSxheW0"
LE_AID = "EKPdng_ffec4VInvOsswAeIoe0C0LtDDBbk-5YbDHDMe"
HOLDER = "EHLragWzyPdQ_JFPHAQXn3IqdeQaVRRqy_iDvMXYwqz4"
REGISTRY = "EHsH7DfMGlfOsAVjTw1EZMhbHQJovsqmBYXHFYDgiz2K"

QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
ECR_SCHEMA = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"

LEI = "984500ABCDEF12345678"


def mint(schema: str, issuer: str, issuee: str, attributes: dict, edge: tuple[str, str] | None = None) -> str:
    """Serialize a credential and fill in the SAID its contents imply."""
    import blake3

    body: dict = {
        "v": "ACDC10JSON000000_",
        "d": "#" * 44,
        "i": issuer,
        "ri": REGISTRY,
        "s": schema,
        "a": {"i": issuee, "dt": "2026-09-23T00:00:00.000000+00:00", **attributes},
    }
    if edge:
        label, target = edge
        body["e"] = {"d": "E" + "A" * 43, label: {"n": target, "s": schema}}

    text = json.dumps(body, separators=(",", ":"))
    digest = blake3.blake3(text.encode("utf-8")).digest(length=32)
    said = "E" + base64.urlsafe_b64encode(b"\x00" + digest).decode("ascii")[1:]
    return text.replace('"d":"' + "#" * 44 + '"', f'"d":"{said}"', 1)


@pytest.fixture
def chain_stream() -> str:
    """root -> QVI -> LE -> ECR, as one stream."""
    qvi = mint(QVI_SCHEMA, ROOT, QVI_AID, {"LEI": LEI})
    qvi_said = json.loads(qvi)["d"]
    le = mint(LE_SCHEMA, QVI_AID, LE_AID, {"LEI": LEI}, edge=("qvi", qvi_said))
    le_said = json.loads(le)["d"]
    ecr = mint(
        ECR_SCHEMA, LE_AID, HOLDER,
        {"LEI": LEI, "personLegalName": "Chen Wei-Ting", "engagementContextRole": "regulatory-filing"},
        edge=("le", le_said),
    )
    return qvi + le + ecr


@pytest.fixture
def ecr_said(chain_stream: str) -> str:
    return list(parse_stream(chain_stream))[-1]


# --------------------------------------------------------------------------------------------- #
# Parsing and SAID recomputation
# --------------------------------------------------------------------------------------------- #

def test_parses_every_credential_in_the_stream(chain_stream: str):
    assert len(parse_stream(chain_stream)) == 3


def test_every_said_recomputes(chain_stream: str):
    for credential in parse_stream(chain_stream).values():
        assert recompute_said(credential) == credential.said


def test_altering_a_field_breaks_the_said(chain_stream: str, ecr_said: str):
    """The SAID is a digest over the content, so tampering is detectable without any key."""
    tampered = chain_stream.replace('"regulatory-filing"', '"chief-executive"')
    with pytest.raises(ChainInvalid, match="does not hash to its own SAID"):
        walk_chain(parse_stream(tampered), ecr_said, [ROOT])


# --------------------------------------------------------------------------------------------- #
# Walking the chain
# --------------------------------------------------------------------------------------------- #

def test_walks_to_the_root(chain_stream: str, ecr_said: str):
    chain = walk_chain(parse_stream(chain_stream), ecr_said, [ROOT])

    assert [link.issuer for link in chain] == [LE_AID, QVI_AID, ROOT]
    assert chain[0].role == "regulatory-filing"
    assert chain[-1].issuer == ROOT


def test_a_root_we_do_not_accept_is_refused(chain_stream: str, ecr_said: str):
    """Nothing is wrong with the credential. Two organizations disagree about whom they trust.

    So the layer is `unknown_root`, not `chain_invalid` — the remedy is a conversation between the
    two parties, not a new credential, and the skill tells the agent which one it is facing.
    """
    with pytest.raises(UnknownRoot, match="not an accepted root"):
        walk_chain(parse_stream(chain_stream), ecr_said, ["ESomeoneElsesRootXXXXXXXXXXXXXXXXXXXXXXXXXXX"])


def test_a_missing_link_is_named(chain_stream: str, ecr_said: str):
    """Drop the LE credential: the ECR's edge then points at something not presented."""
    without_le = "".join(
        text for said, text in _texts(chain_stream).items()
        if json.loads(text)["s"] != LE_SCHEMA
    )
    with pytest.raises(ChainInvalid, match="was not presented with it"):
        walk_chain(parse_stream(without_le), ecr_said, [ROOT])


def test_a_credential_not_in_the_stream_is_named(chain_stream: str):
    with pytest.raises(ChainInvalid, match="not present in the stream"):
        walk_chain(parse_stream(chain_stream), "E" + "z" * 43, [ROOT])


def test_a_chain_whose_issuer_does_not_match_the_edge_is_refused():
    """An edge that resolves, to a credential issued to someone else, is a broken chain."""
    qvi = mint(QVI_SCHEMA, ROOT, QVI_AID, {"LEI": LEI})
    qvi_said = json.loads(qvi)["d"]
    # Issued by an identifier the QVI credential was never issued to.
    rogue = mint(LE_SCHEMA, "EImpostorXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", LE_AID,
                 {"LEI": LEI}, edge=("qvi", qvi_said))
    stream = qvi + rogue
    with pytest.raises(ChainInvalid, match="the chain is broken here"):
        walk_chain(parse_stream(stream), json.loads(rogue)["d"], [ROOT])


# --------------------------------------------------------------------------------------------- #
# OfflineVerifier
# --------------------------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def issued() -> World:
    """A chain issued through real registries: what the offline verifier now requires."""
    return World(role="regulatory-filing", label="offline")


async def test_offline_verifier_establishes_the_entity(issued: World):
    result = await OfflineVerifier([issued.root.pre]).verify(
        issued.ecr_stream, said=issued.ecr_credential.said
    )

    assert result.lei == LEI
    assert result.role == "regulatory-filing"
    assert result.holder_aid == issued.holder.pre
    assert result.root_aid == issued.root.pre


async def test_offline_verifier_admits_what_it_did_not_check(issued: World):
    """'Checked as far as we could' is not 'valid': issuance is established offline, revocation is not."""
    result = await OfflineVerifier([issued.root.pre]).verify(
        issued.ecr_stream, said=issued.ecr_credential.said
    )

    assert result.signatures_checked is True
    assert result.revocation_checked is False


async def test_offline_verifier_finds_the_leaf_without_being_told(issued: World):
    """A --full export carries the chain; the leaf is the credential nothing points at."""
    result = await OfflineVerifier([issued.root.pre]).verify(issued.ecr_stream)
    assert result.role == "regulatory-filing"


async def test_offline_verifier_checks_the_role(issued: World):
    with pytest.raises(RoleMismatch):
        await OfflineVerifier([issued.root.pre]).verify(
            issued.ecr_stream, said=issued.ecr_credential.said, expected_role="member-registration"
        )


async def test_offline_verifier_refuses_an_empty_credential():
    with pytest.raises(MissingCredential):
        await OfflineVerifier([ROOT]).verify("")


async def test_offline_verifier_refuses_a_stream_with_no_credential():
    with pytest.raises(ChainInvalid, match="no credential was found"):
        await OfflineVerifier([ROOT]).verify('{"v":"KERI10JSON","t":"icp","d":"E","i":"E"}')


def test_empty_accepted_roots_is_a_configuration_error():
    with pytest.raises(ValueError, match="accepted_roots"):
        OfflineVerifier([])


# --------------------------------------------------------------------------------------------- #

def _texts(stream: str) -> dict[str, str]:
    return {credential.said: credential.raw for credential in parse_stream(stream).values()}
