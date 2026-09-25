"""The vLEI chain rules hold wherever the relying party puts its root of trust.

An ECR's LEI means something only because the LE credential it is issued under carries the same
LEI, and that LE credential was issued by a QVI that verified the entity. These tests are the
forgeries that are properly signed and properly issued but break that shape — each one accepted
before the checks they name existed.
"""

from __future__ import annotations

import json
import math

import pytest

from mcp_vlei.chain import VLEI_SCHEMAS
from mcp_vlei.errors import ChainInvalid
from mcp_vlei.signing import scope_satisfied
from mcp_vlei.testing import (
    ECR_SCHEMA,
    LE_SCHEMA,
    LEI,
    QVI_SCHEMA,
    Controller,
    Registry,
    World,
    export,
)
from mcp_vlei.verifier import OfflineVerifier

OTHER_LEI = "5493000OTHERORG00001"
PERSON = {"personLegalName": "Mallory", "engagementContextRole": "member-registration"}


@pytest.fixture
def world() -> World:
    return World()


async def verify(stream: str, said: str, roots: list[str]):
    return await OfflineVerifier(roots).verify(stream, said=said)


def attacker_entity(world: World) -> tuple[Controller, Registry, object]:
    """A genuine legal entity of the attacker's own, with a genuine LE credential from the QVI."""
    wits = dict(witnesses=world.witnesses, toad=2)
    le = world.enrol(Controller("attacker:le", **wits))
    registry = world.enrol_registry(Registry(le, "attacker:registry"))
    credential = world.issue(world.qvi_registry, LE_SCHEMA, le.pre, {"LEI": OTHER_LEI},
                             edge=("qvi", world.qvi_credential))
    return le, registry, credential


# --------------------------------------------------------------------------------------------- #
# RT3-1: the root decides whom to trust, not which rules apply
# --------------------------------------------------------------------------------------------- #

async def test_a_qvi_trusted_as_root_cannot_issue_an_ecr_for_any_lei(world):
    """A QVI verifies legal entities; it does not employ their staff. An ECR it issues itself has
    no LE credential in its chain, so nothing ties the LEI it names to anything."""
    ecr = world.issue(world.qvi_registry, ECR_SCHEMA, world.holder.pre, {"LEI": LEI, **PERSON})

    with pytest.raises(ChainInvalid, match="LE credential"):
        await verify(export([ecr]), ecr.said, [world.qvi.pre])


async def test_an_le_trusted_as_root_cannot_name_another_entitys_lei(world):
    ecr = world.issue(world.le_registry, ECR_SCHEMA, world.holder.pre, {"LEI": OTHER_LEI, **PERSON},
                      edge=("le", world.le_credential))
    stream = export([ecr, world.le_credential, world.qvi_credential])

    with pytest.raises(ChainInvalid, match="LEI"):
        await verify(stream, ecr.said, [world.le.pre])


async def test_an_le_trusted_as_root_still_verifies_its_own_staff(world):
    """The operator who trusts one legal entity directly keeps working — with the LEI checked."""
    result = await verify(world.ecr_stream, world.ecr_credential.said, [world.le.pre])

    assert result.lei == LEI
    assert result.root_aid == world.le.pre


async def test_an_ecr_is_not_accepted_without_the_le_credential_it_is_issued_under(world):
    stream = export([world.ecr_credential])

    with pytest.raises(ChainInvalid, match="not presented"):
        await verify(stream, world.ecr_credential.said, [world.le.pre])


# --------------------------------------------------------------------------------------------- #
# RT3-2: only vLEI credentials, in vLEI positions
# --------------------------------------------------------------------------------------------- #

async def test_a_credential_of_a_schema_that_is_not_vlei_is_refused(world):
    """The attacker's own entity writes the victim's LEI into a credential of a schema the vLEI
    rules do not cover, so no rule about LEIs applied to it."""
    mallory = world.enrol(Controller("attacker:mallory"))
    _, registry, le_credential = attacker_entity(world)
    fake = world.issue(registry, "E" + "A" * 43, mallory.pre, {"LEI": LEI, **PERSON},
                       edge=("le", le_credential))

    with pytest.raises(ChainInvalid, match="not a vLEI"):
        await verify(export([fake, le_credential, world.qvi_credential]), fake.said,
                     [world.root.pre])


async def test_a_qvi_credential_below_another_credential_is_refused(world):
    mallory = world.enrol(Controller("attacker:mallory"))
    _, registry, le_credential = attacker_entity(world)
    fake = world.issue(registry, QVI_SCHEMA, mallory.pre, {"LEI": LEI, **PERSON},
                       edge=("le", le_credential))

    with pytest.raises(ChainInvalid, match="QVI"):
        await verify(export([fake, le_credential, world.qvi_credential]), fake.said,
                     [world.root.pre])


async def test_an_ecr_role_is_read_from_the_ecr_role_field(world):
    """`officialRole` is the OOR's field. An ECR carrying one has not been given that role."""
    ecr = world.issue(world.le_registry, ECR_SCHEMA, world.holder.pre,
                      {"LEI": LEI, "personLegalName": "Mallory", "officialRole": "CEO"},
                      edge=("le", world.le_credential))
    result = await verify(export([ecr, world.le_credential, world.qvi_credential]), ecr.said,
                          [world.root.pre])

    assert result.role is None


async def test_an_oor_role_is_read_from_the_oor_role_field(world):
    oor = world.issue(world.le_registry, VLEI_SCHEMAS["OOR"], world.holder.pre,
                      {"LEI": LEI, "personLegalName": "Chen", "officialRole": "CFO"},
                      edge=("le", world.le_credential))
    result = await verify(export([oor, world.le_credential, world.qvi_credential]), oor.said,
                          [world.root.pre])

    assert result.role == "CFO"


# --------------------------------------------------------------------------------------------- #
# RT3-3..5: scope comparison never answers yes by accident
# --------------------------------------------------------------------------------------------- #

def test_a_held_nan_satisfies_no_numeric_requirement():
    held = json.loads('{"maxAmount": NaN}')
    assert math.isnan(held["maxAmount"])

    ok, _ = scope_satisfied({"maxAmount": 1_000_000}, held)
    assert not ok


def test_a_boolean_requirement_is_not_met_by_a_number():
    ok, _ = scope_satisfied({"admin": True}, {"admin": 1})
    assert not ok


@pytest.mark.parametrize("held", ["maxAmount", ["maxAmount"], 5])
def test_a_scope_that_is_not_an_object_is_refused_not_crashed(held):
    ok, reason = scope_satisfied({"maxAmount": 5}, held)
    assert not ok and "object" in reason


# --------------------------------------------------------------------------------------------- #
# RT3-2: the server's own requirement applies when a tool names no credential type
# --------------------------------------------------------------------------------------------- #

async def test_a_tool_that_names_only_a_role_still_gets_the_servers_credential_type(world, tmp_path):
    """The capability says this server requires an ECR. A tool declaring only a role must not
    accept an OOR whose office happens to share the role's name."""
    from test_extension import build, call_next, layer_of, present

    oor = world.issue(world.le_registry, VLEI_SCHEMAS["OOR"], world.holder.pre,
                      {"LEI": LEI, "personLegalName": "Chen", "officialRole": "member-registration"},
                      edge=("le", world.le_credential))
    ext = build(world, tmp_path, {"register_member": {"role": "member-registration"}})
    params = present(world, "register_member", {"name": "A"},
                     stream=export([oor, world.le_credential, world.qvi_credential]),
                     said=oor.said)

    result = await ext.intercept_tool_call(params, None, call_next)

    assert result.is_error
    assert layer_of(result) == "chain_invalid"
