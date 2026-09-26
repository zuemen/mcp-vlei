"""Revocation is established, or the record says it was not — in every mode.

The specification requires every link of the chain to be checked against its issuer's live
transaction event log. `revocation_source="verifier"` used to mark revocation established on any
200 from a vlei-verifier — whose own revocation check ships switched off — and asked it about the
leaf only; `"none"` left no trace in the decision record. Each test here failed before its fix.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from conftest import Ctx, StubVerifier  # noqa: E402
from mcp_vlei import VleiIdentity
from mcp_vlei.errors import ChainInvalid
from mcp_vlei.testing import World
from mcp_vlei.verifier import VleiVerifier
from test_extension import ARGS, REQUIRES_REGISTRATION, build, call_next, layer_of, present


@pytest.fixture
def world() -> World:
    return World()


async def test_verifier_mode_checks_every_links_transaction_event_log(world, tmp_path):
    """The legal entity's credential is withdrawn; a vlei-verifier that does not check revocation
    still answers 200 about the ECR."""
    world.qvi_registry.revoke(world.le_credential.said)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                revocation_source="verifier", verifier=StubVerifier())

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_verifier_mode_still_allows_a_live_chain(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                revocation_source="verifier", verifier=StubVerifier())

    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert not result.is_error


async def test_a_verifier_answer_that_does_not_name_its_credential_is_not_an_answer():
    """A holder re-issued a fresh ECR after the old one was revoked; the service answers 200 about
    the holder without saying which credential. The old one must not pass on the new one's word."""
    aid, presented = "E" + "h" * 43, "E" + "o" * 43

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"aid": aid, "lei": "984500ABCDEF12345678", "role": "r"})

    verifier = VleiVerifier("http://verifier", accepted_roots=["E" + "r" * 43],
                            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ChainInvalid, match="which credential"):
        await verifier.verify("cesr", said=presented, aid=aid)


@pytest.mark.parametrize("source, checked", [("tel", True), ("none", False)])
async def test_the_decision_record_says_whether_revocation_was_checked(world, tmp_path, source,
                                                                        checked):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                revocation_source=source)

    await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert ext.records[-1]["revocationChecked"] is checked


def test_turning_revocation_off_is_said_out_loud(world, tmp_path, caplog):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        VleiIdentity(le_credential=le, accepted_roots=[world.root.pre],
                     witness_url="http://witness", revocation_source="none")

    assert any("revocation" in r.message.lower() for r in caplog.records)


# --------------------------------------------------------------------------------------------- #
# RT1-02: arguments no signature can cover are a refusal with a layer, not a crash
# --------------------------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
async def test_arguments_json_cannot_carry_are_refused_and_recorded(world, tmp_path, value):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", {**ARGS, "amount": 1})
    params.arguments["amount"] = value

    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "digest_mismatch"
    assert ext.records and ext.records[-1]["allowed"] is False


# --------------------------------------------------------------------------------------------- #
# From the review of the fix above
# --------------------------------------------------------------------------------------------- #

async def test_a_vlei_verifier_answer_does_not_claim_a_revocation_check():
    """The service's own revocation check ships off; its 200 says nothing either way."""
    aid, said = "E" + "h" * 43, "E" + "s" * 43

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"aid": aid, "said": said, "lei": "984500ABCDEF12345678",
                                         "role": "r"})

    verifier = VleiVerifier("http://verifier", accepted_roots=["E" + "r" * 43],
                            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    result = await verifier.verify("cesr", said=said, aid=aid)

    assert result.revocation_checked is False


async def test_a_refused_call_is_recorded_as_not_revocation_checked(world, tmp_path):
    world.le_registry.revoke(world.ecr_credential.said)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})

    await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert ext.records[-1]["allowed"] is False
    assert ext.records[-1]["revocationChecked"] is False


async def test_verifier_mode_does_not_lend_the_credential_a_role_it_does_not_carry(world, tmp_path):
    """An ECR with no engagement context role, only an `officialRole`; the service's record says
    the role the tool wants. The presented credential decides, not the service's summary of it."""
    from mcp_vlei.testing import ECR_SCHEMA, LEI, export

    ecr = world.issue(world.le_registry, ECR_SCHEMA, world.holder.pre,
                      {"LEI": LEI, "personLegalName": "Chen", "officialRole": "member-registration"},
                      edge=("le", world.le_credential))
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                revocation_source="verifier", verifier=StubVerifier(role="member-registration"))
    params = present(world, "register_member", ARGS,
                     stream=export([ecr, world.le_credential, world.qvi_credential]),
                     said=ecr.said)

    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert result.is_error


async def test_arguments_with_values_json_does_not_have_are_refused(world, tmp_path):
    from datetime import datetime, timezone

    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", {**ARGS, "when": "now"})
    params.arguments["when"] = datetime.now(timezone.utc)

    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "digest_mismatch"
