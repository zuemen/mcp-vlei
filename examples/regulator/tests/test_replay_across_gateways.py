"""The replay the review council found, end to end: a call captured at one gateway, sent to another.

Two stand-in gateways in front of one simulator, each with its own vlei-authz. A call signed for
gateway A is allowed at A once, refused at B — whoever operates B — and refused at A again.
"""

from __future__ import annotations

from typing import Any

from conftest import ARGS, answer_at, authz_app, labor, serve, signed_meta, stand_in_gateway

import gateway_client
from mcp_vlei.testing import LE_SCHEMA, Controller, export


def another_operator(world) -> str:
    """A second legal entity's LE credential, from the same QVI: another gateway's operator."""
    other = world.enrol(Controller("other-operator", witnesses=world.witnesses, toad=2))
    le = world.issue(world.qvi_registry, LE_SCHEMA, other.pre, {"LEI": "984500OTHEROP0000012"},
                     edge=("qvi", world.qvi_credential))
    return export([le, world.qvi_credential])


class _CountingInsured(dict):
    """A drop-in for ``labor.INSURED`` that counts every delivery of ``enroll_employee`` to the
    simulator — the one statement (``INSURED.setdefault(ubn, {})[person_ref] = record``) its body
    always reaches, whether or not a record already exists. ``enroll_employee`` replaces by
    ``person_ref``, so the dict's own size cannot tell a second delivery from the first; this can,
    because it is ground truth about how many times the simulator actually ran the tool, not about
    what it ended up storing."""

    def __init__(self) -> None:
        super().__init__()
        self.deliveries = 0

    def setdefault(self, key: Any, default: Any = None) -> Any:
        self.deliveries += 1
        return super().setdefault(key, default)


async def replay_from_a_to_b(world, tmp_path, *, b_operator: str | None) -> None:
    """Gateway B is operated by ``b_operator`` (an LE stream), or by A's operator when None."""
    original_insured = labor.INSURED
    insured = _CountingInsured()
    labor.INSURED = insured
    try:
        gateway_a = authz_app(world, tmp_path / "a")
        gateway_b = authz_app(world, tmp_path / "b", le_stream=b_operator)
        async with serve(labor.create_app()) as upstream:
            async with serve(stand_in_gateway(gateway_a, upstream)) as base_a:
                async with serve(stand_in_gateway(gateway_b, upstream)) as base_b:
                    url_a, url_b = f"{base_a}/mcp", f"{base_b}/mcp"
                    answer_at(gateway_a, url_a)
                    answer_at(gateway_b, url_b)
                    captured = signed_meta(world, url=url_a)

                    first = await gateway_client.call_through_gateway(url_a, "enroll_employee", ARGS, captured)
                    at_b = await gateway_client.call_through_gateway(url_b, "enroll_employee", ARGS, captured)
                    again = await gateway_client.call_through_gateway(url_a, "enroll_employee", ARGS, captured)
    finally:
        labor.INSURED = original_insured

    assert first["allowed"] is True, first["text"]
    assert at_b["allowed"] is False and at_b["layer"] == "audience_mismatch", at_b["text"]
    # The specific recipient-mismatch message — not just the layer — so a refusal for an unrelated
    # reason that happens to share the layer name cannot pass as this scenario. The exact wording
    # differs by which half of the recipient (AID or URL) does not match.
    assert ("not for this server" in at_b["text"] or "is not this server's endpoint" in at_b["text"]), \
        at_b["text"]
    assert again["allowed"] is False and again["layer"] == "stale_signature", again["text"]
    # Specifically the nonce already spent — not merely "stale_signature", which the *other*
    # stale-signature message (a store whose memory began after this signature was made) also
    # carries the word "replay" in, and would make this assertion pass for the wrong reason: a
    # gateway that forgot everything rather than one that remembered this exact call.
    assert "already presented" in again["text"] and "nonce is spent" in again["text"], again["text"]
    # Ground truth: the simulator itself was asked to enrol EMP-0001 exactly once. INSURED's own
    # size cannot show this (enroll_employee replaces by person_ref), so a second delivery that
    # happened to carry identical arguments would otherwise go unnoticed.
    assert insured.deliveries == 1, f"enroll_employee reached the simulator {insured.deliveries} time(s)"


async def test_a_call_captured_at_one_gateway_is_refused_at_another_entitys(world, tmp_path):
    await replay_from_a_to_b(world, tmp_path, b_operator=another_operator(world))


async def test_a_call_captured_at_one_gateway_is_refused_at_another_of_the_same_entity(world, tmp_path):
    """The same operator, another endpoint: the URL in the signature is what tells them apart."""
    await replay_from_a_to_b(world, tmp_path, b_operator=None)
