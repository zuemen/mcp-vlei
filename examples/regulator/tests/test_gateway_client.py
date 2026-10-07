"""``call_through_gateway`` end to end, with a stand-in for agentgateway — no Docker.

The stand-in implements exactly the part of agentgateway's HTTP ``extAuthz`` this scenario relies
on: send the request body to vlei-authz; on 200 copy the ``includeResponseHeaders`` onto the request
and forward it to labor-insurance-sim; on anything else return vlei-authz's answer to the caller. The
simulator and the gateway run under uvicorn on 127.0.0.1; vlei-authz verifies against a real
KERI world. What the live stack adds on top is agentgateway itself (see deploy/agentgateway).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from conftest import ARGS, answer_at, authz_app, labor, serve, signed_meta, stand_in_gateway

import gateway_client
from mcp_vlei import Signer
from mcp_vlei.audience import Audience
from mcp_vlei.testing import LEI

@asynccontextmanager
async def gateway(world, tmp_path) -> AsyncIterator[str]:
    labor.INSURED.clear()
    authz = authz_app(world, tmp_path)
    async with serve(labor.create_app()) as upstream:
        async with serve(stand_in_gateway(authz, upstream)) as base:
            answer_at(authz, f"{base}/mcp")
            yield f"{base}/mcp"


def agent_meta(world, url, tool="enroll_employee", arguments=ARGS):
    """Built with the helper the console will use, not the test harness's own."""
    return gateway_client.signed_meta(
        credential=world.ecr_stream,
        signer=Signer.from_seed(world.agent.pre, world.agent.seed),
        tool=tool, arguments=arguments, audience=Audience(world.le.pre, url),
        delegated_aid=world.agent.pre, credential_said=world.ecr_credential.said,
    )


async def test_an_allowed_call_reaches_the_server_and_brings_back_the_report(world, tmp_path):
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "enroll_employee", ARGS,
                                                        agent_meta(world, url))

    assert set(out) == {"allowed", "layer", "text", "report", "identity"}
    assert out["allowed"] is True and out["layer"] is None, out["text"]
    assert '"status": "insured"' in out["text"] and "Simulated" in out["text"]
    assert out["report"]["allowed"] is True
    assert [c["name"] for c in out["report"]["checks"] if c["passed"]] == [
        "credential_present", "freshness", "digest", "signature",
        "delegation", "chain", "revocation", "authority",
    ]
    identity = out["identity"]
    assert identity["lei"] == LEI and identity["role"] == "labor-insurance-filing"
    assert identity["holderAid"] == world.holder.pre
    assert identity["delegateAid"] == world.agent.pre
    assert identity["credentialSaid"] == world.ecr_credential.said
    # What the simulator says it received — the only identity it ever had.
    assert identity["headers"] == {
        "x-vlei-lei": LEI,
        "x-vlei-role": "labor-insurance-filing",
        "x-vlei-holder-aid": world.holder.pre,
        "x-vlei-delegate-aid": world.agent.pre,
    }
    assert labor.INSURED["00000000"]["EMP-0001"]["filedBy"]["agentAid"] == world.agent.pre


async def test_a_refusal_names_its_layer_and_carries_the_report(world, tmp_path):
    tampered = {**ARGS, "payload": {"totalAssets": 1}}
    async with gateway(world, tmp_path) as url:
        meta = agent_meta(world, url)
        out = await gateway_client.call_through_gateway(url, "enroll_employee", tampered, meta)

    assert out["allowed"] is False
    assert out["layer"] == "digest_mismatch"
    assert out["text"].startswith("digest_mismatch: ")
    digest = next(c for c in out["report"]["checks"] if c["name"] == "digest")
    assert digest["passed"] is False
    assert out["identity"]["holderAid"] == world.holder.pre
    assert labor.INSURED == {}  # never reached


async def test_a_revoked_credential_is_refused_through_the_gateway(world, tmp_path):
    world.le_registry.revoke(world.ecr_credential.said)
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "enroll_employee", ARGS,
                                                        agent_meta(world, url))

    assert out["allowed"] is False and out["layer"] == "revoked"


async def test_someone_elses_credential_is_refused_through_the_gateway(world, tmp_path):
    from conftest import signer_for

    from mcp_vlei.testing import Controller

    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    async with gateway(world, tmp_path) as url:
        meta = signed_meta(world, signer=signer_for(mallory), delegated=None, url=url)
        out = await gateway_client.call_through_gateway(url, "enroll_employee", ARGS, meta)

    assert out["allowed"] is False and out["layer"] == "invalid_signature"


async def test_a_chain_from_a_root_nobody_accepted_is_unknown_root(world, tmp_path):
    """scripts/bootstrap-forged.sh in miniature: a second, self-made root issues a delegated QVI, an
    LE and an ECR with the same role, and its agent signs exactly as the real one does. Every key
    event log is on the witness, so the request verifies; only the root at the end differs."""
    from mcp_vlei.testing import World

    forged = World(role="labor-insurance-filing", label="forged")
    for controller in forged.controllers.values():
        world.enrol(controller)
    for registry in forged.registries:
        world.enrol_registry(registry)
    async with gateway(world, tmp_path) as url:
        # The forger signs for the gateway it attacks: the operator's LE, at its URL.
        out = await gateway_client.call_through_gateway(
            url, "enroll_employee", ARGS,
            signed_meta(forged, audience=Audience(world.le.pre, url)),
        )

    assert out["allowed"] is False and out["layer"] == "unknown_root", out["text"]
    assert out["text"].startswith("unknown_root: ")
    checks = {c["name"]: c["passed"] for c in out["report"]["checks"]}
    assert checks["signature"] is True and checks["delegation"] is True
    assert checks["chain"] is False
    assert labor.INSURED == {}  # never reached


async def test_nothing_presented_is_missing_credential_for_every_tool(world, tmp_path):
    """No tool of the simulator is public: listing an employer's insured needs the employer."""
    async with gateway(world, tmp_path) as url:
        refused = await gateway_client.call_through_gateway(url, "enroll_employee", ARGS, {})
        listed = await gateway_client.call_through_gateway(url, "list_insured", {}, {})

    assert refused["allowed"] is False and refused["layer"] == "missing_credential"
    assert listed["allowed"] is False and listed["layer"] == "missing_credential"


async def test_an_unreachable_gateway_is_reported_not_raised():
    out = await gateway_client.call_through_gateway(
        "http://127.0.0.1:9/mcp", "enroll_employee", ARGS, {}, timeout=3
    )
    assert out["allowed"] is False and out["layer"] is None
    assert "transport error" in out["text"] or "JSON-RPC" in out["text"]
