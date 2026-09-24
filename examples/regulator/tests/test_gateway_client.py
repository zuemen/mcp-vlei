"""``call_through_gateway`` end to end, with a stand-in for agentgateway — no Docker.

The stand-in implements exactly the part of agentgateway's HTTP ``extAuthz`` this scenario relies
on: send the request body to vlei-authz; on 200 copy the ``includeResponseHeaders`` onto the request
and forward it to filing-server; on anything else return vlei-authz's answer to the caller. The
filing server and the gateway run under uvicorn on 127.0.0.1; vlei-authz verifies against a real
KERI world. What the live stack adds on top is agentgateway itself (see deploy/agentgateway).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from conftest import ARGS, authz_app, filing, serve, signed_meta
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

import gateway_client
from mcp_vlei import Signer
from mcp_vlei.testing import LEI

INCLUDE_RESPONSE_HEADERS = (
    "x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid", "x-vlei-report",
)


def stand_in_gateway(authz, upstream: str) -> Starlette:
    decide = httpx.AsyncClient(transport=httpx.ASGITransport(app=authz), base_url="http://vlei-authz")
    forward = httpx.AsyncClient(base_url=upstream, timeout=30)

    async def route(request: Request) -> Response:
        body = await request.body()
        decision = await decide.request(request.method, "/auth/mcp", content=body)
        if decision.status_code != 200:
            keep = {k: decision.headers[k] for k in ("content-type", "x-vlei-failure") if k in decision.headers}
            return Response(decision.content, status_code=decision.status_code, headers=keep)
        headers = [
            (k, v) for k, v in request.headers.items()
            if k not in ("host", "content-length", *INCLUDE_RESPONSE_HEADERS)
        ]
        headers += [(k, decision.headers.get(k, "")) for k in INCLUDE_RESPONSE_HEADERS]
        response = await forward.send(
            forward.build_request(request.method, "/mcp", headers=headers, content=body), stream=True
        )
        passed = {
            k: v for k, v in response.headers.items()
            if k in ("content-type", "mcp-session-id", "cache-control")
        }
        return StreamingResponse(
            response.aiter_raw(), status_code=response.status_code, headers=passed,
            background=BackgroundTask(response.aclose),
        )

    return Starlette(routes=[Route("/mcp", route, methods=["GET", "POST", "DELETE"])])


@asynccontextmanager
async def gateway(world, tmp_path) -> AsyncIterator[str]:
    filing.FILINGS.clear()
    async with serve(filing.create_app()) as upstream:
        async with serve(stand_in_gateway(authz_app(world, tmp_path), upstream)) as base:
            yield f"{base}/mcp"


def agent_meta(world, tool="submit_filing", arguments=ARGS):
    """Built with the helper the console will use, not the test harness's own."""
    return gateway_client.signed_meta(
        credential=world.ecr_stream,
        signer=Signer.from_seed(world.agent.pre, world.agent.seed),
        tool=tool, arguments=arguments,
        delegated_aid=world.agent.pre, credential_said=world.ecr_credential.said,
    )


async def test_an_allowed_call_reaches_the_server_and_brings_back_the_report(world, tmp_path):
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "submit_filing", ARGS, agent_meta(world))

    assert set(out) == {"allowed", "layer", "text", "report", "identity"}
    assert out["allowed"] is True and out["layer"] is None, out["text"]
    assert '"ACCEPTED"' in out["text"]
    assert out["report"]["allowed"] is True
    assert [c["name"] for c in out["report"]["checks"] if c["passed"]] == [
        "credential_present", "freshness", "digest", "signature",
        "delegation", "chain", "revocation", "authority",
    ]
    identity = out["identity"]
    assert identity["lei"] == LEI and identity["role"] == "regulatory-filing"
    assert identity["holderAid"] == world.holder.pre
    assert identity["delegateAid"] == world.agent.pre
    assert identity["credentialSaid"] == world.ecr_credential.said
    # What the filing server says it received — the only identity it ever had.
    assert identity["headers"] == {
        "x-vlei-lei": LEI,
        "x-vlei-role": "regulatory-filing",
        "x-vlei-holder-aid": world.holder.pre,
        "x-vlei-delegate-aid": world.agent.pre,
    }
    assert filing.FILINGS[LEI][0]["submittedBy"]["agentAid"] == world.agent.pre


async def test_a_refusal_names_its_layer_and_carries_the_report(world, tmp_path):
    meta = agent_meta(world)
    tampered = {**ARGS, "payload": {"totalAssets": 1}}
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "submit_filing", tampered, meta)

    assert out["allowed"] is False
    assert out["layer"] == "digest_mismatch"
    assert out["text"].startswith("digest_mismatch: ")
    digest = next(c for c in out["report"]["checks"] if c["name"] == "digest")
    assert digest["passed"] is False
    assert out["identity"]["holderAid"] == world.holder.pre
    assert filing.FILINGS == {}  # never reached


async def test_a_revoked_credential_is_refused_through_the_gateway(world, tmp_path):
    world.le_registry.revoke(world.ecr_credential.said)
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "submit_filing", ARGS, agent_meta(world))

    assert out["allowed"] is False and out["layer"] == "revoked"


async def test_someone_elses_credential_is_refused_through_the_gateway(world, tmp_path):
    from conftest import signer_for

    from mcp_vlei.testing import Controller

    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    meta = signed_meta(world, signer=signer_for(mallory), delegated=None)
    async with gateway(world, tmp_path) as url:
        out = await gateway_client.call_through_gateway(url, "submit_filing", ARGS, meta)

    assert out["allowed"] is False and out["layer"] == "invalid_signature"


async def test_nothing_presented_is_missing_credential_and_public_tools_still_work(world, tmp_path):
    async with gateway(world, tmp_path) as url:
        refused = await gateway_client.call_through_gateway(url, "submit_filing", ARGS, {})
        public = await gateway_client.call_through_gateway(url, "list_forms", {}, {})

    assert refused["allowed"] is False and refused["layer"] == "missing_credential"
    assert public["allowed"] is True and public["report"] is None and "A1" in public["text"]


async def test_an_unreachable_gateway_is_reported_not_raised():
    out = await gateway_client.call_through_gateway(
        "http://127.0.0.1:9/mcp", "submit_filing", ARGS, {}, timeout=3
    )
    assert out["allowed"] is False and out["layer"] is None
    assert "transport error" in out["text"] or "JSON-RPC" in out["text"]
