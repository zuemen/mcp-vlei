"""vlei-authz over gRPC ext-authz: the wire on which a refused tools/call is the call's own answer.

Called the way agentgateway calls it: a ``CheckRequest`` with the JSON-RPC body in
``attributes.request.http``, sent to a real gRPC server on 127.0.0.1 that shares its state with the
HTTP service, verifying against a real KERI world. What agentgateway then does with each answer is
read from its source (``crates/agentgateway/src/http/ext_authz.rs`` at v1.5.0):

* ``status.code == 0``: allowed; ``headers_to_remove`` then ``headers`` are applied to the request.
* otherwise: refused; a ``denied_response`` becomes the response — its status, headers and body —
  and the backend is never called.
"""

from __future__ import annotations

import json
import socket
import sys
from datetime import date, timedelta

import grpc
from conftest import ARGS, REGULATOR, authz, identity_for, rpc, serve, signed_meta

from mcp_vlei.testing import LEI

sys.path.insert(0, str(REGULATOR / "vlei-authz" / "envoy_authz"))
import ext_authz_pb2 as pb  # noqa: E402
import ext_authz_pb2_grpc as pb_grpc  # noqa: E402

CLEARED = {"x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid", "x-vlei-report"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def check(world, tmp_path, body: bytes, *, as_text: bool = False) -> pb.CheckResponse:
    """Run the service (HTTP and gRPC, one lifespan) and send one Check, as agentgateway would."""
    port = free_port()
    app = authz.create_app(
        identity=identity_for(world, tmp_path),
        policy=authz.load_policy(authz.HERE / "policy.json"),
        audit=authz.Audit(path=tmp_path / "audit" / "decisions.jsonl"),
        grpc_port=port,
    )
    request = pb.CheckRequest()
    if as_text:
        request.attributes.request.http.body = body.decode("utf-8")
    else:
        request.attributes.request.http.raw_body = body
    async with serve(app):
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            return await pb_grpc.AuthorizationStub(channel).Check(request, timeout=20)


def set_headers(response: pb.CheckResponse) -> dict[str, str]:
    return {h.header.key: h.header.value for h in response.ok_response.headers}


def tool_error(response: pb.CheckResponse, layer: str | None) -> dict:
    """A refusal answered as HTTP 200 carrying the call's own JSON-RPC answer: an MCP tool error."""
    assert response.status.code == 7, response  # PERMISSION_DENIED: refused, the backend is not called
    denied = response.denied_response
    assert denied.status.code == 200
    headers = {h.header.key: h.header.value for h in denied.headers}
    assert headers["content-type"] == "application/json"
    message = json.loads(denied.body)
    assert message["jsonrpc"] == "2.0" and "error" not in message
    result = message["result"]
    assert result["isError"] is True
    failure = result["_meta"]["org.gleif.vlei/failure"]
    assert failure["layer"] == layer
    first = result["content"][0]["text"].splitlines()[0]
    assert first == f"{layer or 'refused'}: {failure['message']}"
    if layer:
        assert headers["x-vlei-failure"] == layer
    return message


# ------------------------------------------------------------------------------------------- #

async def test_an_allowed_call_is_ok_and_carries_the_facts_replacing_what_the_caller_sent(world, tmp_path):
    response = await check(world, tmp_path, rpc("enroll_employee", ARGS, signed_meta(world)))
    assert response.status.code == 0, response
    assert CLEARED <= set(response.ok_response.headers_to_remove)
    headers = set_headers(response)
    assert headers["x-vlei-lei"] == LEI and headers["x-vlei-role"] == "labor-insurance-filing"
    assert headers["x-vlei-holder-aid"] == world.holder.pre
    assert headers["x-vlei-delegate-aid"] == world.agent.pre
    assert headers["x-vlei-report"] and headers["x-vlei-namespace"] == "org.gleif.vlei"
    # Set, not appended: a value the caller sent under the same name never survives.
    assert all(h.append_action == 2 for h in response.ok_response.headers)  # OVERWRITE_IF_EXISTS_OR_ADD


async def test_a_message_that_asserts_nothing_is_ok_and_clears_every_identity_header(world, tmp_path):
    initialize = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}).encode()
    response = await check(world, tmp_path, initialize)
    assert response.status.code == 0
    assert CLEARED <= set(response.ok_response.headers_to_remove)
    assert set(set_headers(response)) == {"x-vlei-namespace"}


async def test_no_credential_is_answered_as_a_tool_error_with_http_200(world, tmp_path):
    message = tool_error(await check(world, tmp_path, rpc("list_insured", {})), "missing_credential")
    assert message["id"] == 1
    assert "resultType" not in message["result"]  # a legacy request gets the plain result


async def test_each_layer_is_the_first_line_of_its_tool_error(world, tmp_path):
    adjust = rpc("adjust_insured_salary", {"person_ref": "EMP-0001", "salary_grade": 5},
                 signed_meta(world, "adjust_insured_salary",
                             {"person_ref": "EMP-0001", "salary_grade": 5}))
    tool_error(await check(world, tmp_path, adjust), "role_mismatch")

    late = {**ARGS, "start_date": (date.today() + timedelta(days=15)).isoformat()}
    tool_error(await check(world, tmp_path,
                           rpc("enroll_employee", late, signed_meta(world, arguments=late))),
               "scope_exceeded")

    world.le_registry.revoke(world.ecr_credential.said)
    report = tool_error(await check(world, tmp_path, rpc("enroll_employee", ARGS, signed_meta(world))),
                        "revoked")["result"]["_meta"]["org.gleif.vlei/report"]
    assert report["allowed"] is False


async def test_an_unlisted_tool_is_a_tool_error_without_a_layer(world, tmp_path):
    message = tool_error(await check(world, tmp_path, rpc("delete_all_records", {})), None)
    assert "closed" in message["result"]["_meta"]["org.gleif.vlei/failure"]["message"]


async def test_a_2026_07_28_request_gets_a_complete_result_signed_by_the_gateway(world, tmp_path):
    body = json.dumps({"jsonrpc": "2.0", "id": "m-3", "method": "tools/call", "params": {
        "name": "list_insured",
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}).encode()
    message = tool_error(await check(world, tmp_path, body), "missing_credential")
    assert message["id"] == "m-3"
    assert message["result"]["resultType"] == "complete"
    assert message["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "vlei-authz"


async def test_a_body_with_no_call_to_answer_is_still_refused_with_403(world, tmp_path):
    response = await check(world, tmp_path, b"{not json")
    assert response.status.code == 7 and response.denied_response.status.code == 403
    body = json.loads(response.denied_response.body)
    assert body["layer"] is None and "not JSON" in body["message"]


async def test_the_body_is_read_whether_it_arrives_as_bytes_or_as_text(world, tmp_path):
    response = await check(world, tmp_path, rpc("list_insured", {}), as_text=True)
    tool_error(response, "missing_credential")
