"""vlei-authz over gRPC: the Envoy ext_authz ``Check`` API, as agentgateway calls it.

The same decisions as the HTTP service, from the same process and state. A second wire is needed
because of what each wire can say when a ``tools/call`` is refused:

* **HTTP ext-authz.** agentgateway allows on any 2xx and returns anything else to the caller as it
  is. A refusal can therefore only be a 4xx. MCP clients such as the claude.ai connector show a 4xx
  as a bare "the connector's server returned an error", so Claude never learns why and tells the user
  the server is broken.
* **gRPC ext-authz.** A refusal carries its own HTTP response: a non-OK ``CheckResponse`` with a
  ``denied_response`` becomes the response, status included, and the backend is never called
  (agentgateway v1.5.0, ``crates/agentgateway/src/http/ext_authz.rs``).

  So a refused call is answered with HTTP 200 and the call's own JSON-RPC answer, an MCP tool error
  (``isError``) whose first line is the failure layer, and the model reads it. The refusal still
  happens here, before the backend.

A body with no call in it to answer — unreadable, a batch, a call without a name — is refused with
403, as on the HTTP wire.

The protocol buffers are agentgateway's own (``envoy_authz/proto/``, copied from its v1.5.0
``crates/protos/proto``), compiled with grpcio-tools 1.73.1.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable

import grpc

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "envoy_authz"))
import ext_authz_pb2 as pb  # noqa: E402
import ext_authz_pb2_grpc as pb_grpc  # noqa: E402
import shared_envoy_pb2 as common  # noqa: E402

logger = logging.getLogger(__name__)

import service  # noqa: E402  (the module that started this one; its decision and its names)

#: google.rpc.Code: OK allows; PERMISSION_DENIED refuses.
OK, PERMISSION_DENIED = 0, 7
#: Removed from every request this service allows, then set again from what was established. A
#: value the caller sent under one of these names must never reach the backend.
CLEARED = (*service.IDENTITY_HEADERS, service.REPORT_HEADER, service.NAMESPACE_HEADER)
_OVERWRITE = common.HeaderValueOption.HeaderAppendAction.OVERWRITE_IF_EXISTS_OR_ADD


def _header(key: str, value: str) -> common.HeaderValueOption:
    return common.HeaderValueOption(header=common.HeaderValue(key=key, value=value),
                                    append_action=_OVERWRITE)


def _allowed(decision: service.Decision) -> pb.CheckResponse:
    headers = {k: v for k, v in decision.headers.items() if v}
    headers[service.NAMESPACE_HEADER] = service.namespace_keys().namespace
    return pb.CheckResponse(
        status=common.Status(code=OK),
        ok_response=pb.OkHttpResponse(
            headers=[_header(k, v) for k, v in headers.items()],
            headers_to_remove=list(CLEARED),
        ),
    )


def _refused(decision: service.Decision) -> pb.CheckResponse:
    if decision.call is not None:
        status, body = 200, service.tool_error(decision)
    else:
        status, body = decision.status, {"layer": decision.layer, "message": decision.message,
                                         "report": decision.report}
    headers = [_header("content-type", "application/json")]
    if decision.layer:
        headers.append(_header(service.FAILURE_HEADER, decision.layer))
    return pb.CheckResponse(
        status=common.Status(code=PERMISSION_DENIED, message=decision.layer or "refused"),
        denied_response=pb.DeniedHttpResponse(
            status=common.HttpStatus(code=status),
            headers=headers,
            body=json.dumps(body, ensure_ascii=False),
        ),
    )


class Check(pb_grpc.AuthorizationServicer):
    def __init__(self, decide: Callable[..., Awaitable[Any]]) -> None:
        self._decide = decide

    async def Check(self, request: pb.CheckRequest, context: Any) -> pb.CheckResponse:  # noqa: N802
        try:
            http = request.attributes.request.http
            body = http.raw_body or http.body.encode("utf-8")
            decision = await self._decide(body, dict(http.headers), "grpc")
        except Exception as exc:  # noqa: BLE001 - this wire has no "never allow on error" except
            # by never raising: an uncaught exception here surfaces to agentgateway as an UNKNOWN
            # status, indistinguishable from a bug, and the call goes nowhere. Answer the same
            # labelled denial the HTTP wire would, instead. ``self._decide`` (`decide()`, above)
            # already does this for everything inside it; this is the backstop for everything else
            # in this method (reading the request itself). Only the exception's class name, never
            # its text or the request.
            logger.warning("vlei-authz: unexpected error in gRPC Check (%s)", type(exc).__name__)
            message = f"the verifier failed unexpectedly ({type(exc).__name__}); try again"
            return _refused(service.Decision(False, layer="verifier_error", message=message,
                                             status=503))
        return _allowed(decision) if decision.allowed else _refused(decision)


async def serve_grpc(port: int, decide: Callable[..., Awaitable[Any]]) -> grpc.aio.Server:
    """Start the gRPC service on ``port`` (all interfaces, inside the gateway's network)."""
    server = grpc.aio.server()
    pb_grpc.add_AuthorizationServicer_to_server(Check(decide), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    await server.start()
    return server
