"""vlei-authz — the package's verification logic, wrapped as an HTTP authorization service.

Conforms to agentgateway's HTTP external authorization contract: a 200 allows the request and the
headers named in ``includeResponseHeaders`` are copied onto it; anything else denies it.

Two deployments, one implementation. The in-process extension and this service call the same
``mcp_vlei`` code, so an institution's choice between "embed the package" and "put a gateway in
front" is a deployment decision, not a difference in what gets checked.

## One thing that had to be designed around

agentgateway's HTTP external authorization forwards request **headers** to the authorizer; the
documented options are ``protocol.includeRequestHeaders`` and ``protocol.http.includeResponseHeaders``.
There is no documented request-body forwarding for the HTTP protocol, and the vLEI credential and
signature live in the JSON-RPC body's ``_meta``.

So for gateway deployments the client mirrors the same three ``_meta`` values into ``x-vlei-*``
request headers (``VleiClient(..., mirror_headers=True)``). This does not weaken anything: the
signature's digest still covers the canonicalized ``params``, so a mirrored header that disagrees
with the body fails on the digest. It is the same data on a transport the gateway can see.

If a future agentgateway release forwards the body, :func:`_extract` already prefers the body when
one is present, and the header mirror becomes redundant rather than wrong.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from mcp_vlei import Signer, VleiVerifier, make_attestation
from mcp_vlei.errors import MissingCredential, VleiError
from mcp_vlei.signing import ReplayCache, scope_satisfied, verify_request

ROOT = Path(__file__).resolve().parents[3]
CREDENTIALS = ROOT / "credentials"
ENV = json.loads((CREDENTIALS / "env.json").read_text()) if (CREDENTIALS / "env.json").exists() else {}

VERIFIER_URL = os.environ.get("VLEI_VERIFIER_URL", ENV.get("verifierUrl", "http://localhost:7676"))
ACCEPTED_ROOTS = ENV.get("acceptedRoots", [])

#: The regulator's per-tool requirements. In the in-process deployment these live in Tool._meta;
#: at a gateway the gateway must hold them, because it decides before the server is reached.
REQUIREMENTS: dict[str, dict[str, Any]] = {
    "submit_filing": {"credential": "ECR", "role": "regulatory-filing"},
    "get_filing_status": {"credential": "ECR"},
    # list_forms is public.
}

app = FastAPI(title="vlei-authz")
verifier = VleiVerifier(VERIFIER_URL, accepted_roots=ACCEPTED_ROOTS, ttl_ms=0)
replay = ReplayCache()

#: The gateway's own AID, used to sign attestations it issues under mode (b).
GATEWAY_SIGNER = (
    Signer.from_key_store(os.environ["VLEI_GATEWAY_KEYS"], os.environ["VLEI_GATEWAY_AID"])
    if os.environ.get("VLEI_GATEWAY_AID")
    else None
)


def _extract(request: Request, body: bytes) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Return ``(tool_name, params, vlei_meta)`` from the body if present, else from headers."""
    if body:
        try:
            rpc = json.loads(body)
            params = rpc.get("params") or {}
            meta = params.get("_meta") or {}
            if meta.get("org.gleif.vlei/credential"):
                return params.get("name", ""), params, meta
        except json.JSONDecodeError:
            pass

    h = request.headers
    meta = {
        "org.gleif.vlei/credential": h.get("x-vlei-credential", ""),
        "org.gleif.vlei/delegatedAid": h.get("x-vlei-delegated-aid", ""),
    }
    signature = h.get("x-vlei-signature")
    if signature:
        try:
            meta["org.gleif.vlei/signature"] = json.loads(signature)
        except json.JSONDecodeError:
            meta["org.gleif.vlei/signature"] = {}
    return h.get("x-vlei-tool", ""), {}, meta


def _deny(exc: VleiError) -> Response:
    """403 with the layer named.

    The layer is in a header as well as the body so it survives a gateway that discards the body
    on a denial — without it the agent sees "forbidden" and the skill has nothing to act on.
    """
    return JSONResponse(
        status_code=403,
        content={"layer": exc.layer.value, "message": exc.message},
        headers={"x-vlei-failure": exc.layer.value},
    )


@app.post("/authz")
@app.get("/authz")
async def authorize(request: Request) -> Response:
    body = await request.body()
    tool, params, meta = _extract(request, body)

    requirement = REQUIREMENTS.get(tool)
    if not requirement:
        return Response(status_code=200)  # public tool, or not a tool call

    credential = meta.get("org.gleif.vlei/credential")
    signature = meta.get("org.gleif.vlei/signature")
    if not credential or not signature:
        return _deny(
            MissingCredential(
                f"{tool} requires an ECR credential and a signed request; none was presented"
            )
        )

    delegated = meta.get("org.gleif.vlei/delegatedAid") or signature.get("aid", "")

    try:
        result = await verifier.verify(
            credential,
            said=_said_of(credential),
            aid=delegated,
            expected_role=requirement.get("role"),
        )

        verkey = request.headers.get("x-vlei-verkey")
        if verkey and params:
            verify_request(signature, "tools/call", params, verkey, replay_cache=replay)

        ok, reason = scope_satisfied(requirement.get("scope"), result.scope)
        if not ok:
            from mcp_vlei.errors import ScopeExceeded

            raise ScopeExceeded(reason, aid=result.aid)
    except VleiError as exc:
        return _deny(exc)

    # Allow, and hand the downstream system the established facts. The filing server reads these
    # four headers and contains no other identity code.
    return Response(status_code=200, headers=result.to_headers())


@app.post("/attest")
async def attest(request: Request) -> Response:
    """Mode (b): issue a signed attestation for a party this gateway has already verified.

    This is the "letter of confirmation" endpoint — another institution asks this one to confirm an
    identity, and gets back a statement it can verify against this gateway's own AID.
    """
    if GATEWAY_SIGNER is None:
        return JSONResponse(
            status_code=501,
            content={"error": "this gateway has no AID configured and cannot attest"},
        )

    payload = await request.json()
    subject = payload.get("subjectAid")
    credential = payload.get("credential")
    if not (subject and credential):
        return JSONResponse(status_code=400, content={"error": "subjectAid and credential required"})

    try:
        result = await verifier.verify(credential, said=_said_of(credential), aid=subject)
    except VleiError as exc:
        return _deny(exc)

    return JSONResponse(
        status_code=200,
        content={"org.gleif.vlei/attestation": make_attestation(GATEWAY_SIGNER, result)},
    )


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "verifier": VERIFIER_URL,
        "acceptedRoots": ACCEPTED_ROOTS,
        "canAttest": GATEWAY_SIGNER is not None,
        "protectedTools": sorted(REQUIREMENTS),
    }


def _said_of(cesr: str) -> str:
    from mcp_vlei.extension import _said_of as impl

    return impl(cesr)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))
