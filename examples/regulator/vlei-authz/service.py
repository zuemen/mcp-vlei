"""vlei-authz — the package's verification logic, wrapped as an HTTP authorization service.

Conforms to agentgateway's HTTP external authorization contract: a 200 allows the request and the
headers named in ``includeResponseHeaders`` are copied onto it; anything else denies it.

Two deployments, one implementation. The in-process extension and this service call the same
``mcp_vlei`` code, so an institution's choice between "embed the package" and "put a gateway in
front" is a deployment decision, not a difference in what gets checked.

The credential and signature arrive in the JSON-RPC body's ``_meta``. agentgateway forwards the body
when ``extAuthz.includeRequestBody`` is set, and the gateway configuration raises
``maxRequestBytes`` to 65536 because a chained CESR ACDC exceeds the 8192-byte default.

:func:`_extract` also accepts the same values as ``x-vlei-*`` headers, for deployments whose gateway
cannot forward a body. That path is not a weakening: the signature's digest covers the canonicalized
``params``, so a header that disagrees with the body fails on ``digest_mismatch`` rather than being
believed. The body is preferred whenever one is present.
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


#: Audit log, one JSON object per line. Every decision this service makes lands here, allowed and
#: denied alike — a log that records only refusals cannot answer "who filed this?", which is the
#: question stage 5 of docs/GOVERNMENT.md exists to make answerable.
AUDIT_LOG = Path(os.environ.get("VLEI_AUDIT_LOG", "/var/log/vlei-authz/decisions.jsonl"))


def audit(**fields: Any) -> None:
    from datetime import datetime, timezone

    fields["at"] = datetime.now(timezone.utc).isoformat()
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(fields, ensure_ascii=False) + "\n")
    except OSError:
        # An unwritable audit log must not take the gateway down, but it must be visible.
        print("AUDIT", json.dumps(fields, ensure_ascii=False), flush=True)


def _is_tool_call(body: bytes) -> bool:
    """Only ``tools/call`` carries a credential. Everything else passes through untouched."""
    if not body:
        return True  # cannot tell; fall through to the header path and decide there
    try:
        return (json.loads(body) or {}).get("method") == "tools/call"
    except json.JSONDecodeError:
        return False


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


def _deny(exc: VleiError, tool: str = "") -> Response:
    """403 with the layer named.

    The layer is in a header as well as the body so it survives a gateway that discards the body
    on a denial — without it the agent sees "forbidden" and the skill has nothing to act on.
    """
    audit(decision="deny", tool=tool, layer=exc.layer.value, message=exc.message, aid=exc.aid)
    return JSONResponse(
        status_code=403,
        content={"layer": exc.layer.value, "message": exc.message},
        headers={"x-vlei-failure": exc.layer.value},
    )


@app.post("/auth/mcp")
@app.get("/auth/mcp")
async def authorize(request: Request) -> Response:
    body = await request.body()

    # Anything that is not a tools/call carries no credential and asserts nothing. initialize,
    # tools/list, ping and the rest pass through: refusing them would break discovery for every
    # client, including the ones that are about to present a perfectly good credential.
    if not _is_tool_call(body):
        return Response(status_code=200)

    tool, params, meta = _extract(request, body)

    requirement = REQUIREMENTS.get(tool)
    if not requirement:
        audit(decision="allow", tool=tool, note="public tool")
        return Response(status_code=200)

    credential = meta.get("org.gleif.vlei/credential")
    signature = meta.get("org.gleif.vlei/signature")
    if not credential or not signature:
        return _deny(
            MissingCredential(
                f"{tool} requires an ECR credential and a signed request; none was presented"
            ),
            tool,
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
        return _deny(exc, tool)

    # Allow, and hand the downstream system the established facts. The filing server reads these
    # four headers and contains no other identity code.
    audit(
        decision="allow",
        tool=tool,
        lei=result.lei,
        role=result.role,
        holderAid=result.holder_aid,
        delegateAid=result.aid if result.aid != result.holder_aid else None,
        credentialSaid=result.credential_said,
    )
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
