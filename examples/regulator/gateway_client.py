"""Call a tool through the gateway in front of the labour-insurance simulator, and say what happened.

The console's labour-insurance scenes import :func:`call_through_gateway`. (The simulator is
simulated — not connected to the Bureau of Labor Insurance.) It is an ordinary MCP client (SDK
2.2.0, streamable HTTP): nothing here verifies anything, and nothing here knows the gateway exists
beyond its URL. What it adds is the reading of the two ways a call can end:

* **allowed** — the call reached ``labor-insurance-sim``. The receipt lists the identity headers the
  server received, and ``_meta["org.gleif.vlei/report"]`` carries the gateway's verification
  report, which the server decoded from ``x-vlei-report`` and handed back untouched.
* **refused** — ``vlei-authz`` answered 403 before the server was reached. agentgateway returns
  that answer as the HTTP response to the ``tools/call`` POST, which the SDK only surfaces as a
  generic transport error; the body — ``{"layer", "message", "report"}`` — is captured here with a
  response hook so the failure layer is not lost.

Usage from code::

    from gateway_client import call_through_gateway, signed_meta

    url = "http://localhost:3000/mcp"
    meta = signed_meta(credential=chain, signer=signer, tool="enroll_employee", arguments=args,
                       audience=await audience_for(url), delegated_aid=signer.aid,
                       credential_said=said)
    out = await call_through_gateway(url, "enroll_employee", args, meta)
    # {"allowed": True, "layer": None, "text": "...", "report": {...}, "identity": {...}}

From a shell::

    python examples/regulator/gateway_client.py --world          # demo chain; see --help
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

DEFAULT_URL = "http://localhost:3000/mcp"


def _client_info():
    """How the console names itself to the gateway: a script playing the agent, not Claude."""
    from mcp.types import Implementation

    return Implementation(name="trust-console (scripted agent)", version="0.2")


CLIENT_INFO = _client_info()

_HEADER_TO_FIELD = {
    "x-vlei-lei": "lei",
    "x-vlei-role": "role",
    "x-vlei-holder-aid": "holderAid",
    "x-vlei-delegate-aid": "delegateAid",
}


def _keys() -> Any:
    """The names on the wire, under `MCP_VLEI_NAMESPACE` or the provisional default — imported when
    first needed, like the rest of `mcp_vlei` here."""
    from mcp_vlei.namespace import keys

    return keys()


async def audience_for(url: str, *, timeout: float = 10.0) -> Any:
    """The gateway at ``url`` as a call is signed for it: the LE its ``/.well-known/vlei`` names
    (taken as published — this script trusts the gateway it was pointed at) and ``url`` itself."""
    from urllib.parse import urlsplit, urlunsplit

    import httpx

    from mcp_vlei.client import published_audience

    parts = urlsplit(url)
    well_known = urlunsplit((parts.scheme, parts.netloc, "/.well-known/vlei", "", ""))
    async with httpx.AsyncClient(timeout=timeout) as http:
        response = await http.get(well_known)
    response.raise_for_status()
    return published_audience(response.json(), url)


def signed_meta(
    *,
    credential: str,
    signer: Any,
    tool: str,
    arguments: dict[str, Any],
    audience: Any,
    delegated_aid: str | None = None,
    credential_said: str | None = None,
) -> dict[str, Any]:
    """The ``_meta`` a vLEI ``tools/call`` carries, signed (``vlei-sig/0.3``) over exactly
    ``{name, arguments}``, for ``audience`` — the gateway's LE AID and the URL the call goes to.

    Sign immediately before calling: the signature expires in 30 seconds, any change to
    ``arguments`` after signing is refused as ``digest_mismatch``, and a call sent anywhere but
    ``audience`` is refused as ``audience_mismatch``.
    """
    from mcp_vlei.extension import _said_of
    from mcp_vlei.signing import sign_request

    k = _keys()
    said = credential_said or _said_of(credential)
    meta: dict[str, Any] = {
        k.credential: credential,
        k.signature: sign_request(signer, "tools/call", {"name": tool, "arguments": arguments},
                                  audience=audience, credential_said=said),
        k.credential_said: said,
    }
    if delegated_aid:
        meta[k.delegated_aid] = delegated_aid
    return meta


async def call_through_gateway(
    url: str,
    tool: str,
    arguments: dict,
    meta: dict,
    *,
    mode: str = "auto",
    timeout: float = 30.0,
    client_info: Any = None,
) -> dict:
    """Call ``tool`` at ``url`` (the gateway's MCP endpoint) and report the outcome.

    Returns ``{"allowed", "layer", "text", "report", "identity"}``:

    ``allowed``   the tool ran and did not report an error
    ``layer``     the failure layer when vlei-authz refused (``None`` when allowed, or when the
                  refusal was not a verification failure — a policy or transport problem)
    ``text``      the tool's text, or ``"<layer>: <message>"`` for a refusal
    ``report``    the verification report (``VerificationReport.as_dict()``), from the gateway —
                  via the receipt's ``_meta`` when allowed, from the 403 body when refused
    ``identity``  ``lei``/``role``/``holderAid``/``delegateAid``/``credentialSaid`` as the gateway
                  established them, plus ``headers``: what the simulator actually received
    """
    refusals: list[dict[str, Any]] = []

    async def capture(response: httpx2.Response) -> None:
        # Only a POST answers a JSON-RPC request; GET is the SSE stream and DELETE ends a session.
        if response.request.method != "POST" or response.status_code < 400:
            return
        body = await response.aread()
        try:
            payload = json.loads(body) if body else None
        except ValueError:
            payload = None
        refusals.append(
            {
                "status": response.status_code,
                "payload": payload if isinstance(payload, dict) else None,
                "body": body.decode("utf-8", "replace")[:500],
                "failure": response.headers.get("x-vlei-failure"),
            }
        )

    http = httpx2.AsyncClient(
        timeout=httpx2.Timeout(timeout, read=max(timeout, 60.0)),
        event_hooks={"response": [capture]},
    )
    try:
        async with http:
            async with Client(streamable_http_client(url, http_client=http), mode=mode,
                              client_info=client_info or CLIENT_INFO) as client:
                result = await client.call_tool(tool, arguments, meta=meta)
    except MCPError as exc:
        return _refused(refusals, f"{exc.error.message} (JSON-RPC {exc.error.code})")
    except Exception as exc:  # noqa: BLE001 - a console shows "could not reach", it does not crash
        return _refused(refusals, f"transport error: {_describe(exc)}")

    return _completed(result)


def _refused(refusals: list[dict[str, Any]], fallback: str) -> dict:
    """A call that never reached the tool. Prefer the authorizer's own words when it spoke."""
    for refusal in reversed(refusals):
        payload = refusal["payload"] or {}
        if "layer" in payload and "message" in payload:
            layer = payload.get("layer") or refusal["failure"]
            report = payload.get("report")
            text = f"{layer}: {payload['message']}" if layer else str(payload["message"])
            return {
                "allowed": False,
                "layer": layer,
                "text": text,
                "report": report,
                "identity": _identity(report, None),
            }
    if refusals:
        last = refusals[-1]
        text = f"gateway refused the call (HTTP {last['status']}): {last['body'] or fallback}"
        return {
            "allowed": False, "layer": last["failure"], "text": text, "report": None, "identity": {},
        }
    return {"allowed": False, "layer": None, "text": fallback, "report": None, "identity": {}}


def _completed(result: Any) -> dict:
    text = "\n".join(
        getattr(block, "text", "") for block in (result.content or []) if getattr(block, "text", None)
    )
    meta = dict(result.meta or {})
    k = _keys()
    report = meta.get(k.report)
    receipt = result.structured_content if isinstance(result.structured_content, dict) else None
    failure = meta.get(k.failure) or {}
    return {
        "allowed": not result.is_error,
        "layer": failure.get("layer") if result.is_error else None,
        "text": text,
        "report": report,
        "identity": _identity(report, receipt),
    }


def _identity(report: dict[str, Any] | None, receipt: dict[str, Any] | None) -> dict[str, Any]:
    identity: dict[str, Any] = dict((report or {}).get("identity") or {})
    received = (receipt or {}).get("receivedHeaders")
    if isinstance(received, dict):
        for header, name in _HEADER_TO_FIELD.items():
            if received.get(header) and not identity.get(name):
                identity[name] = received[header]
        identity["headers"] = received
    return identity


def _describe(exc: BaseException) -> str:
    """The innermost cause, which is the useful one out of an anyio exception group."""
    inner = getattr(exc, "exceptions", None)
    if inner:
        return _describe(inner[0])
    return f"{type(exc).__name__}: {exc}"


# ------------------------------------------------------------------------------------------- #
# CLI
# ------------------------------------------------------------------------------------------- #

def demo_arguments() -> dict[str, Any]:
    """An enrolment filed on the start date, for a fictitious employee — "today" as the gateway
    counts it (VLEI_POLICY_UTC_OFFSET, +08:00 in deploy/agentgateway)."""
    from mcp_vlei.signing import parse_utc_offset, today_at

    today = today_at(parse_utc_offset(os.environ.get("VLEI_POLICY_UTC_OFFSET", "").strip()))
    return {"person_ref": "EMP-0001", "start_date": today.isoformat(), "salary_grade": 3}


def _meta_from_args(args: argparse.Namespace, arguments: dict[str, Any]) -> dict[str, Any]:
    if args.meta:
        return json.loads(Path(args.meta).read_text(encoding="utf-8"))
    if args.world:
        # A deterministic demo chain (mcp_vlei.testing): verifies only against a witness serving
        # the same World. Never a real credential.
        from mcp_vlei import Signer
        from mcp_vlei.audience import Audience
        from mcp_vlei.testing import World

        world = World(role="labor-insurance-filing", label=args.world_label)
        signer = Signer.from_seed(world.agent.pre, world.agent.seed)
        return signed_meta(
            credential=world.ecr_stream, signer=signer, tool=args.tool, arguments=arguments,
            audience=Audience(world.le.pre, args.url),
            delegated_aid=world.agent.pre, credential_said=world.ecr_credential.said,
        )
    if args.credential and args.key_store and args.aid:
        from mcp_vlei import Signer

        signer = Signer.from_key_store(args.key_store, args.aid)
        return signed_meta(
            credential=Path(args.credential).read_text(encoding="utf-8").strip(), signer=signer,
            tool=args.tool, arguments=arguments, audience=asyncio.run(audience_for(args.url)),
            delegated_aid=args.delegated_aid, credential_said=args.credential_said,
        )
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help=f"gateway MCP endpoint ({DEFAULT_URL})")
    parser.add_argument("--tool", default="enroll_employee")
    parser.add_argument("--arguments", help="tool arguments as JSON (default: enrol EMP-0001 today)")
    parser.add_argument("--mode", default="auto", help="MCP connect mode: auto | legacy | <version>")
    source = parser.add_argument_group("what to present (none: an unsigned call)")
    source.add_argument("--meta", help="a JSON file holding the complete _meta, used as is")
    source.add_argument("--world", action="store_true", help="sign with the mcp_vlei.testing demo chain")
    source.add_argument("--world-label", default="world")
    source.add_argument("--credential", help="CESR stream to present (e.g. credentials/ecr.cesr)")
    source.add_argument("--key-store", help="directory holding <aid>.key (32-byte Ed25519 seed)")
    source.add_argument("--aid", help="the signing AID")
    source.add_argument("--delegated-aid")
    source.add_argument("--credential-said")
    args = parser.parse_args(argv)

    arguments = json.loads(args.arguments) if args.arguments else demo_arguments()
    meta = _meta_from_args(args, arguments)
    out = asyncio.run(call_through_gateway(args.url, args.tool, arguments, meta, mode=args.mode))
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["allowed"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "mcp-vlei" / "src"))
    sys.exit(main())
