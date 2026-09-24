"""Call a tool through the regulator's gateway, and say what happened in one dictionary.

The console's scene 4 imports :func:`call_through_gateway`. It is an ordinary MCP client (SDK
2.2.0, streamable HTTP): nothing here verifies anything, and nothing here knows the gateway exists
beyond its URL. What it adds is the reading of the two ways a call can end:

* **allowed** — the call reached ``filing-server``. The receipt lists the identity headers the
  server received, and ``_meta["org.gleif.vlei/report"]`` carries the gateway's verification
  report, which the server decoded from ``x-vlei-report`` and handed back untouched.
* **refused** — ``vlei-authz`` answered 403 before the server was reached. agentgateway returns
  that answer as the HTTP response to the ``tools/call`` POST, which the SDK only surfaces as a
  generic transport error; the body — ``{"layer", "message", "report"}`` — is captured here with a
  response hook so the failure layer is not lost.

Usage from code::

    from gateway_client import call_through_gateway, signed_meta

    meta = signed_meta(credential=chain, signer=signer, tool="submit_filing",
                       arguments=args, delegated_aid=signer.aid, credential_said=said)
    out = await call_through_gateway("http://localhost:3000/mcp", "submit_filing", args, meta)
    # {"allowed": True, "layer": None, "text": "...", "report": {...}, "identity": {...}}

From a shell::

    python examples/regulator/gateway_client.py --world          # demo chain; see --help
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

META_CREDENTIAL = "org.gleif.vlei/credential"
META_SIGNATURE = "org.gleif.vlei/signature"
META_DELEGATED_AID = "org.gleif.vlei/delegatedAid"
META_CREDENTIAL_SAID = "org.gleif.vlei/credentialSaid"
META_REPORT = "org.gleif.vlei/report"
META_FAILURE = "org.gleif.vlei/failure"

DEFAULT_URL = "http://localhost:3000/mcp"

_HEADER_TO_FIELD = {
    "x-vlei-lei": "lei",
    "x-vlei-role": "role",
    "x-vlei-holder-aid": "holderAid",
    "x-vlei-delegate-aid": "delegateAid",
}


def signed_meta(
    *,
    credential: str,
    signer: Any,
    tool: str,
    arguments: dict[str, Any],
    delegated_aid: str | None = None,
    credential_said: str | None = None,
) -> dict[str, Any]:
    """The ``_meta`` a vLEI ``tools/call`` carries, signed over exactly ``{name, arguments}``.

    Sign immediately before calling: the gateway's freshness window is 60 seconds, and any change
    to ``arguments`` after signing is refused as ``digest_mismatch``.
    """
    from mcp_vlei.signing import sign_request

    meta: dict[str, Any] = {
        META_CREDENTIAL: credential,
        META_SIGNATURE: sign_request(signer, "tools/call", {"name": tool, "arguments": arguments}),
    }
    if delegated_aid:
        meta[META_DELEGATED_AID] = delegated_aid
    if credential_said:
        meta[META_CREDENTIAL_SAID] = credential_said
    return meta


async def call_through_gateway(
    url: str,
    tool: str,
    arguments: dict,
    meta: dict,
    *,
    mode: str = "auto",
    timeout: float = 30.0,
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
                  established them, plus ``headers``: what the filing server actually received
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
            async with Client(streamable_http_client(url, http_client=http), mode=mode) as client:
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
    report = meta.get(META_REPORT)
    receipt = result.structured_content if isinstance(result.structured_content, dict) else None
    failure = meta.get(META_FAILURE) or {}
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

DEMO_ARGUMENTS = {"form": "A1", "period": "2026Q2", "payload": {"totalAssets": 84_200_000}}


def _meta_from_args(args: argparse.Namespace, arguments: dict[str, Any]) -> dict[str, Any]:
    if args.meta:
        return json.loads(Path(args.meta).read_text(encoding="utf-8"))
    if args.world:
        # A deterministic demo chain (mcp_vlei.testing): verifies only against a witness serving
        # the same World. Never a real credential.
        from mcp_vlei import Signer
        from mcp_vlei.testing import World

        world = World(role="regulatory-filing", label=args.world_label)
        signer = Signer.from_seed(world.agent.pre, world.agent.seed)
        return signed_meta(
            credential=world.ecr_stream, signer=signer, tool=args.tool, arguments=arguments,
            delegated_aid=world.agent.pre, credential_said=world.ecr_credential.said,
        )
    if args.credential and args.key_store and args.aid:
        from mcp_vlei import Signer

        signer = Signer.from_key_store(args.key_store, args.aid)
        return signed_meta(
            credential=Path(args.credential).read_text(encoding="utf-8").strip(), signer=signer,
            tool=args.tool, arguments=arguments, delegated_aid=args.delegated_aid,
            credential_said=args.credential_said,
        )
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help=f"gateway MCP endpoint ({DEFAULT_URL})")
    parser.add_argument("--tool", default="submit_filing")
    parser.add_argument("--arguments", help="tool arguments as JSON (default: the A1 demo filing)")
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

    arguments = json.loads(args.arguments) if args.arguments else dict(DEMO_ARGUMENTS)
    meta = _meta_from_args(args, arguments)
    out = asyncio.run(call_through_gateway(args.url, args.tool, arguments, meta, mode=args.mode))
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["allowed"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "mcp-vlei" / "src"))
    sys.exit(main())
