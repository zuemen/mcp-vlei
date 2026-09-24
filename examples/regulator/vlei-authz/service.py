"""vlei-authz — ``mcp_vlei``'s verification, behind agentgateway's HTTP external authorization.

Conforms to agentgateway's HTTP ``extAuthz`` contract: a 200 allows the request and the headers
named in ``includeResponseHeaders`` are copied onto it; anything else is returned to the caller as
the denial.

This file contains no signature, key-state, chain or revocation logic. Every decision is
:meth:`mcp_vlei.VleiIdentity.verify_call` — the same checks, in the same order, as the in-process
extension — so an institution's choice between "embed the package" and "put a gateway in front" is
a deployment decision, not a difference in what gets checked. In particular the key a request is
verified under is read from a witness's copy of the signer's key event log, never from the request.

What this service adds is only what a gateway needs:

* **the policy** — which filing-server tool requires what (``policy.json``). The gateway holds it
  because it decides before the server is reached. The list is closed: a ``tools/call`` naming a
  tool the policy does not list is refused rather than treated as public.
* **the translation** — an allowed call becomes five request headers for the backend; a refused
  one becomes a 403 whose body names the failure layer.

The credential and signature arrive in the JSON-RPC body's ``params._meta``, so
``extAuthz.includeRequestBody`` must be set; the gateway configuration raises ``maxRequestBytes`` to
65536 because a chained CESR ACDC exceeds the 8192-byte default. There is deliberately no header
fallback: a call is verified from the body the backend will execute, or not at all.

Configuration is environment only:

* ``VLEI_LE_CREDENTIAL`` — the regulator's own LE credential (CESR). Default
  ``credentials/le.cesr``.
* ``VLEI_ACCEPTED_ROOTS`` — comma-separated root AIDs a chain may terminate at. Required.
* ``VLEI_WITNESS_URL`` — where key event logs and TELs are read. Default
  ``http://witness-demo:5642``.
* ``VLEI_WITNESS_TIMEOUT`` — seconds per witness request. Default 3. It must fit, with room to
  spare, inside the gateway's ext-authz timeout (config.yaml sets 10s; agentgateway's default is
  2s); otherwise an unreachable witness surfaces as the gateway's generic "external authorization
  failed" instead of the named layer. Either way the call is refused.
* ``VLEI_REVOCATION_SOURCE`` — ``tel`` (default), ``verifier`` or ``none``.
* ``VLEI_VERIFIER_URL`` — only with ``VLEI_REVOCATION_SOURCE=verifier``.
* ``VLEI_AUTHZ_POLICY`` — the per-tool policy. Default ``policy.json`` next to this file.
* ``VLEI_AUDIT_LOG`` — JSON-lines decision log. Unset: decisions are printed to stdout.
"""

from __future__ import annotations

import base64
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from mcp.types import CallToolRequestParams
from pydantic import ValidationError

from mcp_vlei import VerificationReport, VleiIdentity
from mcp_vlei.errors import VleiError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

DEFAULT_WITNESS_URL = "http://witness-demo:5642"

#: The whole interface between this service and the filing server. Every 200 carries all five —
#: empty when nothing was established — so the authorizer is the only writer of these names on a
#: request that reaches the backend, whatever a client put there itself.
IDENTITY_HEADERS = ("x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid")
REPORT_HEADER = "x-vlei-report"
FAILURE_HEADER = "x-vlei-failure"

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


# ------------------------------------------------------------------------------------------- #
# Configuration
# ------------------------------------------------------------------------------------------- #

@dataclass
class Settings:
    le_credential: Path
    accepted_roots: list[str]
    witness_url: str
    revocation_source: str = "tel"
    verifier_url: str = ""
    witness_timeout: float = 3.0
    policy_path: Path = HERE / "policy.json"
    audit_log: Path | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        roots = [r.strip() for r in env.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r.strip()]
        audit = env.get("VLEI_AUDIT_LOG", "").strip()
        return cls(
            le_credential=Path(env.get("VLEI_LE_CREDENTIAL", str(ROOT / "credentials" / "le.cesr"))),
            accepted_roots=roots,
            witness_url=env.get("VLEI_WITNESS_URL", DEFAULT_WITNESS_URL).strip(),
            revocation_source=env.get("VLEI_REVOCATION_SOURCE", "tel").strip(),
            verifier_url=env.get("VLEI_VERIFIER_URL", "").strip(),
            witness_timeout=float(env.get("VLEI_WITNESS_TIMEOUT", "3") or 3),
            policy_path=Path(env.get("VLEI_AUTHZ_POLICY", str(HERE / "policy.json"))),
            audit_log=Path(audit) if audit else None,
        )

    def identity(self) -> VleiIdentity:
        """The package's verifier, configured for this deployment. Fails loudly when misconfigured."""
        if not self.accepted_roots:
            raise RuntimeError(
                "VLEI_ACCEPTED_ROOTS is empty: without an accepted root no chain can be trusted "
                "(see credentials/env.json 'acceptedRoots' after scripts/bootstrap-credentials.sh)"
            )
        if not self.le_credential.is_file():
            raise RuntimeError(f"VLEI_LE_CREDENTIAL {self.le_credential} does not exist")
        return VleiIdentity(
            le_credential=self.le_credential,
            accepted_roots=self.accepted_roots,
            witness_url=self.witness_url,
            # Several witnesses (VLEI_WITNESS_URLS, comma-separated): each caller's key log is
            # compared across them and a fork refused.
            witness_urls=[u.strip() for u in os.environ.get("VLEI_WITNESS_URLS", "").split(",")
                          if u.strip()] or None,
            revocation_source=self.revocation_source,
            verifier_url=self.verifier_url,
            # Bounded, so an unreachable witness is named (`invalid_signature ... not established`)
            # before the gateway gives up on this service and answers with a generic denial.
            witness_client=httpx.AsyncClient(timeout=httpx.Timeout(self.witness_timeout)),
        )


def load_policy(path: Path) -> dict[str, dict[str, Any] | None]:
    """Tool name -> requirement, or ``None`` for a public tool."""
    document = json.loads(path.read_text(encoding="utf-8"))
    tools = document.get("tools", document)
    if not isinstance(tools, dict):
        raise RuntimeError(f"{path}: 'tools' must map tool names to requirements")
    return {
        name: (dict(requirement) if requirement else None)
        for name, requirement in tools.items()
        if not name.startswith("_")
    }


# ------------------------------------------------------------------------------------------- #
# Audit
# ------------------------------------------------------------------------------------------- #

@dataclass
class Audit:
    """One JSON object per decision, allowed and denied alike.

    A log that records only refusals cannot answer "who filed this?", which is the question stage 5
    of docs/GOVERNMENT.md exists to make answerable.
    """

    path: Path | None = None
    records: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, **fields: Any) -> None:
        fields["at"] = datetime.now(timezone.utc).isoformat()
        self.records.append(fields)
        line = json.dumps(fields, ensure_ascii=False)
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                return
            except OSError:
                pass  # an unwritable log must not take the gateway down, but it must be visible
        print("AUDIT", line, flush=True)


# ------------------------------------------------------------------------------------------- #
# Wire helpers
# ------------------------------------------------------------------------------------------- #

def encode_report(report: dict[str, Any]) -> str:
    """``base64url(JSON)``, unpadded — safe in a header, and no credential content (see report.py)."""
    raw = json.dumps(report, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _allow(headers: Mapping[str, str] | None = None) -> Response:
    out = {name: "" for name in (*IDENTITY_HEADERS, REPORT_HEADER)}
    out.update({k: v for k, v in (headers or {}).items() if v is not None})
    return Response(status_code=200, headers=out)


def _deny(layer: str | None, message: str, report: dict[str, Any] | None = None) -> Response:
    """403 with the layer named, in the body and in a header.

    The header survives a gateway that replaces the body of a denial; without the layer the agent
    sees "forbidden" and the skill has nothing to act on.
    """
    headers = {FAILURE_HEADER: layer} if layer else {}
    return JSONResponse(
        status_code=403,
        content={"layer": layer, "message": message, "report": report},
        headers=headers,
    )


class _Refused(Exception):
    """A body this service will not pass on. Not a vLEI layer: nothing was presented to check."""


def _tool_calls(body: bytes) -> list[dict[str, Any]]:
    """The ``tools/call`` messages in a request body. Empty for everything else.

    Fails closed on a body it cannot read: a streamable-HTTP POST is always JSON, so a body that is
    not is either broken or an attempt to find a parser the backend disagrees with.
    """
    if not body.strip():
        return []  # GET (SSE stream), DELETE (session end): nothing is asserted, nothing to check
    try:
        message = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _Refused(f"the request body is not JSON ({exc.__class__.__name__})") from exc
    messages = message if isinstance(message, list) else [message]
    if not all(isinstance(m, dict) for m in messages):
        raise _Refused("the request body is not a JSON-RPC message")
    calls = [m for m in messages if m.get("method") == "tools/call"]
    if calls and len(messages) > 1:
        # One request, one caller: the headers a 200 produces can describe a single identity.
        raise _Refused("a JSON-RPC batch carrying tools/call is refused; send one call per request")
    return calls


# ------------------------------------------------------------------------------------------- #
# The service
# ------------------------------------------------------------------------------------------- #

def create_app(
    *,
    identity: VleiIdentity | None = None,
    policy: dict[str, dict[str, Any] | None] | None = None,
    settings: Settings | None = None,
    audit: Audit | None = None,
) -> FastAPI:
    """Build the service. Anything not given is read from the environment at startup."""
    state: dict[str, Any] = {"identity": identity, "policy": policy, "settings": settings}
    record = audit or Audit()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if state["identity"] is None or state["policy"] is None:
            cfg = state["settings"] or Settings.from_env()
            state["settings"] = cfg
            if record.path is None and audit is None:
                record.path = cfg.audit_log
            if state["policy"] is None:
                state["policy"] = load_policy(cfg.policy_path)
            if state["identity"] is None:
                state["identity"] = cfg.identity()
        yield

    app = FastAPI(title="vlei-authz", lifespan=lifespan)
    app.state.audit = record

    @app.api_route("/auth/mcp", methods=ALL_METHODS)
    async def authorize(request: Request) -> Response:
        body = await request.body()
        try:
            calls = _tool_calls(body)
        except _Refused as exc:
            record(decision="deny", tool=None, layer=None, message=str(exc))
            return _deny(None, str(exc))

        # initialize, tools/list, notifications, the SSE GET and the session DELETE carry no
        # credential and assert nothing. Refusing them would break discovery for every client,
        # including the ones about to present a perfectly good credential.
        if not calls:
            return _allow()

        raw = calls[0].get("params")
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            message = "tools/call without a tool name"
            record(decision="deny", tool=None, layer=None, message=message)
            return _deny(None, message)
        tool = raw["name"]

        tools: dict[str, dict[str, Any] | None] = state["policy"]
        if tool not in tools:
            message = (
                f"tool {tool!r} is not in this gateway's policy; the list of reachable tools is "
                "closed, so an unlisted tool is refused rather than treated as public"
            )
            record(decision="deny", tool=tool, layer=None, message=message)
            return _deny(None, message)

        requirement = tools[tool]
        if not requirement:
            record(decision="allow", tool=tool, note="public tool")
            return _allow()

        try:
            params = CallToolRequestParams.model_validate(raw)
        except ValidationError as exc:
            message = f"tools/call params do not validate ({exc.error_count()} errors)"
            record(decision="deny", tool=tool, layer=None, message=message)
            return _deny(None, message)

        report = VerificationReport(tool=tool)
        try:
            result = await state["identity"].verify_call(params, requirement, report=report)
        except VleiError as exc:
            record(
                decision="deny", tool=tool, layer=exc.layer.value, message=exc.message,
                aid=exc.aid, report=report.as_dict(),
            )
            return _deny(exc.layer.value, exc.message, report.as_dict())

        facts = report.as_dict()
        record(
            decision="allow",
            tool=tool,
            lei=result.lei,
            role=result.role,
            holderAid=result.holder_aid,
            delegateAid=result.aid if result.aid != result.holder_aid else None,
            credentialSaid=result.credential_said,
        )
        # Hand the backend the established facts and nothing else. The filing server reads these
        # headers and contains no identity code.
        return _allow({**result.to_headers(), REPORT_HEADER: encode_report(facts)})

    @app.get("/health")
    async def health() -> dict[str, Any]:
        cfg: Settings | None = state["settings"]
        tools = state["policy"] or {}
        return {
            "ok": state["identity"] is not None,
            "witnessUrl": getattr(getattr(state["identity"], "key_states", None), "witness_url", None),
            "acceptedRoots": getattr(state["identity"], "accepted_roots", []),
            "revocationSource": getattr(state["identity"], "revocation_source", None),
            "policy": str(cfg.policy_path) if cfg else None,
            "protectedTools": sorted(t for t, r in tools.items() if r),
            "publicTools": sorted(t for t, r in tools.items() if not r),
        }

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "9000")),
    )
