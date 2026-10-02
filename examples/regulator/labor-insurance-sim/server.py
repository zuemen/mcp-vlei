"""A labour-insurance enrolment service — simulated — that knows nothing about vLEI.

**Simulated — not connected to the Bureau of Labor Insurance.** It models the shape of a real
business process closely enough for an official to recognise it: an employer files enrolment
(加保) on an employee's start date, withdrawal (退保) on the last day, and adjustments to the
insured salary grade; it can also file up to ten days ahead. The rules it models are sourced in
`docs/GOVERNMENT.md`. It holds no real data: people are fictitious references (`EMP-0001`),
employers are test values, and nothing leaves this process.

This file is still the point of the government scenario. Search it for "vlei" and you will find the
header names it reads and nothing else: no credential parsing, no chain validation, no revocation
check, no signature verification, no dependency on ``mcp_vlei``. The gateway in front of it does all
of that — including the rule that an enrolment date lies between today and ten days ahead — and
passes down the established facts as ordinary request headers. That is the claim stage 3 of
``docs/GOVERNMENT.md`` makes: **an institution does not modify its existing systems.**

Which employer is filing is not a parameter of any tool. It is the legal entity in the caller's
verified credential, mapped to its unified business number (統一編號) through the LEI record's
``registeredAs`` field — here, a table of test values (``registered_as.json``).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

HERE = Path(__file__).resolve().parent

#: On every response, and in every document about this example.
SIMULATED = "Simulated — not connected to the Bureau of Labor Insurance"

mcp = MCPServer(name="labor-insurance-sim", version="0.1.0", instructions=SIMULATED)

# The operator's own Legal Entity credential, published for passive verification (mode (a) of
# `spec/SPEC.md`). Served as published; nothing here parses or verifies it.
LE_CREDENTIAL = Path(
    os.environ.get("VLEI_LE_CREDENTIAL", HERE.parents[2] / "credentials" / "le.cesr")
)
ACCEPTED_ROOTS = [r for r in os.environ.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r]

#: The headers the gateway sets. This tuple is the server's entire vLEI surface.
IDENTITY_HEADERS = ("x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid")
REPORT_HEADER = "x-vlei-report"
#: The extension's namespace, as the gateway states it: the decoded report goes back to the caller
#: under `<namespace>/report`. Taken from the gateway, not written here — this server holds no
#: vLEI names of its own.
NAMESPACE_HEADER = "x-vlei-namespace"
#: A reverse-domain name, as the extension's namespace must be; anything else is not used.
_NAMESPACE_SHAPE = re.compile(r"[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+")
#: For the well-known document, fetched without the gateway: the deployment's configuration.
NAMESPACE = os.environ.get("MCP_VLEI_NAMESPACE", "").strip()
if NAMESPACE and not _NAMESPACE_SHAPE.fullmatch(NAMESPACE):
    NAMESPACE = ""

#: What each tool requires, exactly as the gateway enforces it: the gateway's own policy, published
#: with the tools so a caller can tell before calling whether it is entitled (docs/GOVERNMENT.md,
#: Stage 2). Read and repeated here, never enforced — the gateway decides before this server is
#: reached. One file, so what is published and what is enforced cannot drift apart.
POLICY = Path(os.environ.get("VLEI_AUTHZ_POLICY", HERE.parent / "vlei-authz" / "policy.json"))


def _published(tool: str) -> dict[str, Any] | None:
    """``{"<namespace>/requires": requirement}`` for a tool's ``_meta``, or nothing.

    Nothing without a namespace: a requirement under a name no caller reads would make the tool look
    public, which is worse than saying nothing.
    """
    if not NAMESPACE or not POLICY.is_file():
        return None
    requirement = json.loads(POLICY.read_text(encoding="utf-8")).get("tools", {}).get(tool)
    return {f"{NAMESPACE}/requires": requirement} if requirement else None

#: LEI -> the unified business number its LEI record names in `registeredAs`. Test values.
REGISTERED_AS: dict[str, str] = {
    lei: entry["registeredAs"]
    for lei, entry in json.loads((HERE / "registered_as.json").read_text(encoding="utf-8"))
    .items()
    if not lei.startswith("_")
}

#: A person is a fictitious reference — never anything shaped like a national ID number.
PERSON_REF = re.compile(r"EMP-[0-9]{4}")  # ASCII digits only: \d would also admit ０ and ٠

#: unified business number -> person_ref -> the insured record.
INSURED: dict[str, dict[str, dict[str, Any]]] = {}


class Refused(ToolError):
    """An anticipated refusal. The SDK shows a `ToolError`'s text to the caller; any other
    exception reaches them only as "Error executing tool", which would hide why."""


def _header(headers: Any, name: str) -> str:
    """One value, or a refusal. Two values for an identity header means two writers disagreed."""
    values = headers.getlist(name) if hasattr(headers, "getlist") else [headers.get(name)]
    values = [v for v in values if v is not None]
    if len(values) > 1:
        raise Refused(f"{name} arrived {len(values)} times; refusing an ambiguous identity")
    return values[0] if values else ""


def _caller(ctx: Context) -> dict[str, str]:
    """Read what the gateway established. No verification happens here — that already happened.

    If these headers are absent, the request did not come through the gateway. The server refuses
    rather than guessing: a deployment where it is reachable directly is a misconfiguration.
    """
    headers = ctx.headers or {}
    received = {name: _header(headers, name)
                for name in (*IDENTITY_HEADERS, REPORT_HEADER, NAMESPACE_HEADER)}
    if not received["x-vlei-lei"]:
        raise Refused(
            "no x-vlei-lei header: this server must be reached through the authorization gateway"
        )
    return received


def _employer(caller: dict[str, str]) -> str:
    """The caller's unified business number, from the LEI the gateway established."""
    lei = caller["x-vlei-lei"]
    ubn = REGISTERED_AS.get(lei)
    if not ubn:
        raise Refused(
            f"no unified business number is registered for LEI {lei}; the LEI record's "
            "registeredAs field is what links the two"
        )
    return ubn


def _person(person_ref: str) -> str:
    if not isinstance(person_ref, str) or not PERSON_REF.fullmatch(person_ref):
        raise Refused(
            "person_ref must be a fictitious reference such as EMP-0001; this simulation holds "
            "no real identities"
        )
    return person_ref


def _date(name: str, value: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError) as exc:
        raise Refused(f"{name} must be a date, YYYY-MM-DD") from exc


def _grade(salary_grade: int) -> int:
    if isinstance(salary_grade, bool) or not isinstance(salary_grade, int) or salary_grade < 1:
        raise Refused("salary_grade must be a positive integer (a simulated grade)")
    return salary_grade


def _report(encoded: str) -> dict[str, Any] | None:
    """The gateway's record, decoded for the caller. Decoding is all that happens to it here."""
    if not encoded:
        return None
    try:
        report = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (binascii.Error, ValueError):
        return None
    return report if isinstance(report, dict) else None


def _filed_by(caller: dict[str, str]) -> dict[str, str]:
    return {
        "lei": caller["x-vlei-lei"],
        "role": caller["x-vlei-role"],
        "holderAid": caller["x-vlei-holder-aid"],
        "agentAid": caller["x-vlei-delegate-aid"],
    }


def _receipt(caller: dict[str, str], body: dict[str, Any]) -> CallToolResult:
    receipt = {
        "simulated": SIMULATED,
        **body,
        "receivedHeaders": {name: caller[name] for name in IDENTITY_HEADERS if caller[name]},
        "reportReceived": bool(caller[REPORT_HEADER]),
    }
    report = _report(caller[REPORT_HEADER])
    namespace = caller.get(NAMESPACE_HEADER)
    if namespace and not _NAMESPACE_SHAPE.fullmatch(namespace):
        namespace = None
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(receipt, indent=2, ensure_ascii=False))],
        structured_content=receipt,
        meta={f"{namespace}/report": report} if report is not None and namespace else None,
    )


def _refused(caller: dict[str, str], message: str) -> CallToolResult:
    """The system's own refusal, after the gateway verified the caller. The gateway's report travels
    with it, as it does with a receipt: a caller can then show that the identity was verified and a
    business rule said no — instead of an error with no verification behind it."""
    report = _report(caller[REPORT_HEADER])
    namespace = caller.get(NAMESPACE_HEADER)
    if namespace and not _NAMESPACE_SHAPE.fullmatch(namespace):
        namespace = None
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        is_error=True,
        meta={f"{namespace}/report": report} if report is not None and namespace else None,
    )


@mcp.custom_route("/.well-known/vlei", methods=["GET"])
async def well_known(request: Request) -> JSONResponse:
    """Who operates this endpoint, fetchable without a session."""
    if not LE_CREDENTIAL.exists():
        return JSONResponse({"error": "no LE credential configured"}, status_code=404)
    if not NAMESPACE:
        return JSONResponse({"error": "no MCP_VLEI_NAMESPACE configured"}, status_code=404)
    return JSONResponse(
        {
            "extension": f"{NAMESPACE}/identity",
            "credential": LE_CREDENTIAL.read_text(encoding="utf-8").strip(),
            "acceptedRoots": ACCEPTED_ROOTS,
            "signatureAlgs": ["Ed25519"],
            "note": SIMULATED,
        }
    )


@mcp.tool(meta=_published("list_insured"))
def list_insured(ctx: Context) -> CallToolResult:
    """List the people the caller's employer has enrolled. Simulated — not connected to the Bureau
    of Labor Insurance. Only the caller's own employer's records: which employer is the caller's
    verified legal entity, not an argument."""
    caller = _caller(ctx)
    try:
        ubn = _employer(caller)
        return _receipt(caller, {
            "employer": {"lei": caller["x-vlei-lei"], "unifiedBusinessNumber": ubn,
                         "linkedBy": "LEI record registeredAs (test value)"},
            "insured": sorted(INSURED.get(ubn, {}).values(), key=lambda r: r["personRef"]),
        })
    except Refused as exc:
        return _refused(caller, str(exc))


@mcp.tool(meta=_published("enroll_employee"))
def enroll_employee(person_ref: str, start_date: str, salary_grade: int,
                    ctx: Context) -> CallToolResult:
    """Enrol an employee (加保) from their start date. Simulated — not connected to the Bureau of
    Labor Insurance. The gateway admits a start date from today to ten days ahead."""
    caller = _caller(ctx)
    try:
        ubn = _employer(caller)
        record = {
            "personRef": _person(person_ref),
            "startDate": _date("start_date", start_date),
            "salaryGrade": _grade(salary_grade),
            "status": "insured",
            "filedOn": date.today().isoformat(),
            "filedBy": _filed_by(caller),
        }
        again = person_ref in INSURED.get(ubn, {})
        INSURED.setdefault(ubn, {})[person_ref] = record
        return _receipt(caller, {"action": "enrol", "employer": ubn, "record": record,
                                 "note": "already enrolled; record replaced" if again else None})
    except Refused as exc:
        return _refused(caller, str(exc))


@mcp.tool(meta=_published("withdraw_employee"))
def withdraw_employee(person_ref: str, end_date: str, ctx: Context) -> CallToolResult:
    """Withdraw an employee (退保) on their last day. Simulated — not connected to the Bureau of
    Labor Insurance. The gateway admits an end date from today to ten days ahead."""
    caller = _caller(ctx)
    try:
        ubn = _employer(caller)
        record = INSURED.get(ubn, {}).get(_person(person_ref))
        if not record or record["status"] != "insured":
            raise Refused(f"{person_ref} is not enrolled by employer {ubn}")
        record.update(status="withdrawn", endDate=_date("end_date", end_date),
                      withdrawnBy=_filed_by(caller))
        return _receipt(caller, {"action": "withdraw", "employer": ubn, "record": record})
    except Refused as exc:
        return _refused(caller, str(exc))


@mcp.tool(meta=_published("adjust_insured_salary"))
def adjust_insured_salary(person_ref: str, salary_grade: int, ctx: Context) -> CallToolResult:
    """Adjust an enrolled employee's insured salary grade. Simulated — not connected to the Bureau
    of Labor Insurance. The gateway admits only the payroll role."""
    caller = _caller(ctx)
    try:
        ubn = _employer(caller)
        record = INSURED.get(ubn, {}).get(_person(person_ref))
        if not record or record["status"] != "insured":
            raise Refused(f"{person_ref} is not enrolled by employer {ubn}")
        record.update(salaryGrade=_grade(salary_grade), adjustedBy=_filed_by(caller))
        return _receipt(caller, {"action": "adjust", "employer": ubn, "record": record})
    except Refused as exc:
        return _refused(caller, str(exc))


def create_app(*, host: str | None = None) -> Starlette:
    """The streamable-HTTP app, with the gateway's view of this server in the allowed hosts:
    agentgateway reaches it as ``labor-insurance-sim:8081``, and a default that only admits
    ``localhost`` would answer the gateway with 421."""
    allowed = [
        h.strip()
        for h in os.environ.get(
            "LABOR_SIM_ALLOWED_HOSTS",
            "labor-insurance-sim,labor-insurance-sim:*,localhost,localhost:*,127.0.0.1,127.0.0.1:*",
        ).split(",")
        if h.strip()
    ]
    return mcp.streamable_http_app(
        host=host or os.environ.get("HOST", "0.0.0.0"),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"http://{h}" for h in allowed],
        ),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8081")),
    )
