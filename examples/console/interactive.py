"""The interactive page (`/app`): its scenarios, the calls a visitor builds, and the audit log.

A call made here is signed — or, for an attack, deliberately mis-signed — as the agent, and handed
to the same verification the recording page uses: the gateway, or the gateway's own policy run in
process. Nothing in this module decides an outcome. It builds what is sent, and reports what came
back in the verifier's words.

`router(backend)` builds the routes. `app.py` passes in what it already has — the agent's signer,
the call through the gateway, revocation — so this file holds no key and no credential.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

#: What each tool of labor-insurance-sim takes, in the order the form shows it.
TOOL_FIELDS: dict[str, tuple[str, ...]] = {
    "enroll_employee": ("person_ref", "start_date", "salary_grade"),
    "withdraw_employee": ("person_ref", "end_date"),
    "adjust_insured_salary": ("person_ref", "salary_grade"),
    "list_insured": (),
}
DATE_FIELDS = ("start_date", "end_date")
VARIANTS = ("none", "strip", "replay", "tamper", "wrong_key")
#: How old a replayed signature is: five times the verifier's sixty-second window.
REPLAY_AGE = timedelta(minutes=5)
AUDIT_SIZE = 50
#: The checks that establish who is calling. The audit log names an identity only after all of them.
IDENTITY_CHECKS = ("credential_present", "freshness", "digest", "signature", "delegation", "chain")
#: The simulator's own rule: fictitious references only, ASCII digits.
PERSON_REF = re.compile(r"EMP-[0-9]{4}")
MAX_GRADE = 60

_ENROL = {"person_ref": "EMP-0101", "start_date": 0, "salary_grade": 3}

#: The scenario list. Dates are days from today: the policy's rule is relative to the day.
SCENARIOS: list[dict[str, Any]] = [
    {"id": "impersonation", "group": "problem", "tool": "reserve_gpu_quota", "arguments": {},
     "variant": "none", "expect": {"status": "self-asserted"}},
    {"id": "enroll-today", "group": "allowed", "tool": "enroll_employee", "arguments": _ENROL,
     "variant": "none", "expect": {"status": "allowed"}},
    {"id": "list-insured", "group": "allowed", "tool": "list_insured", "arguments": {},
     "variant": "none", "expect": {"status": "allowed"}},
    {"id": "salary-by-filer", "group": "policy", "tool": "adjust_insured_salary",
     "arguments": {"person_ref": "EMP-0101", "salary_grade": 4}, "variant": "none",
     "expect": {"status": "refused", "check": "authority", "layer": "role_mismatch"}},
    {"id": "enroll-15-days", "group": "policy", "tool": "enroll_employee",
     "arguments": {**_ENROL, "person_ref": "EMP-0102", "start_date": 15}, "variant": "none",
     "expect": {"status": "refused", "check": "authority", "layer": "scope_exceeded"}},
    {"id": "no-credential", "group": "attack", "tool": "enroll_employee", "arguments": _ENROL,
     "variant": "strip",
     "expect": {"status": "refused", "check": "credential_present", "layer": "missing_credential"}},
    {"id": "replayed", "group": "attack", "tool": "enroll_employee", "arguments": _ENROL,
     "variant": "replay",
     "expect": {"status": "refused", "check": "freshness", "layer": "stale_signature"}},
    {"id": "tampered", "group": "attack", "tool": "enroll_employee", "arguments": _ENROL,
     "variant": "tamper",
     "expect": {"status": "refused", "check": "digest", "layer": "digest_mismatch"}},
    {"id": "wrong-key", "group": "attack", "tool": "enroll_employee", "arguments": _ENROL,
     "variant": "wrong_key",
     "expect": {"status": "refused", "check": "signature", "layer": "invalid_signature"}},
    {"id": "after-revocation", "group": "revocation", "tool": "enroll_employee",
     "arguments": _ENROL, "variant": "none", "needs": "revoked",
     "expect": {"status": "refused", "check": "revocation", "layer": "revoked"}},
]
SCENARIOS_BY_ID = {s["id"]: s for s in SCENARIOS}


class BadRequest(ValueError):
    """A call the page will not sign, and why — in words a visitor can act on. `field` names the
    argument at fault, so the page can mark it in the visitor's language."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


@dataclass
class Backend:
    """What `app.py` already has, handed to the routes. Every field is a callable, so the page reads
    the console's state at the moment of a call rather than at import."""

    policy_tools: Callable[[], dict[str, Any]]
    today: Callable[[], date]
    #: sign(tool, arguments, *, ts=None, signer=None) -> the request `_meta`
    sign: Callable[..., dict[str, Any]]
    #: a signer that claims the agent's identifier with a key that is not in its key log
    fresh_signer: Callable[[], Any]
    send: Callable[[str, dict[str, Any], dict[str, Any] | None], Awaitable[dict[str, Any]]]
    checks: Callable[[dict[str, Any] | None], list[dict[str, Any]]]
    identity: Callable[[], dict[str, Any]]
    status: Callable[[], Awaitable[dict[str, Any]]]
    #: revoke() -> whether a verification read the revocation back before it returned
    revoke: Callable[[], Awaitable[bool]]
    reissue: Callable[[], Awaitable[None]]
    impersonation: Callable[[], Awaitable[dict[str, Any]]]


def resolve(arguments: dict[str, Any], today: date) -> dict[str, Any]:
    """A scenario's arguments with its dates, given as days from today, made dates."""
    out = dict(arguments)
    for name in DATE_FIELDS:
        value = out.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            out[name] = (today + timedelta(days=value)).isoformat()
    return out


def validate(tool: Any, arguments: Any, variant: Any,
             tools: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    """The call, checked before anything is signed. Raises `BadRequest` with the reason."""
    offered = sorted(t for t in TOOL_FIELDS if t in tools)
    if not isinstance(tool, str) or tool not in offered:
        raise BadRequest(f"unknown tool {tool!r}; one of: {', '.join(offered)}", "tool")
    if variant not in VARIANTS:
        raise BadRequest(f"unknown variant {variant!r}; one of: {', '.join(VARIANTS)}", "variant")
    if not isinstance(arguments, dict):
        raise BadRequest("arguments must be an object")
    fields = TOOL_FIELDS[tool]
    extra = sorted(set(arguments) - set(fields))
    if extra:
        raise BadRequest(f"{tool} takes no {', '.join(extra)}")
    missing = [name for name in fields if name not in arguments]
    if missing:
        raise BadRequest(f"{tool} needs {', '.join(missing)}", missing[0])
    clean: dict[str, Any] = {}
    for name in fields:
        value = arguments[name]
        if name == "person_ref":
            if not isinstance(value, str) or not PERSON_REF.fullmatch(value):
                raise BadRequest("person_ref is a fictitious reference: EMP- and four digits, "
                                 "e.g. EMP-0101", name)
        elif name in DATE_FIELDS:
            parsed = None
            if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                try:
                    parsed = date.fromisoformat(value).isoformat()
                except ValueError:
                    parsed = None
            if parsed is None:
                raise BadRequest(f"{name} must be a real date, YYYY-MM-DD", name)
            value = parsed
        elif name == "salary_grade":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_GRADE:
                raise BadRequest(f"salary_grade must be a whole number from 1 to {MAX_GRADE}", name)
        clean[name] = value
    if variant == "tamper" and not clean:
        raise BadRequest(f"{tool} has nothing to tamper with: it takes no arguments")
    return tool, clean, variant


def tampered(arguments: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """What a party in the middle would change after the agent signed: the salary grade if there is
    one, else the date, else the person. Returns (the arguments sent, what changed)."""
    sent = dict(arguments)
    if "salary_grade" in sent:
        field, old = "salary_grade", sent["salary_grade"]
        new: Any = old + 6 if old + 6 <= MAX_GRADE else 1
    else:
        date_field = next((name for name in DATE_FIELDS if name in sent), None)
        if date_field:
            field, old = date_field, sent[date_field]
            try:
                new = (date.fromisoformat(old) + timedelta(days=1)).isoformat()
            except OverflowError:  # 9999-12-31 has no tomorrow
                new = (date.fromisoformat(old) - timedelta(days=1)).isoformat()
        else:
            field, old = "person_ref", sent["person_ref"]
            new = "EMP-9999" if old != "EMP-9999" else "EMP-9998"
    sent[field] = new
    return sent, {"field": field, "signed": old, "sent": new}


def _short(value: Any, limit: int = 60, keep: int = 40) -> Any:
    """Only what no one reads whole is shortened — the credential stream, the signature. A
    timestamp, a digest, an identifier stay as they are: a visitor may want to compare them."""
    if isinstance(value, str) and len(value) > limit:
        return value[:keep] + "…"
    if isinstance(value, dict):
        return {key: _short(item, limit, keep) for key, item in value.items()}
    return value


def shown_request(tool: str, arguments: dict[str, Any],
                  meta: dict[str, Any] | None) -> dict[str, Any]:
    """The request as sent, for a screen: credential and signature values shortened, nothing else
    changed. What is asked comes before the proof."""
    params: dict[str, Any] = {"name": tool, "arguments": arguments}
    if meta:
        params["_meta"] = _short(meta)
    return {"method": "tools/call", "params": params}


def outcome(run: dict[str, Any]) -> dict[str, Any]:
    """Allowed, refused or unavailable — read from the verifier's report, never inferred."""
    if not run.get("reachable"):
        return {"status": "unavailable", "check": None, "layer": None,
                "detail": f"{run.get('url')} did not answer: {run.get('error', '')}".strip()}
    report = run.get("report") or {}
    failed = next((c for c in report.get("checks", []) if c.get("passed") is False), None)
    if failed:
        return {"status": "refused", "check": failed["name"],
                "layer": failed.get("layer") or report.get("layer"), "detail": failed.get("detail")}
    if report.get("allowed") is True:
        return {"status": "allowed", "check": None, "layer": None, "detail": None}
    # No report, or one that does not say allowed: nothing verified this call, so it is not allowed.
    return {"status": "refused", "check": None, "layer": report.get("layer") or run.get("layer"),
            "detail": run.get("text") or "answered without a verification report"}


def server_answer(run: dict[str, Any]) -> dict[str, Any] | None:
    """What labor-insurance-sim answered, when the call reached it. `None` when it did not: refused
    at the gateway, the gateway down, or verified in process with no server behind it."""
    if run.get("target") != "gateway" or not run.get("reachable"):
        return None
    if outcome(run)["status"] != "allowed":
        return None
    text = run.get("text")
    try:
        body = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        body = None
    return {"ok": bool(run.get("allowed")), "body": body,
            "text": None if body is not None else text}


def _replay_ts() -> str:
    moment = datetime.now(timezone.utc) - REPLAY_AGE
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def run_call(backend: Backend, tool: str, arguments: dict[str, Any],
                   variant: str) -> dict[str, Any]:
    """Sign the call as the agent — or as the attack does — send it, and report what came back."""
    signed = dict(arguments)
    sent = dict(arguments)
    change = None
    meta: dict[str, Any] | None
    if variant == "strip":
        meta = None
    elif variant == "replay":
        meta = backend.sign(tool, signed, ts=_replay_ts())
    elif variant == "wrong_key":
        meta = backend.sign(tool, signed, signer=backend.fresh_signer())
    else:
        meta = backend.sign(tool, signed)
        if variant == "tamper":
            sent, change = tampered(signed)
    run = await backend.send(tool, sent, meta)
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "tool": tool,
        "variant": variant,
        "request": shown_request(tool, sent, meta),
        "tampered": change,
        "checks": backend.checks(run.get("report")),
        "outcome": outcome(run),
        "server": server_answer(run),
        "caller": backend.identity(),
        "verified": (run.get("report") or {}).get("identity"),
        "target": run.get("target"),
        "url": run.get("url"),
    }


def router(backend: Backend) -> APIRouter:
    """The `/api` routes for the page. One lock: there is one agent key and one credential."""
    api = APIRouter(prefix="/api")
    lock = asyncio.Lock()
    audit: list[dict[str, Any]] = []
    public = os.environ.get("VLEI_PUBLIC") == "1"
    shared = ("revocation changes the credential every visitor shares; on the public site only the "
              "presenter can revoke or re-issue")

    def record(entry: dict[str, Any], scenario: str | None) -> None:
        # Only an identity the verifier established goes in the log — the signature, the delegation
        # and the chain all verified. A call refused before that (no credential, a stale or altered
        # request, another key) is from whoever it claimed to be, which the log must not repeat as
        # fact. One refused after it (the role, a revocation) is from a proven entity and role.
        states = {c.get("id"): c.get("status") for c in entry.get("checks") or []}
        established = all(states.get(name) == "pass" for name in IDENTITY_CHECKS)
        caller = (entry.get("verified") or {}) if established else {}
        audit.insert(0, {
            "time": entry["time"], "scenario": scenario, "tool": entry["tool"],
            "variant": entry["variant"], "status": entry["outcome"]["status"],
            "check": entry["outcome"].get("check"), "layer": entry["outcome"].get("layer"),
            "systemRefused": bool(entry.get("server") and not entry["server"].get("ok")),
            "lei": caller.get("lei"), "role": caller.get("role"),
        })
        del audit[AUDIT_SIZE:]

    @api.get("/scenarios")
    async def scenarios() -> JSONResponse:
        today = backend.today()
        tools = backend.policy_tools()
        return JSONResponse({
            "scenarios": [dict(s, arguments=resolve(s["arguments"], today)) for s in SCENARIOS],
            "tools": {tool: list(fields) for tool, fields in TOOL_FIELDS.items() if tool in tools},
            "variants": list(VARIANTS),
            "today": today.isoformat(),
        })

    @api.post("/call")
    async def call(body: dict[str, Any] = Body(...)) -> JSONResponse:
        try:
            tool, arguments, variant = validate(body.get("tool"), body.get("arguments", {}),
                                                body.get("variant", "none"),
                                                backend.policy_tools())
        except BadRequest as exc:
            return JSONResponse({"error": str(exc), "field": exc.field}, status_code=400)
        async with lock:
            try:
                entry = await run_call(backend, tool, arguments, variant)
            except Exception as exc:  # noqa: BLE001 - said, not a bare 500
                return JSONResponse({"error": f"{type(exc).__name__}: {exc}"[:300]}, status_code=502)
        scenario = body.get("scenario")
        record(entry, scenario if isinstance(scenario, str) and scenario in SCENARIOS_BY_ID else None)
        return JSONResponse(entry)

    @api.post("/call/impersonation")
    async def impersonation() -> JSONResponse:
        async with lock:
            entry = await backend.impersonation()
        record(entry, "impersonation")
        return JSONResponse(entry)

    @api.get("/status")
    async def status() -> JSONResponse:
        return JSONResponse(dict(await backend.status(), public=public))

    @api.post("/revoke")
    async def revoke() -> JSONResponse:
        if public:
            return JSONResponse({"error": shared}, status_code=403)
        async with lock:
            try:
                confirmed = await backend.revoke()
            except (RuntimeError, OSError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse(dict(await backend.status(), public=public, confirmed=bool(confirmed)))

    @api.post("/reissue")
    async def reissue() -> JSONResponse:
        if public:
            return JSONResponse({"error": shared}, status_code=403)
        async with lock:
            try:
                await backend.reissue()
            except (RuntimeError, OSError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse(dict(await backend.status(), public=public))

    @api.get("/log")
    async def log() -> JSONResponse:
        return JSONResponse({"entries": audit})

    return api
