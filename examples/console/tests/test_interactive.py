"""The interactive page (`/app`): calls a visitor builds, the scenarios, the audit log, the strings.

Like the scene tests, these run on an in-process KERI world (`mcp_vlei.testing.World`) — real key
event logs and issuances behind an in-process witness — by the same code path as a live gateway, and
need no containers. What is checked is what a visitor would see: that each scenario and each attack
is refused at the check the page says it is, that a bad request is refused before anything is
signed, and that nothing on the page decides an outcome.

    pytest examples/console/tests/test_interactive.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "examples" / "console"
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))
sys.path.insert(0, str(CONSOLE))

import interactive  # noqa: E402
from mcp_vlei.errors import FailureLayer  # noqa: E402
from mcp_vlei.report import CHECK_ORDER  # noqa: E402

TODAY = date(2026, 9, 30)
TOOLS = {"enroll_employee": {}, "withdraw_employee": {}, "adjust_insured_salary": {},
         "list_insured": {}}


# --------------------------------------------------------------------------------------------- #
# Pure functions
# --------------------------------------------------------------------------------------------- #

def test_scenario_dates_are_days_from_today():
    out = interactive.resolve({"person_ref": "EMP-0101", "start_date": 15, "salary_grade": 3}, TODAY)
    assert out == {"person_ref": "EMP-0101", "start_date": "2026-10-15", "salary_grade": 3}


def test_a_valid_call_passes_validation_unchanged():
    args = {"person_ref": "EMP-0101", "start_date": "2026-09-30", "salary_grade": 3}
    assert interactive.validate("enroll_employee", args, "none", TOOLS) == (
        "enroll_employee", args, "none")


@pytest.mark.parametrize("tool, args, variant, says", [
    ("delete_everything", {}, "none", "unknown tool"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "2026-09-30", "salary_grade": 3},
     "sneaky", "unknown variant"),
    ("enroll_employee", {"person_ref": "Alice", "start_date": "2026-09-30", "salary_grade": 3},
     "none", "person_ref"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "2026-02-30", "salary_grade": 3},
     "none", "start_date"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "", "salary_grade": 3},
     "none", "start_date"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "2026-09-30", "salary_grade": 0},
     "none", "salary_grade"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "2026-09-30", "salary_grade": True},
     "none", "salary_grade"),
    ("enroll_employee", {"person_ref": "EMP-0101", "start_date": "2026-09-30"}, "none", "needs"),
    ("list_insured", {"person_ref": "EMP-0101"}, "none", "takes no"),
    ("list_insured", {}, "tamper", "nothing to tamper"),
    ("enroll_employee", ["EMP-0101"], "none", "object"),
])
def test_a_bad_call_is_refused_before_anything_is_signed(tool, args, variant, says):
    with pytest.raises(interactive.BadRequest) as raised:
        interactive.validate(tool, args, variant, TOOLS)
    assert says in str(raised.value)


def test_tampering_changes_the_salary_grade_and_says_so():
    signed = {"person_ref": "EMP-0101", "start_date": "2026-09-30", "salary_grade": 3}
    sent, change = interactive.tampered(signed)
    assert sent["salary_grade"] == 9 and sent["person_ref"] == "EMP-0101"
    assert change == {"field": "salary_grade", "signed": 3, "sent": 9}
    assert signed["salary_grade"] == 3  # what the agent signed is not touched


def test_tampering_without_a_grade_moves_the_date():
    sent, change = interactive.tampered({"person_ref": "EMP-0101", "end_date": "2026-09-30"})
    assert change == {"field": "end_date", "signed": "2026-09-30", "sent": "2026-10-01"}


def test_an_unreachable_gateway_is_unavailable_not_refused():
    run = {"reachable": False, "url": "http://127.0.0.1:9/mcp", "error": "connection refused",
           "target": "gateway"}
    assert interactive.outcome(run)["status"] == "unavailable"
    assert "127.0.0.1:9" in interactive.outcome(run)["detail"]


ALL_PASSED = {"allowed": True, "layer": None,
              "checks": [{"name": c, "passed": True} for c in CHECK_ORDER]}


def test_a_system_error_after_verification_is_not_a_refusal():
    """Verification passed — the report says so — and the simulator answered 'not enrolled'. That is
    the system's answer, shown as such."""
    run = {"reachable": True, "target": "gateway", "allowed": False, "layer": None,
           "text": "EMP-0999 is not enrolled by employer 00000000", "report": ALL_PASSED}
    assert interactive.outcome(run)["status"] == "allowed"
    assert interactive.server_answer(run) == {
        "ok": False, "body": None, "text": "EMP-0999 is not enrolled by employer 00000000"}


def test_no_report_is_never_allowed():
    """The gateway refused without a report (authorizer down, a generic 403): nothing verified it,
    so the page must not say allowed."""
    run = {"reachable": True, "target": "gateway", "allowed": False, "layer": None,
           "text": "gateway refused the call (HTTP 403)", "report": None}
    out = interactive.outcome(run)
    assert out["status"] == "refused" and "403" in out["detail"]
    assert interactive.server_answer(run) is None


def test_a_report_that_does_not_say_allowed_is_refused():
    report = {"allowed": None, "layer": None,
              "checks": [{"name": c, "passed": None} for c in CHECK_ORDER]}
    assert interactive.outcome({"reachable": True, "target": "policy", "report": report})[
        "status"] == "refused"


def test_a_bad_field_is_named():
    with pytest.raises(interactive.BadRequest) as raised:
        interactive.validate("enroll_employee", {"person_ref": "Alice", "start_date": "2026-09-30",
                                                 "salary_grade": 3}, "none", TOOLS)
    assert raised.value.field == "person_ref"


def test_tampering_the_last_representable_date_does_not_overflow():
    sent, change = interactive.tampered({"person_ref": "EMP-0101", "end_date": "9999-12-31"})
    assert change["sent"] == "9999-12-30"


def test_the_first_failed_check_is_the_refusal():
    report = {"allowed": False, "layer": "digest_mismatch", "checks": [
        {"name": "credential_present", "passed": True},
        {"name": "freshness", "passed": True},
        {"name": "digest", "passed": False, "layer": "digest_mismatch", "detail": "digest differs"},
        {"name": "signature", "passed": None}]}
    out = interactive.outcome({"reachable": True, "target": "policy", "report": report})
    assert out == {"status": "refused", "check": "digest", "layer": "digest_mismatch",
                   "detail": "digest differs"}


def test_every_scenario_names_a_real_check_and_layer():
    layers = {layer.value for layer in FailureLayer}
    ids = [s["id"] for s in interactive.SCENARIOS]
    assert len(ids) == len(set(ids))
    for s in interactive.SCENARIOS:
        expect = s["expect"]
        if expect["status"] == "refused":
            assert expect["check"] in CHECK_ORDER, s["id"]
            assert expect["layer"] in layers, s["id"]
        assert s["variant"] in interactive.VARIANTS


# --------------------------------------------------------------------------------------------- #
# The routes, on the console's in-process KERI world
# --------------------------------------------------------------------------------------------- #

def _load(public: bool = False):
    os.environ["VLEI_CONSOLE_MINTED"] = "1"
    os.environ.pop("VLEI_CONSOLE_TARGET", None)
    os.environ["VLEI_GATEWAY_URL"] = "http://127.0.0.1:9/mcp"
    os.environ["VLEI_SKILL_SERVER_URL"] = "http://127.0.0.1:9/mcp"
    if public:
        os.environ["VLEI_PUBLIC"] = "1"
    else:
        os.environ.pop("VLEI_PUBLIC", None)
    sys.argv = ["console"]
    spec = importlib.util.spec_from_file_location("console_app_interactive", CONSOLE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    os.environ.pop("VLEI_PUBLIC", None)
    return module


@pytest.fixture(scope="module")
def console():
    return _load()


def _client(module) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url="http://page")


async def _scenario(client: httpx.AsyncClient, scenario_id: str) -> dict:
    listing = (await client.get("/api/scenarios")).json()
    s = next(item for item in listing["scenarios"] if item["id"] == scenario_id)
    response = await client.post("/api/call", json={"tool": s["tool"], "arguments": s["arguments"],
                                                    "variant": s["variant"], "scenario": s["id"]})
    assert response.status_code == 200, response.text
    return response.json()


async def test_each_scenario_ends_where_the_page_says(console):
    # One test over every scenario, not a parametrized one: this directory's conftest marks tests
    # async after collection, which drops a parametrize. Every mismatch is listed at once.
    wrong = []
    async with _client(console) as client:
        for s in interactive.SCENARIOS:
            if s["id"] in ("impersonation", "after-revocation"):
                continue
            expect = s["expect"]
            got = (await _scenario(client, s["id"]))["outcome"]
            if got["status"] != expect["status"] or (
                    expect["status"] == "refused"
                    and (got["check"], got["layer"]) != (expect["check"], expect["layer"])):
                wrong.append((s["id"], expect, got))
    assert not wrong, wrong


async def test_a_refusal_stops_the_sequence(console):
    async with _client(console) as client:
        result = await _scenario(client, "tampered")
    states = [c["status"] for c in result["checks"]]
    first = states.index("fail")
    assert states[:first] == ["pass"] * first
    assert set(states[first + 1:]) == {"skipped"}


async def test_the_tampered_call_shows_what_was_signed_and_what_was_sent(console):
    async with _client(console) as client:
        result = await _scenario(client, "tampered")
    assert result["tampered"] == {"field": "salary_grade", "signed": 3, "sent": 9}
    assert result["request"]["params"]["arguments"]["salary_grade"] == 9


async def test_no_credential_sends_no_extension_keys(console):
    async with _client(console) as client:
        result = await _scenario(client, "no-credential")
    assert "_meta" not in result["request"]["params"]


async def test_the_replayed_signature_is_five_minutes_old(console):
    async with _client(console) as client:
        result = await _scenario(client, "replayed")
    signature = next(v for k, v in result["request"]["params"]["_meta"].items()
                     if k.endswith("/signature"))
    signed_at = datetime.fromisoformat(signature["ts"].replace("Z", "+00:00"))
    assert datetime.now(timezone.utc) - signed_at > timedelta(minutes=4)


async def test_the_wrong_key_signs_under_the_agents_own_identifier(console):
    async with _client(console) as client:
        wrong = await _scenario(client, "wrong-key")
        right = await _scenario(client, "enroll-today")
    aid = lambda r: next(v for k, v in r["request"]["params"]["_meta"].items()
                         if k.endswith("/signature"))["aid"]
    assert aid(wrong) == aid(right)


async def test_a_bad_request_is_a_400_and_signs_nothing(console):
    async with _client(console) as client:
        before = len((await client.get("/api/log")).json()["entries"])
        response = await client.post("/api/call", json={
            "tool": "enroll_employee", "variant": "none",
            "arguments": {"person_ref": "EMP-0101", "start_date": "2026-02-30", "salary_grade": 3}})
        after = len((await client.get("/api/log")).json()["entries"])
    assert response.status_code == 400 and "start_date" in response.json()["error"]
    assert after == before


async def test_a_gateway_refusal_without_a_report_is_refused_on_the_page(console, monkeypatch):
    async def refused_without_report(scene, meta, arguments):
        return {"reachable": True, "report": None, "allowed": False, "layer": None,
                "text": "gateway refused the call (HTTP 403)", "url": "http://gateway/mcp"}
    monkeypatch.setattr(console, "_target", lambda scene: "gateway")
    monkeypatch.setattr(console, "_remote", refused_without_report)
    # Fix round 1: _audience() now refuses to sign at all when the gateway's own document cannot
    # be read (AudienceUnavailable, spec §6.1) instead of falling back to signing for this
    # console's own LE. This test is about what happens when the gateway itself refuses without a
    # report — a different thing from the gateway being unreachable (test_scenes.py covers that) —
    # so its identity is established here by a fixed stand-in rather than a real network fetch.
    monkeypatch.setattr(console, "_audience",
                        lambda: console.Audience(console.ENV.world.le.pre, "http://gateway/mcp"))
    async with _client(console) as client:
        result = await _scenario(client, "enroll-today")
        entry = (await client.get("/api/log")).json()["entries"][0]
    assert result["outcome"]["status"] == "refused"
    assert result["server"] is None
    assert entry["status"] == "refused"


async def test_the_audit_log_names_only_an_identity_the_verifier_established(console):
    async with _client(console) as client:
        await _scenario(client, "no-credential")
        stripped = (await client.get("/api/log")).json()["entries"][0]
        await _scenario(client, "enroll-today")
        allowed = (await client.get("/api/log")).json()["entries"][0]
    assert stripped["lei"] is None and stripped["role"] is None
    assert allowed["lei"] and allowed["role"] == "labor-insurance-filing"


async def test_a_bad_request_names_the_field(console):
    async with _client(console) as client:
        response = await client.post("/api/call", json={
            "tool": "enroll_employee", "variant": "none",
            "arguments": {"person_ref": "Alice", "start_date": "2026-09-30", "salary_grade": 3}})
    assert response.status_code == 400 and response.json()["field"] == "person_ref"


async def test_the_audit_log_records_calls_newest_first(console):
    async with _client(console) as client:
        await _scenario(client, "enroll-today")
        await _scenario(client, "salary-by-filer")
        entries = (await client.get("/api/log")).json()["entries"]
    assert entries[0]["scenario"] == "salary-by-filer" and entries[0]["layer"] == "role_mismatch"
    assert entries[1]["scenario"] == "enroll-today" and entries[1]["status"] == "allowed"
    assert entries[0]["lei"] and entries[0]["role"] == "labor-insurance-filing"


async def test_the_impersonation_runs_no_checks(console):
    async with _client(console) as client:
        result = (await client.post("/api/call/impersonation")).json()
    assert result["outcome"]["status"] == "self-asserted"
    assert {c["status"] for c in result["checks"]} == {"skipped"}


async def test_status_names_who_is_calling_and_where_it_is_verified(console):
    async with _client(console) as client:
        status = (await client.get("/api/status")).json()
    assert status["credential"] == "issued"
    assert status["target"] in ("gateway", "policy")
    assert status["identity"]["role"] == "labor-insurance-filing"
    assert status["public"] is False


async def test_revocation_refuses_the_next_call_and_reissue_restores_it():
    module = _load()
    async with _client(module) as client:
        revoked = await client.post("/api/revoke")
        assert revoked.status_code == 200 and revoked.json()["credential"] == "revoked"
        assert revoked.json()["confirmed"] is True
        after = await _scenario(client, "after-revocation")
        assert after["outcome"]["check"] == "revocation"
        assert after["outcome"]["layer"] == "revoked"
        restored = await client.post("/api/reissue")
        assert restored.status_code == 200 and restored.json()["credential"] == "issued"
        again = await _scenario(client, "enroll-today")
        assert again["outcome"]["status"] == "allowed"


async def test_the_public_site_refuses_revocation():
    module = _load(public=True)
    async with _client(module) as client:
        response = await client.post("/api/revoke")
        reissue = await client.post("/api/reissue")
    assert response.status_code == 403 and "presenter" in response.json()["error"]
    assert reissue.status_code == 403


async def test_the_public_site_refuses_the_recording_pages_controls_too():
    """The recording page's routes live on the same app: in public, they must refuse as well."""
    module = _load(public=True)
    async with _client(module) as client:
        codes = [(await client.post(path)).status_code
                 for path in ("/revoke", "/reissue", "/reset", "/scene/1", "/scene/0/mode/observed")]
    assert codes == [403] * 5


async def test_the_page_and_its_assets_are_served(console):
    async with _client(console) as client:
        page = await client.get("/app")
        assets = [await client.get(f"/app/{name}") for name in ("app.css", "app.js", "i18n.json")]
        missing = await client.get("/app/secrets.txt")
        recording = await client.get("/")
    assert page.status_code == 200 and "app.js" in page.text
    assert all(a.status_code == 200 for a in assets)
    assert missing.status_code == 404
    assert recording.status_code == 200 and "console.js" in recording.text


# --------------------------------------------------------------------------------------------- #
# The strings
# --------------------------------------------------------------------------------------------- #

def test_every_string_exists_in_both_languages():
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))
    assert set(strings) == {"zh", "en"}
    assert set(strings["zh"]) == set(strings["en"])
    assert all(isinstance(v, str) and v.strip() for lang in strings.values() for v in lang.values())


def test_a_gateway_that_failed_itself_is_explained_in_both_languages():
    """vlei-authz names ``verifier_error`` where a layer would stand; the evidence panel shows it."""
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))
    assert strings["en"]["layer.short.verifier_error"] == "gateway error, try again"
    assert strings["zh"]["layer.short.verifier_error"] == "閘道內部錯誤，可重試"
    assert strings["en"]["layer.verifier_error"].startswith("Gateway error: the verifier itself failed")
    assert strings["zh"]["layer.verifier_error"].startswith("閘道內部錯誤")


def test_every_check_layer_scenario_tool_and_variant_is_explained():
    strings = json.loads((CONSOLE / "static" / "i18n.json").read_text(encoding="utf-8"))["zh"]
    wanted = [f"check.{c}" for c in CHECK_ORDER] + [f"check.{c}.source" for c in CHECK_ORDER]
    wanted += [f"check.{c}.why" for c in CHECK_ORDER]
    wanted += [f"layer.{layer.value}" for layer in FailureLayer]
    wanted += [f"scenario.{s['id']}.title" for s in interactive.SCENARIOS]
    wanted += [f"scenario.{s['id']}.what" for s in interactive.SCENARIOS]
    wanted += [f"group.{s['group']}" for s in interactive.SCENARIOS]
    wanted += [f"tool.{t}" for t in interactive.TOOL_FIELDS] + ["tool.reserve_gpu_quota"]
    wanted += [f"variant.{v}" for v in interactive.VARIANTS]
    wanted += [f"field.{f}" for fields in interactive.TOOL_FIELDS.values() for f in fields]
    missing = [key for key in wanted if key not in strings]
    assert not missing, missing
