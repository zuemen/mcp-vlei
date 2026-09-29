"""The console's scene logic.

This is the thing that will be on a screen in front of GLEIF, AAIF and a room of officials. What is
checked here is what a viewer sees: that each scene produces the state the script says it does, that
a failure stops the sequence rather than failing eight times, that nothing on screen is a
credential — and that nothing on screen is decided by the console. A revocation is a revocation in
a transaction event log; a gateway scene is a call through a gateway, or it says the gateway is not
running.

No containers required: the tests run the console on an in-process KERI deployment
(`mcp_vlei.testing.World`) — real key event logs, registries and issuances behind an in-process
witness — by the same code path as a live one.

    pytest examples/console/tests -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))


def _load(target: str | None = None):
    os.environ["VLEI_CONSOLE_MINTED"] = "1"
    if target:
        os.environ["VLEI_CONSOLE_TARGET"] = target
    else:
        os.environ.pop("VLEI_CONSOLE_TARGET", None)
    # Point the remote scenes at ports nothing listens on, so "not running" is what is tested.
    os.environ["VLEI_GATEWAY_URL"] = "http://127.0.0.1:9/mcp"
    os.environ["VLEI_SKILL_SERVER_URL"] = "http://127.0.0.1:9/mcp"
    sys.argv = ["console"]
    spec = importlib.util.spec_from_file_location(
        "console_app", ROOT / "examples" / "console" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def console():
    """The console backend, imported once, for scenes that do not change the world."""
    return _load()


@pytest.fixture
def fresh():
    """A console of its own, for a test that revokes or re-issues."""
    return _load()


@pytest.fixture
def gateway_console():
    """A console told to use the gateway — which, in these tests, is not running."""
    module = _load("gateway")
    os.environ.pop("VLEI_CONSOLE_TARGET", None)
    return module


async def scene(console, n: int) -> dict:
    await console.load_scene(n)
    return json.loads(json.dumps(console.STATE))  # the shape the front end actually receives


# --------------------------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------------------------- #

async def test_every_scene_produces_the_full_state(console):
    for n in console.SCENES:
        state = await scene(console, n)
        assert state["scene"] == n
        assert state["sceneCount"] == len(console.SCENES)
        assert set(state["identities"]) == {"employer", "agent", "server"}
        assert state["request"]["mode"] in ("vlei", "plain")
        assert len(state["verification"]["checks"]) == 8
        assert state["verification"]["outcome"]["status"] in (
            "allowed", "refused", "self-asserted", "unavailable"
        )


async def test_check_ids_and_order_are_fixed(console):
    """The right-hand column is read top to bottom while someone narrates it."""
    from mcp_vlei.report import CHECK_ORDER

    state = await scene(console, 1)
    assert [c["id"] for c in state["verification"]["checks"]] == list(CHECK_ORDER)


async def test_state_is_json_serializable(console):
    """It travels over server-sent events; anything unserializable is a blank screen."""
    for n in console.SCENES:
        json.dumps(await scene(console, n))


# --------------------------------------------------------------------------------------------- #
# What each scene has to show
# --------------------------------------------------------------------------------------------- #

async def test_scene_0_runs_no_checks_and_says_what_it_granted(console):
    """The empty column beside the grey banner is the shot."""
    state = await scene(console, 0)

    assert all(c["status"] == "skipped" for c in state["verification"]["checks"])
    outcome = state["verification"]["outcome"]
    assert outcome["status"] == "self-asserted"
    assert outcome["note"]
    assert state["request"]["mode"] == "plain"
    assert "clientInfo" in state["request"]["json"]
    assert state["banner"] is None


async def test_scene_0_measures_rather_than_asserts(console):
    """The number comes from the impersonation server, not from a constant in the console."""
    await scene(console, 0)
    measured = console._impersonation_result

    if not measured.get("live"):
        pytest.skip("impersonation server unavailable; the console says so rather than inventing")
    assert measured["approved"] == console.IMPERSONATION_HOURS
    assert measured["tier"] == "partner"
    assert measured["received"] == console.IMPERSONATION_CLAIM["name"]


async def test_scene_1_an_enrolment_on_the_start_date_is_allowed(console):
    from datetime import date

    state = await scene(console, 1)

    assert state["request"]["name"] == "enroll_employee"
    assert json.loads(state["request"]["json"])["arguments"]["start_date"] == date.today().isoformat()
    assert state["verification"]["outcome"]["status"] == "allowed"
    assert all(c["status"] == "pass" for c in state["verification"]["checks"])
    assert state["identities"]["agent"]["status"] == "valid"
    assert state["identities"]["employer"]["status"] == "valid"
    assert state["identities"]["server"]["status"] == "simulated"


async def test_scene_1_signs_as_the_agent_under_its_own_key_state(console):
    """The console signs with the agent's key, and the check says the key came from its log."""
    state = await scene(console, 1)
    body = json.loads(state["request"]["json"])

    assert body["_meta"]["org.gleif.vlei/signature"]["aid"] == console.ENV.delegate
    assert body["_meta"]["org.gleif.vlei/delegatedAid"] == console.ENV.delegate
    assert "org.gleif.vlei/verkey" not in body["_meta"]


async def test_scene_1_carries_the_extension_keys(console):
    state = await scene(console, 1)
    body = state["request"]["json"]

    for key in ("credential", "delegatedAid", "signature", "credentialSaid"):
        assert f"org.gleif.vlei/{key}" in body
    assert state["request"]["mode"] == "vlei"


def _stopped_at(state: dict, check_id: str, layer: str) -> None:
    checks = state["verification"]["checks"]
    failed = next(i for i, c in enumerate(checks) if c["status"] == "fail")
    assert checks[failed]["id"] == check_id
    assert all(c["status"] == "pass" for c in checks[:failed])
    assert all(c["status"] == "skipped" for c in checks[failed + 1:])
    assert state["verification"]["outcome"]["layer"] == layer


async def test_scene_2_the_filing_agent_cannot_adjust_salaries(console):
    """Seven checks pass — a genuine agent of a genuine employer; the role is not this one."""
    state = await scene(console, 2)

    assert state["request"]["name"] == "adjust_insured_salary"
    _stopped_at(state, "authority", "role_mismatch")
    assert "labor-insurance-payroll" in state["verification"]["outcome"]["note"]


async def test_scene_3_filing_fifteen_days_ahead_is_refused(console):
    """Filing ahead is allowed within ten days of the start date, not fifteen — from the report."""
    from datetime import date, timedelta

    state = await scene(console, 3)
    arguments = json.loads(state["request"]["json"])["arguments"]

    assert arguments["start_date"] == (date.today() + timedelta(days=15)).isoformat()
    _stopped_at(state, "authority", "scope_exceeded")
    assert "start_date" in state["verification"]["outcome"]["note"]


# --------------------------------------------------------------------------------------------- #
# The revocation scene: a revocation that happens, not one that is drawn
# --------------------------------------------------------------------------------------------- #

async def test_the_revocation_scene_before_revocation_is_a_valid_call(fresh):
    """Loading the scene does not revoke anything. The presenter does, on camera."""
    state = await scene(fresh, fresh.REVOCATION_SCENE)

    assert state["verification"]["outcome"]["status"] == "allowed"
    assert state["identities"]["agent"]["status"] == "valid"


async def test_revoking_is_read_back_from_the_log(fresh):
    """Six things still true, one that stopped being true — established from the issuer's log."""
    await scene(fresh, fresh.REVOCATION_SCENE)
    await fresh.revoke()
    state = json.loads(json.dumps(fresh.STATE))

    _stopped_at(state, "revocation", "revoked")
    assert state["identities"]["agent"]["status"] == "revoked"
    assert state["identities"]["agent"].get("revokedAt")

    # The log is the authority, not the console: the withdrawal is a `rev` event there.
    tel = fresh.ENV.world.le_registry.tels[fresh.ENV.said]
    assert [e.body["t"] for e in tel] == ["iss", "rev"]


async def test_a_revocation_stays_revoked_until_a_new_credential_is_issued(fresh):
    """Leaving the scene does not undo anything. The next take is refused, and says what to do."""
    await scene(fresh, fresh.REVOCATION_SCENE)
    await fresh.revoke()

    state = await scene(fresh, 1)
    assert state["verification"]["outcome"]["layer"] == "revoked"
    assert "press I" in state["readiness"]

    await fresh.reissue()
    state = await scene(fresh, 1)
    assert state["verification"]["outcome"]["status"] == "allowed"
    assert state["readiness"] is None


# --------------------------------------------------------------------------------------------- #
# The labour-insurance scenes: a simulation, said so; the gateway, or an honest "not running"
# --------------------------------------------------------------------------------------------- #

async def test_every_labour_scene_says_it_is_simulated(console):
    for n in console.SCENES:
        if n == 0:
            continue
        state = await scene(console, n)
        assert state["banner"] == "Simulated — not connected to the Bureau of Labor Insurance"
        assert state["identities"]["server"]["note"] == state["banner"]


async def test_the_employer_card_links_the_unified_business_number_to_the_lei(console):
    card = (await scene(console, 1))["identities"]["employer"]

    assert card["type"] == "LE" and card["lei"] == console.ENV.lei
    assert card["label"] == "統一編號 00000000 (test value)"
    assert "registeredAs" in card["note"]


async def test_no_country_or_address_reaches_the_screen(console):
    """GLEIF's records carry a country and addresses; none of it belongs on this screen."""
    for n in console.SCENES:
        text = json.dumps(await scene(console, n), ensure_ascii=False).lower()
        for forbidden in ("country", "address", "province", "jurisdiction"):
            assert forbidden not in text, (n, forbidden)


async def test_a_minted_world_verifies_in_process_and_says_so(console):
    state = await scene(console, 1)
    assert state["request"]["target"] == "policy"
    assert "minted world" in state["verification"]["outcome"]["note"]


async def test_dates_are_counted_in_the_policy_offset_like_the_gateway():
    """The gateway counts days at +08:00; a console that stamped its own local date would be a day
    off whenever the two dates differ. One of +14:00 and -12:00 differs from any local date."""
    from datetime import date, datetime, timedelta, timezone

    text, hours = next((t, h) for t, h in (("+14:00", 14), ("-12:00", -12))
                       if datetime.now(timezone(timedelta(hours=h))).date() != date.today())
    os.environ["VLEI_POLICY_UTC_OFFSET"] = text
    try:
        module = _load()
    finally:
        os.environ.pop("VLEI_POLICY_UTC_OFFSET", None)
    state = await scene(module, 1)
    start = json.loads(state["request"]["json"])["arguments"]["start_date"]

    assert start == datetime.now(timezone(timedelta(hours=hours))).date().isoformat()
    assert state["verification"]["outcome"]["status"] == "allowed"


def test_issued_credentials_verified_in_process_are_not_called_a_minted_world(console, monkeypatch):
    """VLEI_CONSOLE_TARGET=policy with issued credentials: in process, and said so — not 'minted'."""
    monkeypatch.setattr(console.ENV, "live", True)
    monkeypatch.setattr(console, "LABOUR_TARGET", "policy")
    run = {"reachable": True, "allowed": True, "report": {"checks": []}}

    note = console._outcome(run, console.SCENES[1])["note"]
    assert "minted" not in note
    assert "not through the gateway" in note


async def test_the_gateway_scenes_go_to_the_gateway_or_say_it_is_not_running(gateway_console):
    state = await scene(gateway_console, 1)
    outcome = state["verification"]["outcome"]

    assert state["request"]["target"] == "gateway"
    assert outcome["status"] == "unavailable"
    assert "127.0.0.1:9" in outcome["note"]
    assert not any(c["status"] == "pass" for c in state["verification"]["checks"])


# --------------------------------------------------------------------------------------------- #
# Honesty
# --------------------------------------------------------------------------------------------- #

async def test_no_credential_content_reaches_the_screen(console):
    """An ECR names a natural person. The cards carry identifiers, never the credential."""
    for n in console.SCENES:
        state = await scene(console, n)
        cards = json.dumps(state["identities"])
        for forbidden in ("personLegalName", "ACDC10JSON", "-----BEGIN"):
            assert forbidden not in cards


async def test_credential_and_signature_are_truncated_in_the_request(console):
    """The middle column is meant to be readable, not a wall of base64."""
    state = await scene(console, 1)
    meta = json.loads(state["request"]["json"])["_meta"]

    assert len(meta["org.gleif.vlei/credential"]) < 40
    assert meta["org.gleif.vlei/credential"].endswith("…")
    assert len(meta["org.gleif.vlei/signature"]["sig"]) < 40


async def test_state_reports_what_it_is_running_on(console):
    """Issued or minted, where the key is, where revocation is read. A viewer is entitled to know."""
    evidence = (await scene(console, 1))["evidence"]

    assert evidence["credentials"] == "minted"
    assert evidence["revocation"] == "in-process witness"
    assert evidence["signing"] == "in-process key"


# --------------------------------------------------------------------------------------------- #
# Scene 0, observed mode: the observatory's records, never a constant
# --------------------------------------------------------------------------------------------- #

def _observatory_records(log_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "examples" / "observatory"))
    from observations import ObservationLog, transport_records

    log = ObservationLog(log_path)
    init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "Claude", "version": "1.2.3"}}}).encode()
    for headers in ({"user-agent": "real-ua"},
                    {"user-agent": "python-httpx2", "x-observatory-run": "replay"}):
        for record in transport_records(init, headers):
            log.append(record)


async def test_scene_0_observed_mode_reads_the_observatory(fresh, tmp_path):
    fresh.OBSERVATORY_URL = None
    fresh.OBSERVATORY_LOG = tmp_path / "observations.jsonl"
    _observatory_records(fresh.OBSERVATORY_LOG)

    fresh.STATE["sceneMode"] = "observed"
    state = await scene(fresh, 0)
    observed = state["observed"]
    assert observed["available"] is True
    rows = {r["key"]: r for r in observed["rows"]}
    assert rows["clientInfo"]["verdict"] == "same"
    assert rows["userAgent"]["verdict"] == "different"      # shown, not hidden
    assert rows["userAgent"]["real"] == "real-ua"
    # The measured scene's grant must not stay on screen beside the observatory's records.
    outcome = state["verification"]["outcome"]
    assert outcome["headline"] == "INDISTINGUISHABLE"
    assert "hours" not in outcome["note"]
    assert state["request"]["name"] == "echo_identity"


async def test_scene_0_observed_mode_with_nothing_recorded_says_so(fresh, tmp_path):
    fresh.OBSERVATORY_URL = None
    fresh.OBSERVATORY_LOG = tmp_path / "empty.jsonl"
    fresh.STATE["sceneMode"] = "observed"
    state = await scene(fresh, 0)
    assert state["observed"]["available"] is False
    assert state["observed"]["reason"].startswith("no real client recorded yet")
    assert "rows" not in state["observed"]
    assert state["verification"]["outcome"]["status"] == "unavailable"


async def test_leaving_scene_0_leaves_observed_mode(fresh, tmp_path):
    fresh.OBSERVATORY_LOG = tmp_path / "empty.jsonl"
    fresh.STATE["sceneMode"] = "observed"
    await scene(fresh, 0)
    state = await scene(fresh, 1)
    assert state["sceneMode"] == "measured" and state["observed"] is None


async def test_the_revocation_on_camera_carries_no_operator_hint(fresh):
    """The refusal right after REVOKE is the scene's point. The reminder to re-issue belongs to the
    next time a scene is loaded — before the next take — not to the frame the audience watches."""
    await scene(fresh, fresh.REVOCATION_SCENE)
    await fresh.revoke()
    assert fresh.STATE["verification"]["outcome"]["layer"] == "revoked"
    assert fresh.STATE["readiness"] is None

    state = await scene(fresh, fresh.REVOCATION_SCENE)
    assert "press I" in state["readiness"]
