"""The console's scene logic.

This is the thing that will be on a screen in front of GLEIF, AAIF and a room of officials, and it
was the only deliverable without tests. What is checked here is what a viewer sees: that each scene
produces the state the script says it does, that a failure stops the sequence rather than failing
eight times, and that nothing on screen is a credential.

No containers required. The module falls back to a locally minted chain when no environment has
been issued, and verifies it by the same code path.

    pytest examples/console/tests -q
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))


@pytest.fixture(scope="module")
def console():
    """The console backend, imported once."""
    sys.argv = ["console"]
    spec = importlib.util.spec_from_file_location(
        "console_app", ROOT / "examples" / "console" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def scene(console, n: int) -> dict:
    await console.load_scene(n)
    return json.loads(json.dumps(console.STATE))  # the shape the front end actually receives


# --------------------------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------------------------- #

async def test_every_scene_produces_the_full_state(console):
    for n in range(6):
        state = await scene(console, n)
        assert state["scene"] == n
        assert set(state["identities"]) == {"server", "agent"}
        assert state["request"]["mode"] in ("vlei", "plain")
        assert len(state["verification"]["checks"]) == 8
        assert state["verification"]["outcome"]["status"] in (
            "allowed", "refused", "self-asserted"
        )


async def test_check_ids_and_order_are_fixed(console):
    """The right-hand column is read top to bottom while someone narrates it."""
    from mcp_vlei.report import CHECK_ORDER

    state = await scene(console, 1)
    assert [c["id"] for c in state["verification"]["checks"]] == list(CHECK_ORDER)


async def test_state_is_json_serializable(console):
    """It travels over server-sent events; anything unserializable is a blank screen."""
    for n in range(6):
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


async def test_scene_0_measures_rather_than_asserts(console):
    """The number comes from the impersonation server, not from a constant in the console.

    A hardcoded "50 hours" would be the one thing on screen that was written by hand — precisely
    what someone should ask about in questions.
    """
    await scene(console, 0)
    measured = console._impersonation_result

    if not measured.get("live"):
        pytest.skip("impersonation server unavailable; the console says so rather than inventing")
    assert measured["approved"] == console.IMPERSONATION_HOURS
    assert measured["tier"] == "partner"
    assert measured["received"] == console.IMPERSONATION_CLAIM["name"]


async def test_scene_1_carries_the_four_keys(console):
    state = await scene(console, 1)
    body = state["request"]["json"]

    for key in ("credential", "delegatedAid", "signature", "credentialSaid"):
        assert f"org.gleif.vlei/{key}" in body
    assert state["request"]["mode"] == "vlei"


async def test_scene_2_stops_at_the_first_check(console):
    """Not eight failures — one, and then a stopped sequence."""
    state = await scene(console, 2)
    checks = state["verification"]["checks"]

    assert checks[0]["status"] == "fail"
    assert checks[0]["id"] == "credential_present"
    assert all(c["status"] == "skipped" for c in checks[1:])
    assert state["verification"]["outcome"]["layer"] == "missing_credential"


async def test_scene_2_shows_the_agent_as_not_presented(console):
    """Not `revoked`, not `refused`: the client never made a claim."""
    state = await scene(console, 2)
    assert state["identities"]["agent"]["status"] == "unverified"
    assert state["identities"]["server"]["status"] == "valid"


async def test_scene_3_keeps_the_earlier_checks(console):
    """Six things still true, one that stopped being true. That is the narration."""
    state = await scene(console, 3)
    checks = state["verification"]["checks"]

    failed = next(i for i, c in enumerate(checks) if c["status"] == "fail")
    assert checks[failed]["id"] == "revocation"
    assert all(c["status"] == "pass" for c in checks[:failed])
    assert all(c["status"] == "skipped" for c in checks[failed + 1:])
    assert state["verification"]["outcome"]["layer"] == "revoked"
    assert state["identities"]["agent"]["status"] == "revoked"
    assert state["identities"]["agent"].get("revokedAt")


async def test_scene_4_changes_the_server_card(console):
    state = await scene(console, 4)
    assert state["identities"]["server"]["label"] != "association-server"
    assert state["verification"]["outcome"].get("note")


async def test_scene_5_annotates_the_server_card(console):
    state = await scene(console, 5)
    assert state["identities"]["server"].get("note") == "generated from skill"


async def test_leaving_scene_3_clears_the_session_revocation(console):
    """A presenter who jumps back to scene 1 must not carry scene 3's revocation with them.

    What is cleared is the *session's* revocation. If the issuer's log independently says the
    credential is withdrawn, the console keeps reporting that — it reads the log, it does not
    decide. The flag mattering separately is the bug this test found: left set, the readiness
    warning goes quiet for the rest of the session.
    """
    await scene(console, 3)
    assert console.TEL.revoked is True
    assert console._revoked_in_this_session is True

    await scene(console, 1)
    assert console._revoked_in_this_session is False


# --------------------------------------------------------------------------------------------- #
# Honesty
# --------------------------------------------------------------------------------------------- #

async def test_no_credential_content_reaches_the_screen(console):
    """An ECR names a natural person. The cards carry identifiers, never the credential."""
    for n in range(6):
        state = await scene(console, n)
        cards = json.dumps(state["identities"])
        for forbidden in ("personLegalName", "ACDC10JSON", "-----BEGIN"):
            assert forbidden not in cards


async def test_credential_and_signature_are_truncated_in_the_request(console):
    """The middle column is meant to be readable, not a wall of base64."""
    state = await scene(console, 1)
    body = json.loads(state["request"]["json"])
    meta = body["_meta"]

    assert len(meta["org.gleif.vlei/credential"]) < 40
    assert meta["org.gleif.vlei/credential"].endswith("…")
    assert len(meta["org.gleif.vlei/signature"]["sig"]) < 40


async def test_state_reports_what_it_is_running_on(console):
    """Issued or minted, witness or session state. A viewer is entitled to know which."""
    state = await scene(console, 1)
    evidence = state["evidence"]

    assert evidence["credentials"] in ("issued", "minted")
    assert evidence["revocation"] in ("witness", "console")


async def test_a_stale_credential_is_reported_not_hidden(console):
    """If the credential was withdrawn before the session, say so — before a take, not during one."""
    state = await scene(console, 1)

    if state["verification"]["outcome"]["status"] == "refused":
        assert state["readiness"], "a scene that should allow but refuses must explain itself"
        assert "bootstrap-credentials" in state["readiness"]
    else:
        assert state["readiness"] is None
