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


def _load():
    os.environ["VLEI_CONSOLE_MINTED"] = "1"
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
            "allowed", "refused", "self-asserted", "unavailable"
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
    """The number comes from the impersonation server, not from a constant in the console."""
    await scene(console, 0)
    measured = console._impersonation_result

    if not measured.get("live"):
        pytest.skip("impersonation server unavailable; the console says so rather than inventing")
    assert measured["approved"] == console.IMPERSONATION_HOURS
    assert measured["tier"] == "partner"
    assert measured["received"] == console.IMPERSONATION_CLAIM["name"]


async def test_scene_1_is_allowed_and_every_check_passed(console):
    state = await scene(console, 1)

    assert state["verification"]["outcome"]["status"] == "allowed"
    assert all(c["status"] == "pass" for c in state["verification"]["checks"])
    assert state["identities"]["agent"]["status"] == "valid"
    assert state["identities"]["server"]["status"] == "valid"


async def test_scene_1_signs_as_the_agent_under_its_own_key_state(console):
    """The console signs with the agent's key, and the check says the key came from its log.

    It used to sign with a random key, which only verified because the server took the key from
    the request. That the scene now passes is itself the evidence that it no longer does.
    """
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


# --------------------------------------------------------------------------------------------- #
# Scene 3: a revocation that happens, not one that is drawn
# --------------------------------------------------------------------------------------------- #

async def test_scene_3_before_revocation_is_a_valid_call(fresh):
    """Loading scene 3 does not revoke anything. The presenter does, on camera."""
    state = await scene(fresh, 3)

    assert state["verification"]["outcome"]["status"] == "allowed"
    assert state["identities"]["agent"]["status"] == "valid"


async def test_revoking_is_read_back_from_the_log(fresh):
    """Six things still true, one that stopped being true — established from the issuer's log."""
    await scene(fresh, 3)
    await fresh.revoke()
    state = json.loads(json.dumps(fresh.STATE))
    checks = state["verification"]["checks"]

    failed = next(i for i, c in enumerate(checks) if c["status"] == "fail")
    assert checks[failed]["id"] == "revocation"
    assert all(c["status"] == "pass" for c in checks[:failed])
    assert all(c["status"] == "skipped" for c in checks[failed + 1:])
    assert state["verification"]["outcome"]["layer"] == "revoked"
    assert state["identities"]["agent"]["status"] == "revoked"
    assert state["identities"]["agent"].get("revokedAt")

    # The log is the authority, not the console: the withdrawal is a `rev` event there.
    tel = fresh.ENV.world.le_registry.tels[fresh.ENV.said]
    assert [e.body["t"] for e in tel] == ["iss", "rev"]


async def test_a_revocation_stays_revoked_until_a_new_credential_is_issued(fresh):
    """Leaving scene 3 does not undo anything. The next scene is refused, and says what to do."""
    await scene(fresh, 3)
    await fresh.revoke()

    state = await scene(fresh, 1)
    assert state["verification"]["outcome"]["layer"] == "revoked"
    assert "press I" in state["readiness"]

    await fresh.reissue()
    state = await scene(fresh, 1)
    assert state["verification"]["outcome"]["status"] == "allowed"
    assert state["readiness"] is None


# --------------------------------------------------------------------------------------------- #
# Scenes 4 and 5: real servers, or an honest "not running"
# --------------------------------------------------------------------------------------------- #

async def test_scene_4_goes_to_the_gateway_or_says_it_is_not_running(console):
    state = await scene(console, 4)
    outcome = state["verification"]["outcome"]

    assert state["identities"]["server"]["label"] == "regulator-gateway"
    assert state["request"]["target"] == "gateway"
    assert outcome["status"] == "unavailable"
    assert "127.0.0.1:9" in outcome["note"]
    assert not any(c["status"] == "pass" for c in state["verification"]["checks"])


async def test_scene_5_goes_to_the_skill_server_or_says_it_is_not_running(console):
    state = await scene(console, 5)

    assert state["identities"]["server"].get("note") == "generated from skill"
    assert state["request"]["target"] == "skill-server"
    assert state["verification"]["outcome"]["status"] == "unavailable"
    assert not any(c["status"] == "pass" for c in state["verification"]["checks"])


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
