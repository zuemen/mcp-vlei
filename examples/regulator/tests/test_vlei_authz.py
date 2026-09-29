"""vlei-authz, called the way agentgateway calls it: the JSON-RPC body in, 200 or 403 out.

Every refusal is asserted on its named layer, and every allowance on the headers the backend will
receive — those two are the service's whole contract with the gateway.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from conftest import ARGS, authz, authz_app, rpc, signed_meta, signer_for

from mcp_vlei.testing import LEI, Controller, World

IDENTITY = ("x-vlei-lei", "x-vlei-role", "x-vlei-holder-aid", "x-vlei-delegate-aid", "x-vlei-report")


async def ask(app, body: bytes, method: str = "POST") -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://vlei-authz"
    ) as client:
        return await client.request(method, "/auth/mcp", content=body)


def decode(value: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def refused(response: httpx.Response, layer: str | None) -> dict:
    assert response.status_code == 403, response.text
    body = response.json()
    assert set(body) == {"layer", "message", "report"}
    assert body["layer"] == layer, body
    if layer:
        assert response.headers["x-vlei-failure"] == layer
    return body


# ------------------------------------------------------------------------------------------- #
# Allowed
# ------------------------------------------------------------------------------------------- #

async def test_a_delegated_agent_is_allowed_and_the_facts_become_headers(world, tmp_path):
    app = authz_app(world, tmp_path)
    response = await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))

    assert response.status_code == 200, response.text
    assert response.headers["x-vlei-lei"] == LEI
    assert response.headers["x-vlei-role"] == "labor-insurance-filing"
    assert response.headers["x-vlei-holder-aid"] == world.holder.pre
    assert response.headers["x-vlei-delegate-aid"] == world.agent.pre

    report = decode(response.headers["x-vlei-report"])
    assert report["allowed"] is True and report["layer"] is None
    assert [c["passed"] for c in report["checks"]] == [True] * 8
    assert report["identity"]["credentialSaid"] == world.ecr_credential.said
    signature = next(c for c in report["checks"] if c["name"] == "signature")
    assert "key event log" in signature["detail"]

    decision = app.state.audit.records[-1]
    assert decision["decision"] == "allow" and decision["delegateAid"] == world.agent.pre
    assert (tmp_path / "audit" / "decisions.jsonl").read_text(encoding="utf-8").count("\n") == 1


async def test_the_holder_signing_directly_is_allowed_with_no_delegate(world, tmp_path):
    meta = signed_meta(world, signer=signer_for(world.holder), delegated=None)
    response = await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta))

    assert response.status_code == 200, response.text
    assert response.headers["x-vlei-holder-aid"] == world.holder.pre
    # Present and empty: the authorizer overwrites whatever a client sent under this name.
    assert response.headers["x-vlei-delegate-aid"] == ""


async def test_calls_that_assert_nothing_pass_with_empty_identity_headers(world, tmp_path):
    app = authz_app(world, tmp_path)
    initialize = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    for body, method in ((initialize.encode(), "POST"), (b"", "GET"), (b"", "DELETE")):
        response = await ask(app, body, method)
        assert response.status_code == 200
        assert all(response.headers[name] == "" for name in IDENTITY)

    # No tool of the labour-insurance simulator is public: every tools/call must be verified.
    listed = await ask(app, rpc("list_insured", {}))
    assert listed.status_code == 403


# ------------------------------------------------------------------------------------------- #
# Refused — who is calling
# ------------------------------------------------------------------------------------------- #

async def test_someone_elses_credential_with_your_own_key_is_refused(world, tmp_path):
    """The attack the P0 fix closed: present an ECR you were shown, sign with your own key."""
    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    meta = signed_meta(world, signer=signer_for(mallory), delegated=None)
    body = refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
                   "invalid_signature")

    assert mallory.pre in body["message"]
    assert body["report"]["checks"][4]["name"] == "delegation"
    assert body["report"]["checks"][4]["passed"] is False


async def test_claiming_to_be_the_delegate_without_its_key_is_refused(world, tmp_path):
    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    meta = signed_meta(world, signer=signer_for(mallory))  # delegatedAid still names the agent
    refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
            "invalid_signature")


async def test_an_unreachable_witness_refuses_rather_than_allows(world, tmp_path):
    """What the live stack shows while the witness is down: named, and never an allow."""

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    body = refused(
        await ask(authz_app(world, tmp_path, client=client), rpc("enroll_employee", ARGS, signed_meta(world))),
        "invalid_signature",
    )
    assert "not established" in body["message"]


async def test_missing_credential_is_refused(world, tmp_path):
    refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS)), "missing_credential")


# ------------------------------------------------------------------------------------------- #
# Refused — what was presented
# ------------------------------------------------------------------------------------------- #

async def test_a_revoked_credential_is_refused(world, tmp_path):
    world.le_registry.revoke(world.ecr_credential.said)
    body = refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, signed_meta(world))),
                   "revoked")
    assert body["report"]["checks"][5]["passed"] is True  # the chain was fine; the TEL was not


async def test_a_revoked_link_above_the_ecr_is_refused(world, tmp_path):
    world.qvi_registry.revoke(world.le_credential.said)
    refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, signed_meta(world))),
            "revoked")


async def test_a_role_the_tool_does_not_accept_is_refused(tmp_path):
    other = World(role="member-registration", label="association")
    refused(await ask(authz_app(other, tmp_path), rpc("enroll_employee", ARGS, signed_meta(other))),
            "role_mismatch")


# ------------------------------------------------------------------------------------------- #
# Refused — the request itself
# ------------------------------------------------------------------------------------------- #

async def test_tampered_arguments_are_refused(world, tmp_path):
    """Sign one enrolment, send another — the gap the digest closes."""
    meta = signed_meta(world)
    tampered = {**ARGS, "person_ref": "EMP-0002"}
    refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", tampered, meta)),
            "digest_mismatch")


async def test_a_signature_for_another_tool_is_refused(world, tmp_path):
    meta = signed_meta(world, tool="withdraw_employee", arguments=ARGS)
    refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
            "digest_mismatch")


async def test_a_replayed_call_is_refused(world, tmp_path):
    app = authz_app(world, tmp_path)
    body = rpc("enroll_employee", ARGS, signed_meta(world))
    assert (await ask(app, body)).status_code == 200

    replay = await ask(app, body)
    assert replay.status_code == 403
    assert replay.json()["layer"] in ("stale_signature", "invalid_signature")


# ------------------------------------------------------------------------------------------- #
# Refused — not a verification question at all
# ------------------------------------------------------------------------------------------- #

async def test_a_tool_outside_the_policy_is_refused_not_waved_through(world, tmp_path):
    body = refused(await ask(authz_app(world, tmp_path), rpc("delete_all_records", {})), None)
    assert "closed" in body["message"] and body["report"] is None


UNREADABLE = {
    "not-json": b"{not json",
    "not-an-object": b'"a string"',
    "batch-with-tools-call": json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_insured"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "enroll_employee"}},
    ]).encode(),
    "tools-call-without-a-name": json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}
    ).encode(),
}


async def test_bodies_it_cannot_read_are_refused(world, tmp_path):
    """Fail closed: a POST the authorizer cannot read is not one the backend should execute."""
    app = authz_app(world, tmp_path)
    for label, payload in UNREADABLE.items():
        response = await ask(app, payload)
        assert response.status_code == 403, label
        assert response.json()["layer"] is None, label


# ------------------------------------------------------------------------------------------- #
# Configuration
# ------------------------------------------------------------------------------------------- #

def test_configuration_is_read_from_the_environment(tmp_path):
    settings = authz.Settings.from_env(
        {
            "VLEI_LE_CREDENTIAL": str(tmp_path / "le.cesr"),
            "VLEI_ACCEPTED_ROOTS": " Eroot1 , Eroot2 ",
            "VLEI_WITNESS_URL": "http://host.docker.internal:5642",
        }
    )
    assert settings.accepted_roots == ["Eroot1", "Eroot2"]
    assert settings.witness_url == "http://host.docker.internal:5642"
    assert settings.revocation_source == "tel"
    assert settings.audit_log is None
    assert settings.witness_timeout == 3.0
    assert authz.Settings.from_env({"VLEI_WITNESS_TIMEOUT": "1.5"}).witness_timeout == 1.5
    assert authz.Settings.from_env({}).witness_url == authz.DEFAULT_WITNESS_URL


def test_the_policy_reads_dates_in_the_configured_offset():
    """"Today" is the filing office's date, not the container's: a gateway in UTC would move the
    window by a day for eight hours of every Taiwanese morning."""
    from datetime import date, datetime, timedelta, timezone

    for offset, hours in (("+08:00", 8), ("-05:30", -5.5), ("+00:00", 0)):
        settings = authz.Settings.from_env({"VLEI_POLICY_UTC_OFFSET": offset})
        expected = datetime.now(timezone(timedelta(hours=hours))).date()
        assert settings.today() == expected
    assert authz.Settings.from_env({}).today() == date.today()
    for bad in ("+8", "UTC+8", "+25:00", "+14:30", "+٠٨:00"):
        with pytest.raises(RuntimeError, match="VLEI_POLICY_UTC_OFFSET"):
            authz.Settings.from_env({"VLEI_POLICY_UTC_OFFSET": bad})


def test_a_policy_with_a_malformed_argument_rule_does_not_load(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"enroll_employee": {
        "credential": "ECR", "arguments": {"start_date": {"dateWithinDays": [0, "10"]}}}}))
    with pytest.raises(RuntimeError, match="enroll_employee"):
        authz.load_policy(policy)


def test_the_deployed_gateway_reads_dates_in_taiwan():
    compose = (authz.HERE.parents[2] / "deploy" / "agentgateway" / "docker-compose.yml").read_text(
        encoding="utf-8")
    assert "VLEI_POLICY_UTC_OFFSET=${VLEI_POLICY_UTC_OFFSET:-+08:00}" in compose


def test_missing_roots_or_credential_is_a_startup_error(tmp_path):
    with pytest.raises(RuntimeError, match="VLEI_ACCEPTED_ROOTS"):
        authz.Settings.from_env({"VLEI_LE_CREDENTIAL": str(tmp_path / "x")}).identity()
    with pytest.raises(RuntimeError, match="does not exist"):
        authz.Settings.from_env(
            {"VLEI_LE_CREDENTIAL": str(tmp_path / "x"), "VLEI_ACCEPTED_ROOTS": "E1"}
        ).identity()


def test_the_policy_covers_every_simulator_tool():
    """A tool added to the server without a policy entry would be refused — make that visible."""
    import asyncio

    from conftest import labor

    policy = authz.load_policy(authz.HERE / "policy.json")
    served = {tool.name for tool in asyncio.run(labor.mcp.list_tools())}
    assert served == set(policy)
    assert all(policy[name] for name in policy), "no tool of the simulator is public"
    assert policy["enroll_employee"]["role"] == "labor-insurance-filing"
    assert policy["adjust_insured_salary"]["role"] == "labor-insurance-payroll"
    assert policy["enroll_employee"]["arguments"] == {"start_date": {"dateWithinDays": [0, 10]}}


def test_the_service_contains_no_verification_logic_of_its_own():
    source = (authz.HERE / "service.py").read_text(encoding="utf-8")
    for needle in ("verify_request", "cesr_decode", "Ed25519", "walk_chain", "TelRevocationChecker",
                   "x-vlei-verkey", "VleiVerifier("):
        assert needle not in source, needle
    assert ".verify_call(" in source


async def test_every_decision_record_says_whether_revocation_was_checked(world, tmp_path):
    """A gateway run with revocation off must be distinguishable, decision by decision."""
    app = authz_app(world, tmp_path)
    await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))
    assert app.state.audit.records[-1]["revocationChecked"] is True

    world.le_registry.revoke(world.ecr_credential.said)
    await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))
    assert app.state.audit.records[-1]["decision"] == "deny"
    assert app.state.audit.records[-1]["revocationChecked"] is True  # read, and found withdrawn

    await ask(app, rpc("enroll_employee", {**ARGS, "person_ref": "EMP-0009"}, {**signed_meta(world), "org.gleif.vlei/signature": {}}))
    assert app.state.audit.records[-1]["decision"] == "deny"
    assert app.state.audit.records[-1]["revocationChecked"] is False  # never reached


# ------------------------------------------------------------------------------------------- #
# The labour-insurance scenes: what the gateway refuses, and why
# ------------------------------------------------------------------------------------------- #

async def test_the_filing_agent_cannot_adjust_insured_salaries(world, tmp_path):
    """Scene 2: the same agent, a tool that needs the payroll role."""
    args = {"person_ref": "EMP-0001", "salary_grade": 5}
    body = refused(await ask(authz_app(world, tmp_path),
                             rpc("adjust_insured_salary", args,
                                 signed_meta(world, "adjust_insured_salary", args))),
                   "role_mismatch")
    assert "labor-insurance-payroll" in body["message"]


async def test_an_enrolment_filed_more_than_ten_days_ahead_is_refused(world, tmp_path):
    """Scene 3: filing ahead is allowed within ten days of the start date, not fifteen."""
    from datetime import date, timedelta

    args = {**ARGS, "person_ref": "EMP-0002",
            "start_date": (date.today() + timedelta(days=15)).isoformat()}
    body = refused(await ask(authz_app(world, tmp_path),
                             rpc("enroll_employee", args, signed_meta(world, "enroll_employee", args))),
                   "scope_exceeded")
    assert "start_date" in body["message"]
    authority = next(c for c in body["report"]["checks"] if c["name"] == "authority")
    assert authority["passed"] is False and authority["layer"] == "scope_exceeded"
