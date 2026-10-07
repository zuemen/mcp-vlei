"""Server-side enforcement: every scenario from the task acceptance list, and every attack on it.

Each asserts on the **named failure layer**, not on "it was refused". The layer is what the skill
keys its recovery off and what the demo narrates, so a test that only checked for refusal would
pass while the deliverable was broken.

Nothing here is stubbed except the network. The credentials are issued through real registries,
every identifier has a real key event log, and a witness serves those logs over an
``httpx.MockTransport`` — so the package's own KEL, TEL and HTTP code is what runs. See ``keri.py``.

The attacks section is the reason this file was rewritten. Before it, the key a request was verified
under came from the request itself, and a caller that sent no key skipped the check altogether: any
credential anyone had ever been shown could be presented as theirs. Each of those tests fails
against that code.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from conftest import Ctx, StubVerifier, make_params, name_leaked  # noqa: E402
from mcp_vlei.testing import ECR_SCHEMA, LEI, Controller, World
from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.audience import Audience
from mcp_vlei.extension import META_CREDENTIAL, META_DELEGATED_AID, META_SIGNATURE
from mcp_vlei.replay import MemoryReplayStore, SqliteReplayStore
from mcp_vlei.signing import sign_request

REQUIRES_REGISTRATION = {"credential": "ECR", "role": "member-registration"}
REQUIRES_FILING = {
    "credential": "ECR",
    "role": "regulatory-filing",
    "scope": {"maxAmount": 1_000_000},
}
ARGS = {"name": "A", "email": "a@example.org"}
#: Where the server under test is reached; every call here is signed for it unless a test says not.
AUDIENCE_URL = "http://server.test/mcp"
#: A replay store whose memory began before any test signs: restarts are tested where they matter.
LONG_AGO = datetime(2026, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------------------------- #

@pytest.fixture
def world() -> World:
    return World()


def build(
    world: World,
    tmp_path: Path,
    requirements: dict | None = None,
    *,
    roots: list[str] | None = None,
    client: httpx.AsyncClient | None = None,
    **kwargs,
) -> VleiIdentity:
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    records: list[dict] = []
    kwargs.setdefault("revocation_source", "tel")
    kwargs.setdefault("audience_urls", [AUDIENCE_URL])
    kwargs.setdefault("replay_store", MemoryReplayStore(memory_since=LONG_AGO))
    ext = VleiIdentity(
        le_credential=le,
        accepted_roots=roots or [world.root.pre],
        witness_url="http://witness",
        witness_client=client or world.witness_client(),
        requirements=requirements,
        on_decision=records.append,
        **kwargs,
    )
    ext.records = records  # type: ignore[attr-defined]
    return ext


def signer_for(controller: Controller) -> Signer:
    return Signer.from_seed(controller.pre, controller.seed)


def present(
    world: World,
    tool: str,
    arguments: dict,
    *,
    signer: Signer | None = None,
    stream: str | None = None,
    said: str | None = None,
    delegated: str | None = "agent",
    ts: str | None = None,
    exp: str | None = None,
    audience: Audience | None = None,
    **extra,
):
    """Sign and present — by default, the agent presenting its holder's ECR to the server under
    test. ``said=""`` leaves ``credentialSaid`` out of ``_meta`` (the signature still names one)."""
    signer = signer or signer_for(world.agent)
    unsigned = make_params(tool, arguments)
    meta = {
        META_CREDENTIAL: stream if stream is not None else world.ecr_stream,
        META_SIGNATURE: sign_request(
            signer, "tools/call", unsigned.model_dump(by_alias=True, exclude_none=True),
            audience=audience or Audience(world.le.pre, AUDIENCE_URL),
            credential_said=said or world.ecr_credential.said, ts=ts, exp=exp,
        ),
        "org.gleif.vlei/verkey": signer.verkey,
    }
    if said != "":
        meta["org.gleif.vlei/credentialSaid"] = said or world.ecr_credential.said
    if delegated == "agent":
        meta[META_DELEGATED_AID] = world.agent.pre
    elif delegated:
        meta[META_DELEGATED_AID] = delegated
    meta.update(extra)
    return make_params(tool, arguments, meta)


async def call_next(ctx):
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(content=[TextContent(type="text", text="TOOL RAN")], is_error=False)


def layer_of(result) -> str:
    return result.content[0].text.split(":", 1)[0]


def text_of(result) -> str:
    return result.content[0].text


def check(result, name: str) -> dict:
    report = result.meta["org.gleif.vlei/report"]
    return next(c for c in report["checks"] if c["name"] == name)


# --------------------------------------------------------------------------------------------- #
# 1. Allowed
# --------------------------------------------------------------------------------------------- #

async def test_an_agent_the_holder_delegated_to_is_allowed(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert text_of(result) == "TOOL RAN"
    record = ext.records[-1]
    assert record["allowed"] is True
    assert record["lei"] == LEI
    assert record["holderAid"] == world.holder.pre
    assert record["delegateAid"] == world.agent.pre
    assert world.agent.pre in ext.last_report.as_dict()["checks"][4]["detail"]


async def test_the_holder_signing_directly_is_allowed(world, tmp_path):
    """`delegatedAid` is optional: a deployment without delegation signs with the holder's AID."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS, signer=signer_for(world.holder), delegated=None)
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert text_of(result) == "TOOL RAN"


async def test_a_call_that_names_no_credential_is_missing_credential(world, tmp_path):
    """v0.3: the signature speaks for one named credential; v0.2 fell back to the chain's leaf."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, said=""), Ctx(), call_next
    )

    assert layer_of(result) == "missing_credential"
    assert "credentialSaid" in text_of(result)


# --------------------------------------------------------------------------------------------- #
# 2. Nothing presented
# --------------------------------------------------------------------------------------------- #

async def test_missing_credential_is_refused(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(make_params("register_member", {}), Ctx(), call_next)

    assert layer_of(result) == "missing_credential"
    assert ext.records[-1]["identity"] == "unverified"


async def test_public_tool_needs_nothing(world, tmp_path):
    """Additive: a tool that declares no requirement is unaffected by the extension."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(make_params("list_events", {}), Ctx(), call_next)

    assert text_of(result) == "TOOL RAN"
    assert ext.records[-1]["note"] == "public tool"


# --------------------------------------------------------------------------------------------- #
# 3. Attacks on who is calling
# --------------------------------------------------------------------------------------------- #

async def test_someone_elses_credential_with_your_own_key_is_refused(world, tmp_path):
    """The attack that used to work: present an ECR you were shown, sign with your own key.

    Every server a holder ever called has their credential; it is sent with every request. What
    makes it theirs is that the request is signed under their key state — or their delegate's.
    """
    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS, signer=signer_for(mallory), delegated=None)
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert "TOOL RAN" not in text_of(result)


async def test_the_key_a_caller_supplies_is_not_the_key_that_counts(world, tmp_path):
    """Claim the agent's AID, sign with your own key, and send that key along as `verkey`."""
    mallory_key = Signer.from_seed(world.agent.pre, Controller("mallory").seed)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS, signer=mallory_key)
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"


async def test_a_request_without_a_verifiable_signature_is_refused(world, tmp_path):
    """No key, a signature object that is not one — refused, not waved through as 'skipped'."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = make_params(
        "register_member",
        ARGS,
        {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1},
         "org.gleif.vlei/credentialSaid": world.ecr_credential.said},
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"


async def test_a_delegate_of_someone_else_is_refused(world, tmp_path):
    """A genuine delegated AID — delegated by the wrong person."""
    mallory = Controller("mallory", witnesses=world.witnesses, toad=2)
    rogue = world.enrol(
        Controller("rogue-agent", delegator=mallory, witnesses=world.witnesses, toad=2)
    )
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(
        world, "register_member", ARGS, signer=signer_for(rogue), delegated=rogue.pre
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert "delegat" in text_of(result)


async def test_a_delegation_the_holder_never_approved_is_refused(world, tmp_path):
    """Claiming the holder as delegator is not enough; the holder's log must anchor it."""
    unapproved = world.enrol(
        Controller(
            "unapproved-agent", delegator=world.holder, approve=False,
            witnesses=world.witnesses, toad=2,
        )
    )
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(
        world, "register_member", ARGS, signer=signer_for(unapproved), delegated=unapproved.pre
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"


async def test_a_delegated_aid_claim_must_match_the_signer(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS, delegated=world.le.pre)
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"


async def test_a_key_rotated_away_no_longer_verifies(world, tmp_path):
    """The key state is read from the witness now, not from what the caller remembers."""
    old = signer_for(world.agent)
    world.agent.rotate()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, signer=old), Ctx(), call_next
    )

    assert layer_of(result) == "invalid_signature"

    fresh = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, signer=signer_for(world.agent)), Ctx(), call_next
    )
    assert text_of(fresh) == "TOOL RAN"


# --------------------------------------------------------------------------------------------- #
# 4. Attacks on the credential
# --------------------------------------------------------------------------------------------- #

async def test_a_credential_written_by_the_caller_is_refused(world, tmp_path):
    """Mallory writes an ECR naming the real LE as issuer and herself as holder, and signs
    correctly with her own key. Every SAID recomputes; the LE never anchored it."""
    mallory = world.enrol(Controller("mallory", witnesses=world.witnesses, toad=2))
    forged = world.issue(
        world.le_registry, ECR_SCHEMA, mallory.pre,
        {"LEI": LEI, "personLegalName": "Mallory", "engagementContextRole": "member-registration"},
        edge=("le", world.le_credential), anchor=False,
    )
    from mcp_vlei.testing import export

    stream = export([forged, world.le_credential, world.qvi_credential])
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(
        world, "register_member", ARGS,
        signer=signer_for(mallory), stream=stream, said=forged.said, delegated=None,
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "chain_invalid"


async def test_a_credential_of_the_wrong_type_is_refused(world, tmp_path):
    """The LE's own credential, presented by the LE, to a tool that requires an ECR."""
    ext = build(world, tmp_path, {"register_member": {"credential": "ECR"}})
    params = present(
        world, "register_member", ARGS,
        signer=signer_for(world.le), said=world.le_credential.said, delegated=None,
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "chain_invalid"
    assert "ECR" in text_of(result)


# --------------------------------------------------------------------------------------------- #
# 5. Revoked — anywhere in the chain
# --------------------------------------------------------------------------------------------- #

async def test_revoked_credential_is_refused(world, tmp_path):
    world.le_registry.revoke(world.ecr_credential.said)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_a_revoked_link_above_the_ecr_refuses_the_call(world, tmp_path):
    """The LE's credential is withdrawn; every ECR it issued stands on nothing."""
    world.qvi_registry.revoke(world.le_credential.said)
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


async def test_an_issuance_the_log_does_not_know_is_refused(world, tmp_path):
    """No `iss` in the issuer's live log is not 'not revoked'."""
    world.le_registry.tels.clear()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert result.is_error is True
    assert layer_of(result) == "chain_invalid"


async def test_a_live_log_that_never_saw_the_issuance_is_not_read_as_valid(world, tmp_path):
    """The stream carries an issuance; the issuer's log as the witnesses serve it anchors none.
    Silence is not 'fine'."""
    import httpx

    params = present(world, "register_member", ARGS)
    anchor = next(i for i, e in enumerate(world.le.events)
                  if any(s.get("i") == world.ecr_credential.said for s in e.body.get("a", [])))
    before = "".join(e.cesr() for e in world.le.events[:anchor])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("typ") == "kel" and request.url.params.get("pre") == world.le.pre:
            return httpx.Response(200, text=before)
        return world.witness_handler(request)

    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
                client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "chain_invalid"
    assert "not established" in text_of(result)


async def test_a_signer_whose_log_is_forked_across_witnesses_is_refused(world, tmp_path):
    """Configured with several witnesses, the server compares the signer's log across them."""
    import httpx

    world.agent.interact([{"i": "E" + "a" * 43, "s": "0", "d": "E" + "a" * 43}])
    fork = world.agent.forked_kel([{"i": "E" + "b" * 43, "s": "0", "d": "E" + "b" * 43}])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "wes" and request.url.params.get("pre") == world.agent.pre:
            return httpx.Response(200, text=fork)
        return world.witness_handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, client=client,
                witness_urls=["http://wan", "http://wil", "http://wes"])
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert "duplicity" in text_of(result)


async def test_an_unreachable_witness_refuses_rather_than_allows(world, tmp_path):
    """The failure this project exists to prevent: reporting "could not check" as "fine"."""

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, client=client)
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert result.is_error is True
    assert "not established" in text_of(result)


# --------------------------------------------------------------------------------------------- #
# 6. The request itself
# --------------------------------------------------------------------------------------------- #

async def test_tampered_arguments_are_refused(world, tmp_path):
    """Sign one set of arguments, send another — the gap the digest exists to close."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    signed = present(world, "register_member", ARGS)
    tampered = make_params(
        "register_member", {"name": "Someone Else", "email": "attacker@example.org"}, signed.meta
    )
    result = await ext.intercept_tool_call(tampered, Ctx(), call_next)

    assert layer_of(result) == "digest_mismatch"


async def test_stale_signature_is_refused(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, ts=old), Ctx(), call_next
    )

    assert layer_of(result) == "stale_signature"


async def test_a_replay_is_refused(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS)
    first = await ext.intercept_tool_call(params, Ctx(), call_next)
    second = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert text_of(first) == "TOOL RAN"
    assert layer_of(second) == "stale_signature"


async def test_a_forged_request_cannot_lock_out_the_real_one(world, tmp_path):
    """Replay protection records only requests that verified. Otherwise anyone who guesses the
    (AID, digest, timestamp) of a call about to be made can burn it first with garbage."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    genuine = present(world, "register_member", ARGS)
    forged_meta = dict(genuine.meta)
    signature = dict(forged_meta[META_SIGNATURE])
    signature["sig"] = "0B" + "A" * 86
    forged_meta[META_SIGNATURE] = signature
    forged = make_params("register_member", ARGS, forged_meta)

    refused = await ext.intercept_tool_call(forged, Ctx(), call_next)
    allowed = await ext.intercept_tool_call(genuine, Ctx(), call_next)

    assert layer_of(refused) == "invalid_signature"
    assert text_of(allowed) == "TOOL RAN"


async def test_a_timestamp_without_a_zone_is_refused_by_layer(world, tmp_path):
    """Malformed input still names a layer; it does not escape as an unhandled TypeError. The
    layer is invalid_signature — a malformed signature object (spec) — not the retryable
    stale_signature: no clock makes a timestamp without a zone fresh."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    naive = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, ts=naive, exp=naive), Ctx(), call_next
    )

    assert layer_of(result) == "invalid_signature"
    assert "signature.ts carries no time zone" in text_of(result)
    assert check(result, "signature")["layer"] == "invalid_signature"
    for name in ("freshness", "digest"):
        assert check(result, name)["passed"] is None, f"{name} never ran"


# --------------------------------------------------------------------------------------------- #
# 7. Authority
# --------------------------------------------------------------------------------------------- #

async def test_role_mismatch_is_refused(world, tmp_path):
    ext = build(world, tmp_path, {"submit_filing": REQUIRES_FILING})
    result = await ext.intercept_tool_call(
        present(world, "submit_filing", {"form": "A1"}), Ctx(), call_next
    )

    assert layer_of(result) == "role_mismatch"
    assert "regulatory-filing" in text_of(result)


async def test_scope_exceeded_is_refused(tmp_path):
    world = World(role="regulatory-filing", scope={"maxAmount": 100_000}, label="scoped")
    ext = build(world, tmp_path, {"submit_filing": REQUIRES_FILING})
    result = await ext.intercept_tool_call(
        present(world, "submit_filing", {"form": "A1"}), Ctx(), call_next
    )

    assert layer_of(result) == "scope_exceeded"


async def test_scope_within_bounds_is_allowed(tmp_path):
    world = World(role="regulatory-filing", scope={"maxAmount": 5_000_000}, label="scoped-ok")
    ext = build(world, tmp_path, {"submit_filing": REQUIRES_FILING})
    result = await ext.intercept_tool_call(
        present(world, "submit_filing", {"form": "A1"}), Ctx(), call_next
    )

    assert text_of(result) == "TOOL RAN"


async def test_unknown_root_is_refused(world, tmp_path):
    """A perfectly valid chain to a root this server does not accept.

    Nothing is wrong with the credential, and nothing is wrong with the server. Two organizations
    disagree about whom they trust, and only they can resolve it — hence its own layer.
    """
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION}, roots=["E" + "x" * 43])
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "unknown_root"


# --------------------------------------------------------------------------------------------- #
# 8. The report tells the truth
# --------------------------------------------------------------------------------------------- #

async def test_the_report_names_the_key_state_it_verified_against(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)
    report = ext.last_report.as_dict()
    signature = next(c for c in report["checks"] if c["name"] == "signature")

    assert signature["passed"] is True
    assert "key event log" in signature["detail"]
    assert not any("issuer signatures were not verified" in c for c in report["caveats"])


async def test_a_refusal_carries_the_report(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = make_params(
        "register_member", ARGS, {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1},
                                  "org.gleif.vlei/credentialSaid": world.ecr_credential.said}
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert check(result, "signature")["passed"] is False


async def test_verify_call_is_the_same_pipeline_without_a_server(world, tmp_path):
    """A gateway or a console verifies a call it will not execute: same checks, same report."""
    from mcp_vlei.errors import InvalidSignature
    from mcp_vlei.report import VerificationReport

    ext = build(world, tmp_path)
    result = await ext.verify_call(present(world, "register_member", ARGS), REQUIRES_REGISTRATION)
    assert result.holder_aid == world.holder.pre

    report = VerificationReport(tool="register_member")
    forged = make_params(
        "register_member", ARGS, {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1},
                                  "org.gleif.vlei/credentialSaid": world.ecr_credential.said}
    )
    with pytest.raises(InvalidSignature):
        await ext.verify_call(forged, REQUIRES_REGISTRATION, report=report)
    assert report.failure.name == "signature"


# --------------------------------------------------------------------------------------------- #
# Capability declaration, SDK conformance, whoami, configuration
# --------------------------------------------------------------------------------------------- #

def test_identifier_is_valid_per_sep_2133(world, tmp_path):
    """The identifier is set per instance, from its namespace, and is a valid SEP-2133 identifier
    — the SDK validates a per-instance identifier when the extension is applied."""
    from mcp.server.extension import validate_extension_identifier

    for namespace, expected in ((None, "org.gleif.vlei/identity"),
                                ("net.zuemen.vlei", "net.zuemen.vlei/identity")):
        ext = build(world, tmp_path, namespace=namespace)
        validate_extension_identifier(ext.identifier, owner="VleiIdentity")
        assert ext.identifier == expected


def test_settings_are_the_capability_value(world, tmp_path):
    """`settings()` is the value at capabilities.extensions[identifier], not keyed again."""
    ext = build(world, tmp_path, well_known="https://example.org/.well-known/vlei")
    settings = ext.settings()

    assert settings["presents"] == ["LE"]
    assert settings["requires"] == "ECR"
    assert settings["acceptedRoots"] == [world.root.pre]
    assert settings["discovery"]["wellKnown"].endswith("/.well-known/vlei")


def test_contributed_tool_is_a_tool_binding(world, tmp_path):
    from mcp.server.extension import ToolBinding

    bindings = build(world, tmp_path).tools()
    assert len(bindings) == 1
    assert isinstance(bindings[0], ToolBinding)
    assert callable(bindings[0].fn)


def test_well_known_document_carries_the_le_credential(world, tmp_path):
    ext = build(world, tmp_path)
    doc = ext.well_known_document()
    assert doc["extension"] == "org.gleif.vlei/identity"
    assert doc["credential"] == world.le_stream


async def test_whoami_reports_unverified_without_a_credential(world, tmp_path):
    ext = build(world, tmp_path)
    result = await ext.intercept_tool_call(make_params("vlei_whoami", {}), Ctx(), call_next)
    assert "unverified" in text_of(result)


async def test_whoami_reports_identity_when_verified(world, tmp_path):
    ext = build(world, tmp_path)
    result = await ext.intercept_tool_call(present(world, "vlei_whoami", {}), Ctx(), call_next)
    assert LEI in text_of(result)
    assert "member-registration" in text_of(result)


async def test_the_verifier_source_still_establishes_revocation(world, tmp_path):
    """`revocation_source="verifier"` asks a vlei-verifier about revocation; the signer's key state
    and the chain are still established here."""
    verifier = StubVerifier(revoked=True)
    ext = build(
        world, tmp_path, {"register_member": REQUIRES_REGISTRATION},
        revocation_source="verifier", verifier=verifier,
    )
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)

    assert layer_of(result) == "revoked"


def test_the_verifier_revocation_source_needs_a_verifier(world, tmp_path):
    """Choosing `verifier` and supplying none used to skip revocation without a word."""
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with pytest.raises(ValueError, match="verifier"):
        VleiIdentity(
            le_credential=le, accepted_roots=[world.root.pre], witness_url="http://witness",
            revocation_source="verifier",
        )


async def test_an_extension_that_cannot_see_its_tools_refuses_rather_than_opens(world, tmp_path):
    """Never bound to its server and given no requirements, every tool used to be public."""
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    ext = VleiIdentity(
        le_credential=le, accepted_roots=[world.root.pre], witness_url="http://witness",
        witness_client=world.witness_client(), audience_urls=[AUDIENCE_URL],
    )
    result = await ext.intercept_tool_call(make_params("register_member", ARGS), Ctx(), call_next)

    assert result.is_error is True
    assert "bind" in text_of(result)


def test_a_witness_is_required(world, tmp_path):
    """The signer's key state is read from a witness; without one nothing can be verified."""
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with pytest.raises(ValueError, match="witness_url"):
        VleiIdentity(le_credential=le, accepted_roots=[world.root.pre], revocation_source="none")


def test_tel_source_requires_a_witness(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with pytest.raises(ValueError, match="witness_url"):
        VleiIdentity(le_credential=le, accepted_roots=[world.root.pre], revocation_source="tel")


def test_an_unknown_revocation_source_is_refused(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    with pytest.raises(ValueError, match="revocation_source"):
        VleiIdentity(le_credential=le, accepted_roots=[world.root.pre], revocation_source="vibes")


def test_empty_accepted_roots_is_a_configuration_error():
    """An empty accepted-roots list is not 'accept anything' — it is the whole trust decision."""
    from mcp_vlei import VleiVerifier

    with pytest.raises(ValueError, match="accepted_roots"):
        VleiVerifier("http://localhost:7676", accepted_roots=[])


# --------------------------------------------------------------------------------------------- #
# v0.3: the recipient, the format, restarts, and what a refusal never says
# --------------------------------------------------------------------------------------------- #

OTHER_SERVER = "E" + "X" * 43


def test_the_servers_audience_is_its_les_issuee_at_its_configured_urls(world, tmp_path):
    ext = build(world, tmp_path, audience_urls=["HTTP://SERVER.TEST/mcp", "http://127.0.0.1:8080/mcp"])
    assert ext.recipient.aid == world.le.pre
    assert ext.recipient.urls == ("http://server.test/mcp", "http://127.0.0.1:8080/mcp")


def test_a_server_without_audience_urls_is_a_configuration_error(world, tmp_path):
    with pytest.raises(ValueError, match="audience_urls"):
        build(world, tmp_path, audience_urls=[])


def test_the_capability_and_the_well_known_document_declare_the_format(world, tmp_path):
    ext = build(world, tmp_path)
    assert ext.settings()["signatureFormats"] == ["vlei-sig/0.3"]
    assert ext.well_known_document()["signatureFormats"] == ["vlei-sig/0.3"]


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), True, None])
def test_ttl_ms_must_be_a_non_negative_finite_number(world, tmp_path, bad):
    with pytest.raises(ValueError, match="ttl_ms"):
        build(world, tmp_path, ttl_ms=bad)


def test_ttl_ms_default_still_constructs(world, tmp_path):
    ext = build(world, tmp_path)
    assert ext.ttl_ms == 30_000
    assert ext.settings()["ttlMs"] == 30_000
    assert ext.well_known_document()["ttlMs"] == 30_000


def test_ttl_ms_zero_is_accepted(world, tmp_path):
    """0 is a stated meaning (spec §6.3: re-check before every presentation), not an error."""
    ext = build(world, tmp_path, ttl_ms=0)
    assert ext.ttl_ms == 0
    assert ext.settings()["ttlMs"] == 0
    assert ext.well_known_document()["ttlMs"] == 0


async def test_a_call_signed_for_another_server_is_refused_before_it_runs(world, tmp_path):
    """The replay the council found: a call captured at one server, sent to another."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS,
                     audience=Audience(OTHER_SERVER, AUDIENCE_URL))
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "audience_mismatch"
    assert check(result, "digest")["layer"] == "audience_mismatch"
    assert check(result, "signature")["passed"] is None, "refused before any witness was asked"


async def test_a_call_signed_for_another_endpoint_of_the_same_entity_is_refused(world, tmp_path):
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = present(world, "register_member", ARGS,
                     audience=Audience(world.le.pre, "http://other-route.test/mcp"))
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "audience_mismatch"
    assert "http://other-route.test/mcp, which is not this server's endpoint" in text_of(result)
    assert "http://server.test/mcp" not in text_of(result)


def _readdressed(world, params, aud: dict):
    """``params`` with its signature's ``aud`` rewritten and everything else — ``sig`` too — kept."""
    meta = dict(params.meta)
    meta[META_SIGNATURE] = {**meta[META_SIGNATURE], "aud": aud}
    return make_params("register_member", ARGS, meta)


async def test_an_intercepted_call_re_addressed_to_this_server_is_invalid_signature(world, tmp_path):
    """A call captured on its way to another server, its ``aud`` rewritten to name this one: it now
    passes the recipient check, and fails the signature, which covers ``aud``."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    captured = present(world, "register_member", ARGS,
                       audience=Audience(OTHER_SERVER, "http://elsewhere.test/mcp"))
    result = await ext.intercept_tool_call(
        _readdressed(world, captured, {"aid": world.le.pre, "url": AUDIENCE_URL}), Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert check(result, "digest")["passed"] is True, "it names this server and the arguments match"
    assert check(result, "signature")["layer"] == "invalid_signature"
    assert "does not verify" in text_of(result)


async def test_a_malformed_audience_aid_is_invalid_signature_not_audience_mismatch(world, tmp_path):
    """An ``aud.aid`` that is no CESR identifier names no recipient at all: a malformed signature
    object, refused at the signature row (spec), with freshness and digest not reached."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = _readdressed(world, present(world, "register_member", ARGS),
                          {"aid": "not-an-aid", "url": AUDIENCE_URL})
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert "aud.aid" in text_of(result)
    assert check(result, "signature")["layer"] == "invalid_signature"
    for name in ("freshness", "digest"):
        assert check(result, name)["passed"] is None, f"{name} never ran"


@pytest.mark.parametrize("said", [None, ""], ids=["credentialSaid-sent", "no-credentialSaid"])
async def test_a_v02_signature_is_unsupported_version(world, tmp_path, said):
    """A v0.2 client sends no credentialSaid (v0.2 had none): the format is named first, as
    unsupported_version, never as the missing_credential its absence would otherwise be."""
    from mcp_vlei.signing import digest_params

    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    signer = signer_for(world.agent)
    unsigned = make_params("register_member", ARGS).model_dump(by_alias=True, exclude_none=True)
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    digest = digest_params(unsigned)
    legacy = {"aid": signer.aid, "ts": ts, "digest": digest, "alg": "Ed25519",
              "sig": signer.sign(f"tools/call\n{ts}\n{digest}".encode())}
    params = present(world, "register_member", ARGS, said=said)
    assert ("org.gleif.vlei/credentialSaid" in params.meta) is (said is None)
    params = make_params("register_member", ARGS, {**params.meta, META_SIGNATURE: legacy})
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "unsupported_version"
    assert check(result, "credential_present")["layer"] == "unsupported_version"


async def test_a_replay_across_a_restart_is_refused_by_the_persistent_store(world, tmp_path):
    requirements = {"register_member": REQUIRES_REGISTRATION}
    path = tmp_path / "state" / "replay.sqlite3"
    # Created "long ago", so its memory began before this test signs anything.
    first = build(world, tmp_path, requirements,
                  replay_store=SqliteReplayStore(path, clock=lambda: LONG_AGO))
    params = present(world, "register_member", ARGS)
    assert text_of(await first.intercept_tool_call(params, Ctx(), call_next)) == "TOOL RAN"

    restarted = build(world, tmp_path, requirements, replay_store=SqliteReplayStore(path))
    assert restarted._replay.memory_since == LONG_AGO, "the horizon is the file's"
    result = await restarted.intercept_tool_call(params, Ctx(), call_next)
    assert layer_of(result) == "stale_signature"
    # The nonce-spent refusal itself: the memory-horizon refusal also says "replay", and a store
    # that forgot everything would produce that one.
    assert "already presented (its nonce is spent)" in text_of(result)


async def test_a_replay_across_a_restart_is_refused_by_the_memory_horizon(world, tmp_path):
    requirements = {"register_member": REQUIRES_REGISTRATION}
    params = present(world, "register_member", ARGS)
    assert text_of(await build(world, tmp_path, requirements).intercept_tool_call(
        params, Ctx(), call_next)) == "TOOL RAN"

    restarted = build(world, tmp_path, requirements, replay_store=MemoryReplayStore())
    result = await restarted.intercept_tool_call(params, Ctx(), call_next)
    assert layer_of(result) == "stale_signature"
    assert "replay memory began" in text_of(result)


async def test_no_refusal_or_record_names_the_person(world, tmp_path):
    """The ECR carries personLegalName. No report, failure detail or decision record repeats it,
    whichever check the call stops at."""
    import json

    person = json.loads(world.ecr_credential.raw)["a"]["personLegalName"]
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION,
                                  "file_return": {"credential": "ECR", "role": "regulatory-filing"}})
    calls = [  # each with where it stops, so a case that silently stopped elsewhere is caught
        (present(world, "register_member", ARGS), "allowed"),
        (present(world, "file_return", ARGS), "role_mismatch"),
        (present(world, "register_member", ARGS, audience=Audience(OTHER_SERVER, AUDIENCE_URL)),
         "audience_mismatch"),
        (present(world, "register_member", ARGS, said=""), "missing_credential"),
    ]
    for params, stops_at in calls:
        result = await ext.intercept_tool_call(params, Ctx(), call_next)
        assert (text_of(result) == "TOOL RAN") if stops_at == "allowed" else (
            layer_of(result) == stops_at), (stops_at, text_of(result))
        assert not name_leaked(json.dumps(result.model_dump(by_alias=True), ensure_ascii=False), person)
    world.le_registry.revoke(world.ecr_credential.said)
    result = await ext.intercept_tool_call(present(world, "register_member", ARGS), Ctx(), call_next)
    assert layer_of(result) == "revoked"
    assert not name_leaked(json.dumps(result.model_dump(by_alias=True), ensure_ascii=False), person)
    assert not name_leaked(json.dumps(ext.records, ensure_ascii=False), person)
    assert not name_leaked(json.dumps(ext.last_report.as_dict(), ensure_ascii=False), person)


async def test_a_signer_whose_clock_is_59_seconds_ahead_is_still_accepted(world, tmp_path):
    """Two organisations' clocks: v0.2 tolerated 60 s either way, and v0.3 keeps that tolerance."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    ahead = (datetime.now(timezone.utc) + timedelta(seconds=59)).isoformat(timespec="milliseconds")
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, ts=ahead.replace("+00:00", "Z")), Ctx(), call_next)
    assert text_of(result) == "TOOL RAN"


# --------------------------------------------------------------------------------------------- #
# Fix round 1 (review findings F1, F2): a non-string credentialSaid, and what a malformed
# signature leaves behind in rows that never ran.
# --------------------------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_said", [{"x": 1}, ["E" + "X" * 43]], ids=["dict", "list"])
async def test_a_non_string_credential_said_is_chain_invalid(world, tmp_path, bad_said):
    """F1: credentialSaid comes from attacker-controlled _meta. `_presented` does
    `target not in credentials` without checking it is a string first — a dict or list is
    unhashable there and raised TypeError instead of naming a layer. 7 and "abc" already landed
    on chain_invalid (hashable, just absent); a dict or list must land there too, not crash."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = make_params(
        "register_member", ARGS,
        {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1},
         "org.gleif.vlei/credentialSaid": bad_said},
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "chain_invalid"


@pytest.mark.parametrize("bad_said", [{"x": 1}, ["E" + "X" * 43]], ids=["dict", "list"])
async def test_whoami_with_a_non_string_credential_said_does_not_crash(world, tmp_path, bad_said):
    """Same malformed input through vlei_whoami: `_try_verify` only catches VleiError, so the
    TypeError escaped there too. The fix must raise a VleiError (chain_invalid), caught here and
    reported the same way any other failed credential makes whoami say "unverified"."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = make_params(
        "vlei_whoami", {},
        {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1},
         "org.gleif.vlei/credentialSaid": bad_said},
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "unverified"


@pytest.mark.parametrize(
    "junk", [{"junk": 1}, "not a signature", ["E" + "X" * 43]], ids=["dict", "string", "list"]
)
async def test_a_malformed_signature_leaves_freshness_and_digest_not_reached(world, tmp_path, junk):
    """F2: parse_signature raises invalid_signature on shape alone, before _check_time or
    _check_digest ever runs. The refusal still names the signature row (per spec), but freshness
    and digest must show as not reached — the same representation unreached rows always get —
    never silently "passed" with an empty detail, which is what the demo's first gate reads."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    params = make_params(
        "register_member", ARGS,
        {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: junk,
         "org.gleif.vlei/credentialSaid": world.ecr_credential.said},
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "invalid_signature"
    assert check(result, "signature")["layer"] == "invalid_signature"
    for name in ("freshness", "digest"):
        row = check(result, name)
        assert row["passed"] is None, f"{name} never ran and must not read as passed"
        assert row["detail"] == ""
