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

from conftest import Ctx, StubVerifier, make_params  # noqa: E402
from mcp_vlei.testing import ECR_SCHEMA, LEI, Controller, World
from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.extension import META_CREDENTIAL, META_DELEGATED_AID, META_SIGNATURE
from mcp_vlei.signing import sign_request

REQUIRES_REGISTRATION = {"credential": "ECR", "role": "member-registration"}
REQUIRES_FILING = {
    "credential": "ECR",
    "role": "regulatory-filing",
    "scope": {"maxAmount": 1_000_000},
}
ARGS = {"name": "A", "email": "a@example.org"}


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
    **extra,
):
    """Sign and present — by default, the agent presenting its holder's ECR."""
    signer = signer or signer_for(world.agent)
    unsigned = make_params(tool, arguments)
    meta = {
        META_CREDENTIAL: stream if stream is not None else world.ecr_stream,
        META_SIGNATURE: sign_request(
            signer, "tools/call", unsigned.model_dump(by_alias=True, exclude_none=True), ts=ts
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


async def test_the_presented_credential_is_found_without_being_named(world, tmp_path):
    """A --full export carries the whole chain; the one presented is the leaf, not the first."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, said=""), Ctx(), call_next
    )

    assert text_of(result) == "TOOL RAN"


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
        {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1}},
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
    """The stream carries an issuance; the witness's live log has none. Silence is not 'fine'."""
    params = present(world, "register_member", ARGS)
    world.le_registry.tels.clear()
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
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
    """Malformed input still names a layer; it does not escape as an unhandled TypeError."""
    ext = build(world, tmp_path, {"register_member": REQUIRES_REGISTRATION})
    naive = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    result = await ext.intercept_tool_call(
        present(world, "register_member", ARGS, ts=naive), Ctx(), call_next
    )

    assert layer_of(result) == "stale_signature"


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
        "register_member", ARGS, {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1}}
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
        "register_member", ARGS, {META_CREDENTIAL: world.ecr_stream, META_SIGNATURE: {"junk": 1}}
    )
    with pytest.raises(InvalidSignature):
        await ext.verify_call(forged, REQUIRES_REGISTRATION, report=report)
    assert report.failure.name == "signature"


# --------------------------------------------------------------------------------------------- #
# Capability declaration, SDK conformance, whoami, configuration
# --------------------------------------------------------------------------------------------- #

def test_identifier_is_valid_per_sep_2133():
    """The SDK validates extension identifiers at subclass-definition time."""
    from mcp.server.extension import validate_extension_identifier

    validate_extension_identifier(VleiIdentity.identifier, owner="VleiIdentity")
    assert VleiIdentity.identifier == "org.gleif.vlei/identity"


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
        witness_client=world.witness_client(),
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
