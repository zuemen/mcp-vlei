"""The seven server-side scenarios from the task acceptance list.

Each asserts on the **named failure layer**, not on "it was refused". The layer is what the skill
keys its recovery off and what the demo narrates, so a test that only checks for refusal would pass
while the deliverable was broken.
"""

from __future__ import annotations

import pytest

from conftest import AGENT_AID, Ctx, StubVerifier  # noqa: E402
from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.extension import META_CREDENTIAL, META_DELEGATED_AID, META_SIGNATURE
from mcp_vlei.signing import sign_request

REQUIRES_REGISTRATION = {"credential": "ECR", "role": "member-registration"}
REQUIRES_FILING = {"credential": "ECR", "role": "regulatory-filing", "scope": {"maxAmount": 1_000_000}}


def build(le_credential, verifier, **kwargs) -> VleiIdentity:
    records: list[dict] = []
    ext = VleiIdentity(
        le_credential=le_credential,
        verifier_url="http://unused",
        accepted_roots=["EHJ2kA8vQZ4Yd3mRr7TcN1sWpLxFbGuV9oKqDzXnA5eM"],
        verifier=verifier,
        on_decision=records.append,
        **kwargs,
    )
    ext.records = records  # type: ignore[attr-defined]
    return ext


def signed_meta(signer: Signer, credential_file, tool: str, arguments: dict) -> dict:
    params = {"name": tool, "arguments": arguments}
    return {
        META_CREDENTIAL: credential_file.read_text(),
        META_DELEGATED_AID: AGENT_AID,
        META_SIGNATURE: sign_request(signer, "tools/call", params),
    }


async def call_next(ctx):
    return {"content": [{"type": "text", "text": "ok"}], "isError": False}


def layer_of(result) -> str:
    return result["content"][0]["text"].split(":", 1)[0]


# --------------------------------------------------------------------------------------------- #
# 1. Happy path
# --------------------------------------------------------------------------------------------- #

async def test_valid_credential_is_allowed(le_credential, credential_file, signer):
    ext = build(le_credential, StubVerifier(role="member-registration"))
    ctx = Ctx(
        "register_member",
        {"name": "A", "email": "a@example.org"},
        signed_meta(signer, credential_file, "register_member", {"name": "A", "email": "a@example.org"}),
        requires=REQUIRES_REGISTRATION,
        verkey=signer.verkey,
    )
    result = await ext.intercept_tool_call(ctx, call_next)

    assert result["isError"] is False
    assert ctx.vlei.lei == "984500ABCDEF12345678"
    assert ext.records[-1]["allowed"] is True


# --------------------------------------------------------------------------------------------- #
# 2. No credential
# --------------------------------------------------------------------------------------------- #

async def test_missing_credential_is_refused(le_credential):
    ext = build(le_credential, StubVerifier())
    ctx = Ctx("register_member", {}, {}, requires=REQUIRES_REGISTRATION)
    result = await ext.intercept_tool_call(ctx, call_next)

    assert result["isError"] is True
    assert layer_of(result) == "missing_credential"
    assert ext.records[-1]["identity"] == "unverified"


async def test_public_tool_needs_nothing(le_credential):
    """Additive: a tool that declares no requirement is unaffected by the extension."""
    ext = build(le_credential, StubVerifier())
    ctx = Ctx("list_events", {}, {})
    result = await ext.intercept_tool_call(ctx, call_next)

    assert result["isError"] is False
    assert ext.records[-1]["note"] == "public tool"


# --------------------------------------------------------------------------------------------- #
# 3. Revoked
# --------------------------------------------------------------------------------------------- #

async def test_revoked_credential_is_refused(le_credential, credential_file, signer):
    ext = build(le_credential, StubVerifier(revoked=True))
    ctx = Ctx(
        "register_member",
        {"name": "A", "email": "a@example.org"},
        signed_meta(signer, credential_file, "register_member", {"name": "A", "email": "a@example.org"}),
        requires=REQUIRES_REGISTRATION,
        verkey=signer.verkey,
    )
    result = await ext.intercept_tool_call(ctx, call_next)

    assert layer_of(result) == "revoked"


# --------------------------------------------------------------------------------------------- #
# 4. Tampered arguments
# --------------------------------------------------------------------------------------------- #

async def test_tampered_arguments_are_refused(le_credential, credential_file, signer):
    ext = build(le_credential, StubVerifier())
    meta = signed_meta(signer, credential_file, "register_member", {"name": "A", "email": "a@example.org"})
    ctx = Ctx(
        "register_member",
        {"name": "Someone Else", "email": "attacker@example.org"},
        meta,
        requires=REQUIRES_REGISTRATION,
        verkey=signer.verkey,
    )
    result = await ext.intercept_tool_call(ctx, call_next)

    assert layer_of(result) == "digest_mismatch"


# --------------------------------------------------------------------------------------------- #
# 5. Stale signature
# --------------------------------------------------------------------------------------------- #

async def test_stale_signature_is_refused(le_credential, credential_file, signer):
    from datetime import datetime, timedelta, timezone

    ext = build(le_credential, StubVerifier())
    params = {"name": "register_member", "arguments": {"name": "A", "email": "a@example.org"}}
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        META_CREDENTIAL: credential_file.read_text(),
        META_DELEGATED_AID: AGENT_AID,
        META_SIGNATURE: sign_request(signer, "tools/call", params, ts=old),
    }
    ctx = Ctx("register_member", params["arguments"], meta, requires=REQUIRES_REGISTRATION, verkey=signer.verkey)
    result = await ext.intercept_tool_call(ctx, call_next)

    assert layer_of(result) == "stale_signature"


# --------------------------------------------------------------------------------------------- #
# 6. Role mismatch
# --------------------------------------------------------------------------------------------- #

async def test_role_mismatch_is_refused(le_credential, credential_file, signer):
    ext = build(le_credential, StubVerifier(role="member-registration"))
    args = {"form": "A1", "period": "2026Q2", "payload": {}}
    ctx = Ctx(
        "submit_filing",
        args,
        signed_meta(signer, credential_file, "submit_filing", args),
        requires=REQUIRES_FILING,
        verkey=signer.verkey,
    )
    result = await ext.intercept_tool_call(ctx, call_next)

    assert layer_of(result) == "role_mismatch"
    assert "regulatory-filing" in result["content"][0]["text"]


# --------------------------------------------------------------------------------------------- #
# 7. Scope exceeded
# --------------------------------------------------------------------------------------------- #

async def test_scope_exceeded_is_refused(le_credential, credential_file, signer):
    ext = build(
        le_credential,
        StubVerifier(role="regulatory-filing", scope={"maxAmount": 100_000}),
    )
    args = {"form": "A1", "period": "2026Q2", "payload": {}}
    ctx = Ctx(
        "submit_filing",
        args,
        signed_meta(signer, credential_file, "submit_filing", args),
        requires=REQUIRES_FILING,
        verkey=signer.verkey,
    )
    result = await ext.intercept_tool_call(ctx, call_next)

    assert layer_of(result) == "scope_exceeded"


# --------------------------------------------------------------------------------------------- #
# Capability declaration and whoami
# --------------------------------------------------------------------------------------------- #

def test_settings_declare_the_extension(le_credential):
    ext = build(le_credential, StubVerifier(), well_known="https://example.org/.well-known/vlei")
    settings = ext.settings()["org.gleif.vlei/identity"]

    assert settings["presents"] == ["LE"]
    assert settings["requires"] == "ECR"
    assert settings["discovery"]["wellKnown"].endswith("/.well-known/vlei")


def test_well_known_document_carries_the_le_credential(le_credential):
    ext = build(le_credential, StubVerifier())
    doc = ext.well_known_document()
    assert doc["extension"] == "org.gleif.vlei/identity"
    assert doc["credential"] == le_credential.read_text().strip()


async def test_whoami_reports_unverified_without_a_credential(le_credential):
    ext = build(le_credential, StubVerifier())
    result = await ext.intercept_tool_call(Ctx("vlei_whoami", {}, {}), call_next)
    assert "unverified" in result["content"][0]["text"]


async def test_whoami_reports_identity_when_verified(le_credential, credential_file, signer):
    ext = build(le_credential, StubVerifier(role="member-registration"))
    meta = signed_meta(signer, credential_file, "vlei_whoami", {})
    result = await ext.intercept_tool_call(Ctx("vlei_whoami", {}, meta, verkey=signer.verkey), call_next)
    text = result["content"][0]["text"]
    assert "984500ABCDEF12345678" in text and "member-registration" in text


def test_empty_accepted_roots_is_a_configuration_error():
    """An empty accepted-roots list is not 'accept anything' — it is the whole trust decision."""
    from mcp_vlei import VleiVerifier

    with pytest.raises(ValueError, match="accepted_roots"):
        VleiVerifier("http://localhost:7676", accepted_roots=[])
