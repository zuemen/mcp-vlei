"""The eight server-side scenarios from the task acceptance list.

Each asserts on the **named failure layer**, not on "it was refused". The layer is what the skill
keys its recovery off and what the demo narrates, so a test that only checked for refusal would
pass while the deliverable was broken.

These run against the real SDK types (`CallToolRequestParams`) and the real `Extension` signature,
with a stub verifier standing in for a live `vlei-verifier`.
"""

from __future__ import annotations

import pytest

from conftest import AGENT_AID, ROOT_AID, Ctx, StubVerifier, make_params  # noqa: E402
from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.extension import META_CREDENTIAL, META_DELEGATED_AID, META_SIGNATURE
from mcp_vlei.signing import sign_request

REQUIRES_REGISTRATION = {"credential": "ECR", "role": "member-registration"}
REQUIRES_FILING = {
    "credential": "ECR",
    "role": "regulatory-filing",
    "scope": {"maxAmount": 1_000_000},
}
ROOT = ROOT_AID


def build(le_credential, verifier, requirements=None, **kwargs) -> VleiIdentity:
    records: list[dict] = []
    ext = VleiIdentity(
        le_credential=le_credential,
        verifier_url="http://unused",
        accepted_roots=[ROOT],
        verifier=verifier,
        requirements=requirements,
        on_decision=records.append,
        **kwargs,
    )
    ext.records = records  # type: ignore[attr-defined]
    return ext


def signed_meta(signer: Signer, credential_file, tool: str, arguments: dict, said: str = "") -> dict:
    params = make_params(tool, arguments)
    return {
        META_CREDENTIAL: credential_file.read_text(),
        # Name the credential being presented. A chain export carries several, and "the first one
        # in the stream" is the root of the chain, not this one.
        "org.gleif.vlei/credentialSaid": said,
        META_DELEGATED_AID: AGENT_AID,
        META_SIGNATURE: sign_request(
            signer, "tools/call", params.model_dump(by_alias=True, exclude_none=True)
        ),
        "org.gleif.vlei/verkey": signer.verkey,
    }


async def call_next(ctx):
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(content=[TextContent(type="text", text="ok")], is_error=False)


def layer_of(result) -> str:
    return result.content[0].text.split(":", 1)[0]


def text_of(result) -> str:
    return result.content[0].text


# --------------------------------------------------------------------------------------------- #
# 1. Happy path
# --------------------------------------------------------------------------------------------- #

async def test_valid_credential_is_allowed(le_credential, credential_file, credential_said, signer):
    ext = build(
        le_credential,
        StubVerifier(role="member-registration"),
        requirements={"register_member": REQUIRES_REGISTRATION},
    )
    args = {"name": "A", "email": "a@example.org"}
    params = make_params(
        "register_member", args, signed_meta(signer, credential_file, "register_member", args, credential_said)
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert result.is_error is False
    assert ext.records[-1]["allowed"] is True
    assert ext.records[-1]["lei"] == "984500ABCDEF12345678"


# --------------------------------------------------------------------------------------------- #
# 2. No credential
# --------------------------------------------------------------------------------------------- #

async def test_missing_credential_is_refused(le_credential):
    ext = build(
        le_credential, StubVerifier(), requirements={"register_member": REQUIRES_REGISTRATION}
    )
    result = await ext.intercept_tool_call(make_params("register_member", {}), Ctx(), call_next)

    assert result.is_error is True
    assert layer_of(result) == "missing_credential"
    assert ext.records[-1]["identity"] == "unverified"


async def test_public_tool_needs_nothing(le_credential):
    """Additive: a tool that declares no requirement is unaffected by the extension."""
    ext = build(le_credential, StubVerifier())
    result = await ext.intercept_tool_call(make_params("list_events", {}), Ctx(), call_next)

    assert result.is_error is False
    assert ext.records[-1]["note"] == "public tool"


# --------------------------------------------------------------------------------------------- #
# 3. Revoked
# --------------------------------------------------------------------------------------------- #

async def test_revoked_credential_is_refused(le_credential, credential_file, credential_said, signer):
    ext = build(
        le_credential,
        StubVerifier(revoked=True),
        requirements={"register_member": REQUIRES_REGISTRATION},
    )
    args = {"name": "A", "email": "a@example.org"}
    params = make_params(
        "register_member", args, signed_meta(signer, credential_file, "register_member", args, credential_said)
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "revoked"


# --------------------------------------------------------------------------------------------- #
# 4. Tampered arguments
# --------------------------------------------------------------------------------------------- #

async def test_tampered_arguments_are_refused(le_credential, credential_file, credential_said, signer):
    """Sign one set of arguments, send another — the gap the digest exists to close."""
    ext = build(
        le_credential, StubVerifier(), requirements={"register_member": REQUIRES_REGISTRATION}
    )
    meta = signed_meta(
        signer, credential_file, "register_member", {"name": "A", "email": "a@example.org"}
    )
    params = make_params(
        "register_member", {"name": "Someone Else", "email": "attacker@example.org"}, meta
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "digest_mismatch"


# --------------------------------------------------------------------------------------------- #
# 5. Stale signature
# --------------------------------------------------------------------------------------------- #

async def test_stale_signature_is_refused(le_credential, credential_file, credential_said, signer):
    from datetime import datetime, timedelta, timezone

    ext = build(
        le_credential, StubVerifier(), requirements={"register_member": REQUIRES_REGISTRATION}
    )
    args = {"name": "A", "email": "a@example.org"}
    params = make_params("register_member", args)
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        META_CREDENTIAL: credential_file.read_text(),
        META_DELEGATED_AID: AGENT_AID,
        META_SIGNATURE: sign_request(
            signer,
            "tools/call",
            params.model_dump(by_alias=True, exclude_none=True),
            ts=old,
        ),
        "org.gleif.vlei/verkey": signer.verkey,
    }
    result = await ext.intercept_tool_call(
        make_params("register_member", args, meta), Ctx(), call_next
    )

    assert layer_of(result) == "stale_signature"


# --------------------------------------------------------------------------------------------- #
# 6. Role mismatch
# --------------------------------------------------------------------------------------------- #

async def test_role_mismatch_is_refused(le_credential, credential_file, credential_said, signer):
    ext = build(
        le_credential,
        StubVerifier(role="member-registration"),
        requirements={"submit_filing": REQUIRES_FILING},
    )
    args = {"form": "A1", "period": "2026Q2", "payload": {}}
    params = make_params(
        "submit_filing", args, signed_meta(signer, credential_file, "submit_filing", args, credential_said)
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "role_mismatch"
    assert "regulatory-filing" in text_of(result)


# --------------------------------------------------------------------------------------------- #
# 7. Scope exceeded
# --------------------------------------------------------------------------------------------- #

async def test_scope_exceeded_is_refused(le_credential, credential_file, credential_said, signer):
    ext = build(
        le_credential,
        StubVerifier(role="regulatory-filing", scope={"maxAmount": 100_000}),
        requirements={"submit_filing": REQUIRES_FILING},
    )
    args = {"form": "A1", "period": "2026Q2", "payload": {}}
    params = make_params(
        "submit_filing", args, signed_meta(signer, credential_file, "submit_filing", args, credential_said)
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "scope_exceeded"


# --------------------------------------------------------------------------------------------- #
# 8. Unknown root — the chain validates, but not to a root we accept
# --------------------------------------------------------------------------------------------- #

async def test_unknown_root_is_refused(le_credential, credential_file, credential_said, signer):
    """A perfectly valid chain to the wrong root is still refused.

    This is the layer most likely to be mistaken for a bug in the field, which is why it is named
    separately: nothing is wrong with the credential, and nothing is wrong with the server. Two
    organizations disagree about whom they trust, and only they can resolve it.
    """
    ext = build(
        le_credential,
        StubVerifier(
            role="member-registration", root_aid="EOtherRootAidThatWeDoNotAcceptXXXXXXXXXXXXXX"
        ),
        requirements={"register_member": REQUIRES_REGISTRATION},
    )
    args = {"name": "A", "email": "a@example.org"}
    params = make_params(
        "register_member", args, signed_meta(signer, credential_file, "register_member", args, credential_said)
    )
    result = await ext.intercept_tool_call(params, Ctx(), call_next)

    assert layer_of(result) == "unknown_root"


# --------------------------------------------------------------------------------------------- #
# Capability declaration, SDK conformance, and whoami
# --------------------------------------------------------------------------------------------- #

def test_identifier_is_valid_per_sep_2133():
    """The SDK validates extension identifiers at subclass-definition time."""
    from mcp.server.extension import validate_extension_identifier

    validate_extension_identifier(VleiIdentity.identifier, owner="VleiIdentity")
    assert VleiIdentity.identifier == "org.gleif.vlei/identity"


def test_settings_are_the_capability_value(le_credential):
    """`settings()` returns the value advertised at capabilities.extensions[identifier] —
    not a dict keyed by the identifier again."""
    ext = build(
        le_credential, StubVerifier(), well_known="https://example.org/.well-known/vlei"
    )
    settings = ext.settings()

    assert settings["presents"] == ["LE"]
    assert settings["requires"] == "ECR"
    assert settings["acceptedRoots"] == [ROOT]
    assert settings["discovery"]["wellKnown"].endswith("/.well-known/vlei")


def test_contributed_tool_is_a_tool_binding(le_credential):
    from mcp.server.extension import ToolBinding

    bindings = build(le_credential, StubVerifier()).tools()
    assert len(bindings) == 1
    assert isinstance(bindings[0], ToolBinding)
    assert callable(bindings[0].fn)


def test_well_known_document_carries_the_le_credential(le_credential):
    ext = build(le_credential, StubVerifier())
    doc = ext.well_known_document()
    assert doc["extension"] == "org.gleif.vlei/identity"
    assert doc["credential"] == le_credential.read_text().strip()


async def test_whoami_reports_unverified_without_a_credential(le_credential):
    ext = build(le_credential, StubVerifier())
    result = await ext.intercept_tool_call(make_params("vlei_whoami", {}), Ctx(), call_next)
    assert "unverified" in text_of(result)


async def test_whoami_reports_identity_when_verified(le_credential, credential_file, credential_said, signer):
    ext = build(le_credential, StubVerifier(role="member-registration"))
    meta = signed_meta(signer, credential_file, "vlei_whoami", {}, credential_said)
    result = await ext.intercept_tool_call(
        make_params("vlei_whoami", {}, meta), Ctx(), call_next
    )
    assert "984500ABCDEF12345678" in text_of(result)
    assert "member-registration" in text_of(result)


def test_empty_accepted_roots_is_a_configuration_error():
    """An empty accepted-roots list is not 'accept anything' — it is the whole trust decision."""
    from mcp_vlei import VleiVerifier

    with pytest.raises(ValueError, match="accepted_roots"):
        VleiVerifier("http://localhost:7676", accepted_roots=[])
