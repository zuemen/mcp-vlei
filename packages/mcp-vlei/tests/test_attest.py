"""Attestations — mode (b). The safety property under test is that trust is not transitive by
accident: an attestation verifies only under a key established independently of the attestation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from conftest import AGENT_AID, CRED_SAID, HOLDER_AID, LEI  # noqa: E402
from mcp_vlei import Signer, make_attestation, verify_attestation
from mcp_vlei.errors import ChainInvalid, InvalidSignature, StaleSignature
from mcp_vlei.verifier import VerificationResult

GATEWAY_AID = "EGw2LmTnXqYr8Kd5PcVbJi3RoUa1HsNfEq7ZdMxWy4Vt"


@pytest.fixture
def gateway() -> Signer:
    import secrets

    return Signer.from_seed(GATEWAY_AID, secrets.token_bytes(32))


@pytest.fixture
def result() -> VerificationResult:
    return VerificationResult(
        aid=AGENT_AID, lei=LEI, role="regulatory-filing",
        credential_said=CRED_SAID, holder_aid=HOLDER_AID,
    )


def test_roundtrip(gateway, result):
    att = make_attestation(gateway, result)
    out = verify_attestation(att, verifier_verkey=gateway.verkey, expected_subject_aid=AGENT_AID)

    assert out.lei == LEI
    assert out.role == "regulatory-filing"
    assert out.source == "attestation", "the audit trail must show this was attested, not checked here"


def test_tampered_lei_is_rejected(gateway, result):
    att = make_attestation(gateway, result)
    att["lei"] = "000000000000000000XX"
    with pytest.raises(InvalidSignature):
        verify_attestation(att, verifier_verkey=gateway.verkey)


def test_attestation_about_someone_else_is_rejected(gateway, result):
    att = make_attestation(gateway, result)
    with pytest.raises(ChainInvalid, match="not the party in question"):
        verify_attestation(att, verifier_verkey=gateway.verkey, expected_subject_aid="EOther")


def test_a_key_the_attester_chose_for_itself_does_not_help(result):
    """The whole point: the verifying key must come from mode (a), never from the attestation."""
    import secrets

    impostor = Signer.from_seed(GATEWAY_AID, secrets.token_bytes(32))
    honest = Signer.from_seed(GATEWAY_AID, secrets.token_bytes(32))

    att = make_attestation(impostor, result)
    with pytest.raises(InvalidSignature):
        verify_attestation(att, verifier_verkey=honest.verkey)


def test_old_attestation_is_stale(gateway, result):
    old = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = make_attestation(gateway, result, verified_at=old)
    with pytest.raises(StaleSignature, match="ask the attesting party again"):
        verify_attestation(att, verifier_verkey=gateway.verkey)


def test_missing_fields_are_rejected(gateway, result):
    att = make_attestation(gateway, result)
    del att["lei"]
    with pytest.raises(ChainInvalid, match="missing"):
        verify_attestation(att, verifier_verkey=gateway.verkey)
