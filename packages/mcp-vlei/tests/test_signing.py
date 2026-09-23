"""Canonicalization, digest, and the four checks of verify_request, in the order they fire."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_vlei import Signer, canonicalize, digest_params, sign_request, verify_request
from mcp_vlei.errors import DigestMismatch, InvalidSignature, StaleSignature
from mcp_vlei.signing import ReplayCache, scope_satisfied


# --------------------------------------------------------------------------------------------- #
# RFC 8785
# --------------------------------------------------------------------------------------------- #

def test_canonicalization_sorts_keys_and_omits_whitespace():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonicalization_is_order_independent():
    assert canonicalize({"x": {"b": 1, "a": 2}}) == canonicalize({"x": {"a": 2, "b": 1}})


def test_canonicalization_keeps_utf8_literal():
    assert canonicalize({"n": "臺灣"}) == '{"n":"臺灣"}'.encode("utf-8")


def test_digest_ignores_meta():
    """_meta carries the signature, so including it would be circular."""
    without = digest_params({"name": "t", "arguments": {"a": 1}})
    with_meta = digest_params(
        {"name": "t", "arguments": {"a": 1}, "_meta": {"org.gleif.vlei/signature": {"sig": "x"}}}
    )
    assert without == with_meta


def test_digest_treats_none_and_empty_alike():
    """They mean the same thing on the wire; a signature must not depend on the client library."""
    assert digest_params(None) == digest_params({})


# --------------------------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------------------------- #

def test_sign_and_verify_roundtrip(signer: Signer):
    params = {"name": "register_member", "arguments": {"name": "A", "email": "a@example.org"}}
    sig = sign_request(signer, "tools/call", params)
    verify_request(sig, "tools/call", params, signer.verkey)


def test_signature_is_88_char_cesr(signer: Signer):
    sig = sign_request(signer, "tools/call", {"a": 1})
    assert sig["sig"].startswith("0B") and len(sig["sig"]) == 88
    assert len(signer.verkey) == 44 and signer.verkey.startswith("D")


# --------------------------------------------------------------------------------------------- #
# Tampering — must be digest_mismatch, not a generic signature failure
# --------------------------------------------------------------------------------------------- #

def test_tampered_arguments_report_digest_mismatch(signer: Signer):
    params = {"name": "submit_filing", "arguments": {"amount": 1000}}
    sig = sign_request(signer, "tools/call", params)
    tampered = {"name": "submit_filing", "arguments": {"amount": 9_999_999}}

    with pytest.raises(DigestMismatch) as exc:
        verify_request(sig, "tools/call", tampered, signer.verkey)
    assert exc.value.layer.value == "digest_mismatch"
    assert not exc.value.layer.retryable


def test_tampered_method_reports_invalid_signature(signer: Signer):
    """The method is inside the signed payload but not inside the digest, so this is layer 4."""
    params = {"name": "t", "arguments": {}}
    sig = sign_request(signer, "tools/call", params)
    with pytest.raises(InvalidSignature):
        verify_request(sig, "resources/read", params, signer.verkey)


def test_wrong_key_reports_invalid_signature(signer: Signer, seed: bytes):
    other = Signer.from_seed(signer.aid, bytes(32))
    sig = sign_request(signer, "tools/call", {"a": 1})
    with pytest.raises(InvalidSignature):
        verify_request(sig, "tools/call", {"a": 1}, other.verkey)


# --------------------------------------------------------------------------------------------- #
# Freshness and replay
# --------------------------------------------------------------------------------------------- #

def test_expired_signature_is_stale(signer: Signer):
    params = {"a": 1}
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = sign_request(signer, "tools/call", params, ts=old)

    with pytest.raises(StaleSignature) as exc:
        verify_request(sig, "tools/call", params, signer.verkey)
    assert exc.value.layer.retryable, "stale_signature is the one layer worth retrying"


def test_freshness_window_is_configurable(signer: Signer):
    params = {"a": 1}
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = sign_request(signer, "tools/call", params, ts=old)
    verify_request(sig, "tools/call", params, signer.verkey, freshness_seconds=3600)


def test_replay_is_rejected(signer: Signer):
    params = {"a": 1}
    sig = sign_request(signer, "tools/call", params)
    cache = ReplayCache()

    verify_request(sig, "tools/call", params, signer.verkey, replay_cache=cache)
    with pytest.raises(StaleSignature, match="replay"):
        verify_request(sig, "tools/call", params, signer.verkey, replay_cache=cache)


def test_freshness_checked_before_digest(signer: Signer):
    """Ordering matters: a stale request with altered arguments is reported stale, because the
    freshness check is cheap and a stale request should never reach the digest comparison."""
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = sign_request(signer, "tools/call", {"a": 1}, ts=old)
    with pytest.raises(StaleSignature):
        verify_request(sig, "tools/call", {"a": 2}, signer.verkey)


# --------------------------------------------------------------------------------------------- #
# Scope comparison
# --------------------------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "required,held,ok",
    [
        (None, {}, True),
        ({}, {}, True),
        ({"maxAmount": 1_000_000}, {"maxAmount": 5_000_000}, True),
        ({"maxAmount": 1_000_000}, {"maxAmount": 1_000_000}, True),
        ({"maxAmount": 1_000_000}, {"maxAmount": 500_000}, False),
        ({"maxAmount": 1_000_000}, {}, False),
        ({"forms": ["A1"]}, {"forms": ["A1", "A2"]}, True),
        ({"forms": ["A1", "B9"]}, {"forms": ["A1"]}, False),
        ({"jurisdiction": "TW"}, {"jurisdiction": "TW"}, True),
        ({"jurisdiction": "TW"}, {"jurisdiction": "JP"}, False),
    ],
)
def test_scope_satisfied(required, held, ok):
    assert scope_satisfied(required, held)[0] is ok


def test_scope_failure_explains_itself():
    ok, reason = scope_satisfied({"maxAmount": 1_000_000}, {"maxAmount": 500_000})
    assert not ok
    assert "1000000" in reason and "500000" in reason
