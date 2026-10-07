"""Canonicalization, digest, and the checks of a vlei-sig/0.3 signature, in the order they fire."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_vlei import Signer, canonicalize, digest_params, sign_request, verify_request
from mcp_vlei.audience import Audience, Recipient
from mcp_vlei.errors import (
    AudienceMismatch,
    DigestMismatch,
    InvalidSignature,
    MissingCredential,
    StaleSignature,
    UnsupportedVersion,
)
from mcp_vlei.replay import MemoryReplayStore, SqliteReplayStore
from mcp_vlei.signing import (
    SIGNATURE_FORMAT,
    precheck_request,
    scope_satisfied,
    statement_bytes,
)

#: The recipient every call here is signed for, and the credential it is signed with.
SERVER = "E" + "R" * 43
URL = "http://gateway.test/mcp"
ME = Recipient(SERVER, (URL,))
CRED = "E" + "C" * 43
T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)
AT_T0 = "2026-10-04T09:00:00.000Z"
LONG_AGO = datetime(2026, 1, 1, tzinfo=timezone.utc)


def sign(signer: Signer, params, *, audience: Audience | None = None, cred: str = CRED, **kwargs):
    return sign_request(signer, "tools/call", params, audience=audience or Audience(SERVER, URL),
                        credential_said=cred, **kwargs)


def verify(signature, params, key, **kwargs):
    kwargs.setdefault("recipient", ME)
    kwargs.setdefault("credential_said", CRED)
    method = kwargs.pop("method", "tools/call")
    return verify_request(signature, method, params, key, **kwargs)


def store() -> MemoryReplayStore:
    """A store whose memory began long ago: the tests are not about restarts unless they say so."""
    return MemoryReplayStore(memory_since=LONG_AGO)


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
# What is signed
# --------------------------------------------------------------------------------------------- #

def test_sign_and_verify_roundtrip(signer: Signer):
    params = {"name": "register_member", "arguments": {"name": "A", "email": "a@example.org"}}
    verify(sign(signer, params), params, signer.verkey)


def test_the_signature_object_carries_the_binding(signer: Signer):
    sig = sign(signer, {"name": "t"}, ts=AT_T0)
    assert sig["v"] == SIGNATURE_FORMAT == "vlei-sig/0.3"
    assert sig["aud"] == {"aid": SERVER, "url": URL}
    assert sig["ts"] == AT_T0 and sig["exp"] == "2026-10-04T09:00:30.000Z"
    assert len(sig["nonce"]) == 22
    assert sig["sig"].startswith("0B") and len(sig["sig"]) == 88


def test_each_signature_has_its_own_nonce(signer: Signer):
    assert sign(signer, {"name": "t"})["nonce"] != sign(signer, {"name": "t"})["nonce"]


def test_the_statement_is_ascii_json_in_rfc8785_order():
    raw = statement_bytes(aid="E" + "A" * 43, aud={"aid": SERVER, "url": URL}, cred=CRED,
                          digest="d", ts=AT_T0, exp="e", nonce="n")
    assert raw.isascii()
    assert raw.decode().startswith('{"aid":"EAAA')
    assert raw.decode().endswith(',"method":"tools/call","nonce":"n","ts":"%s","v":"vlei-sig/0.3"}' % AT_T0)


def test_a_credential_is_required_to_sign(signer: Signer):
    with pytest.raises(ValueError, match="credential_said"):
        sign(signer, {"name": "t"}, cred="")


@pytest.mark.parametrize("bad", ["not-a-said", "E" + "C" * 42, "E" + "C" * 42 + "=", 7])
def test_a_credential_said_that_is_not_qb64_is_refused_before_signing(signer: Signer, bad):
    """Fail fast in the client: every verifier would refuse it (invalid_signature) after a signer
    — possibly a keystore round trip — had already been asked to sign."""
    with pytest.raises(ValueError, match="credential_said"):
        sign(signer, {"name": "t"}, cred=bad)


# --------------------------------------------------------------------------------------------- #
# Tampering — each named by its layer
# --------------------------------------------------------------------------------------------- #

def test_tampered_arguments_report_digest_mismatch(signer: Signer):
    params = {"name": "submit_filing", "arguments": {"amount": 1000}}
    sig = sign(signer, params)
    tampered = {"name": "submit_filing", "arguments": {"amount": 9_999_999}}

    with pytest.raises(DigestMismatch) as exc:
        verify(sig, tampered, signer.verkey)
    assert not exc.value.layer.retryable


def test_tampered_method_reports_invalid_signature(signer: Signer):
    """The method is inside the signed statement but not inside the digest."""
    params = {"name": "t", "arguments": {}}
    with pytest.raises(InvalidSignature):
        verify(sign(signer, params), params, signer.verkey, method="resources/read")


def test_wrong_key_reports_invalid_signature(signer: Signer):
    other = Signer.from_seed(signer.aid, bytes(32))
    with pytest.raises(InvalidSignature):
        verify(sign(signer, {"a": 1}), {"a": 1}, other.verkey)


def test_the_signature_speaks_for_one_credential(signer: Signer):
    """A captured signature presented with another credential of the same signer is refused."""
    params = {"name": "t"}
    with pytest.raises(InvalidSignature):
        verify(sign(signer, params), params, signer.verkey, credential_said="E" + "Z" * 43)


def test_the_signer_is_inside_the_signed_bytes(signer: Signer):
    params = {"name": "t"}
    sig = dict(sign(signer, params), aid="E" + "Q" * 43)
    with pytest.raises(InvalidSignature):
        verify(sig, params, signer.verkey)


def test_a_value_with_no_canonical_form_is_digest_mismatch(signer: Signer):
    params = {"name": "t", "arguments": {"n": 1}}
    sig = sign(signer, params)
    with pytest.raises(DigestMismatch, match="no signature can cover"):
        verify(sig, {"name": "t", "arguments": {"n": 2**60}}, signer.verkey)


# --------------------------------------------------------------------------------------------- #
# The recipient
# --------------------------------------------------------------------------------------------- #

def test_a_call_signed_for_another_server_is_audience_mismatch(signer: Signer):
    params = {"name": "t"}
    sig = sign(signer, params, audience=Audience("E" + "X" * 43, URL))
    with pytest.raises(AudienceMismatch, match="not for this server"):
        verify(sig, params, signer.verkey)


def test_a_call_signed_for_another_endpoint_is_audience_mismatch(signer: Signer):
    params = {"name": "t"}
    sig = sign(signer, params, audience=Audience(SERVER, "http://elsewhere.test/mcp"))
    with pytest.raises(AudienceMismatch,
                       match="signed for http://elsewhere.test/mcp, which is not this server's endpoint"
                       ) as exc:
        verify(sig, params, signer.verkey)
    assert "gateway.test" not in exc.value.message


def test_an_intercepted_signature_re_addressed_to_this_server_is_invalid_signature(signer: Signer):
    """Whoever captured a call made for another server rewrites ``aud`` to name this one. The
    recipient check passes — it reads ``aud`` as sent — but ``aud`` is inside the signed statement,
    so the signature no longer verifies."""
    params = {"name": "t", "arguments": {"a": 1}}
    sig = sign(signer, params, audience=Audience("E" + "X" * 43, "http://elsewhere.test/mcp"))
    readdressed = {**sig, "aud": {"aid": SERVER, "url": URL}}
    precheck_request(readdressed, params, recipient=ME)  # names this server; arguments unaltered
    seen = store()
    with pytest.raises(InvalidSignature, match="does not verify"):
        verify(readdressed, params, signer.verkey, replay_store=seen)
    verify(sig, params, signer.verkey, recipient=Recipient("E" + "X" * 43, ("http://elsewhere.test/mcp",)),
           replay_store=seen)  # the original still verifies where it was meant to go


def test_the_recipient_is_checked_before_the_arguments(signer: Signer):
    """A call replayed to the wrong server is named as that, even if it was also altered."""
    sig = sign(signer, {"a": 1}, audience=Audience(SERVER, "http://elsewhere.test/mcp"))
    with pytest.raises(AudienceMismatch):
        verify(sig, {"a": 2}, signer.verkey)


# --------------------------------------------------------------------------------------------- #
# Format
# --------------------------------------------------------------------------------------------- #

def test_a_v02_signature_is_unsupported_version_not_invalid(signer: Signer):
    params = {"name": "t"}
    digest = digest_params(params)
    legacy = {"aid": signer.aid, "ts": AT_T0, "digest": digest, "alg": "Ed25519",
              "sig": signer.sign(f"tools/call\n{AT_T0}\n{digest}".encode())}
    with pytest.raises(UnsupportedVersion, match="vlei-sig/0.2") as exc:
        verify(legacy, params, signer.verkey, now=T0)
    assert exc.value.aid == signer.aid
    assert not exc.value.layer.retryable


def test_an_unknown_format_is_unsupported_version(signer: Signer):
    sig = dict(sign(signer, {"name": "t"}), v="vlei-sig/9")
    with pytest.raises(UnsupportedVersion, match="vlei-sig/9"):
        verify(sig, {"name": "t"}, signer.verkey)


@pytest.mark.parametrize("change, says", [
    ({"nonce": ""}, "missing nonce"),
    ({"nonce": "short"}, "base64url"),
    ({"nonce": "has spaces in it, twenty-two+"}, "base64url"),
    ({"aud": {"aid": SERVER}}, "exactly aid and url"),
    ({"aud": "http://gateway.test/mcp"}, "exactly aid and url"),
    ({"aud": {"aid": "not-an-aid", "url": URL}}, "aud.aid is not a 44-character CESR"),
    ({"exp": None}, "missing exp"),
    ({"aid": "not-an-aid"}, "CESR"),
    ({"alg": "RSA"}, "algorithm"),
])
def test_a_malformed_v03_signature_is_invalid_signature(signer: Signer, change, says):
    sig = {**sign(signer, {"name": "t"}), **change}
    with pytest.raises(InvalidSignature, match=says):
        verify(sig, {"name": "t"}, signer.verkey)


def test_no_credential_named_is_missing_credential(signer: Signer):
    with pytest.raises(MissingCredential, match="credentialSaid"):
        verify(sign(signer, {"name": "t"}), {"name": "t"}, signer.verkey, credential_said=None)


@pytest.mark.parametrize("bad", [
    123456789012345678901,     # an integer, and beyond I-JSON besides
    float("nan"),               # no canonical form at all
    "\ud800",                   # a lone surrogate: not valid UTF-8
    "E" + "A" * 42,              # 43 characters: one short of a CESR identifier
])
def test_a_malformed_credential_said_is_invalid_signature_not_a_crash(signer: Signer, bad):
    """credential_said reaches statement_bytes -> canonicalize before any key is checked, so a
    caller-supplied value must be refused as a layer, never escape as ValueError or
    UnicodeEncodeError from inside canonicalization."""
    with pytest.raises(InvalidSignature, match="credentialSaid"):
        verify(sign(signer, {"name": "t"}), {"name": "t"}, signer.verkey, credential_said=bad)


# --------------------------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------------------------- #

def test_a_signature_in_its_window_verifies(signer: Signer):
    verify(sign(signer, {"a": 1}, ts=AT_T0), {"a": 1}, signer.verkey, now=T0 + timedelta(seconds=20))


@pytest.mark.parametrize("now, says", [
    (T0 + timedelta(seconds=30 + 61), "expired 61.0s ago"),
    (T0 - timedelta(seconds=61), "ahead of this verifier's clock"),
])
def test_outside_the_window_is_stale(signer: Signer, now, says):
    with pytest.raises(StaleSignature, match=says) as exc:
        verify(sign(signer, {"a": 1}, ts=AT_T0), {"a": 1}, signer.verkey, now=now)
    assert exc.value.layer.retryable, "stale_signature is the one layer worth retrying"


def test_the_clock_tolerance_is_configurable(signer: Signer):
    late = T0 + timedelta(minutes=10)
    verify(sign(signer, {"a": 1}, ts=AT_T0), {"a": 1}, signer.verkey, now=late,
           freshness_seconds=3600)


def test_a_signature_cannot_ask_for_a_long_life(signer: Signer):
    sig = sign(signer, {"a": 1}, ts=AT_T0, lifetime_seconds=3600)
    with pytest.raises(StaleSignature, match="at most 60s"):
        verify(sig, {"a": 1}, signer.verkey, now=T0)


def test_a_signature_that_expires_before_it_was_made_is_stale(signer: Signer):
    sig = sign(signer, {"a": 1}, ts=AT_T0, exp="2026-10-04T08:59:59.000Z")
    with pytest.raises(StaleSignature, match="expires before"):
        verify(sig, {"a": 1}, signer.verkey, now=T0)


@pytest.mark.parametrize("now, says", [
    # Strictly beyond the bound, by less than a second: int() printed "60s ... tolerance 60s".
    (T0 + timedelta(seconds=30 + 60, milliseconds=1), r"expired 60\.1s ago \(tolerance 60s\)"),
    (T0 + timedelta(seconds=30 + 60, milliseconds=500), r"expired 60\.5s ago"),
    (T0 - timedelta(seconds=60, milliseconds=200), r"dated 60\.2s ahead of this verifier's clock, beyond the 60s"),
])
def test_a_refusal_never_states_the_bound_it_exceeded_as_the_amount(signer: Signer, now, says):
    with pytest.raises(StaleSignature, match=says):
        verify(sign(signer, {"a": 1}, ts=AT_T0), {"a": 1}, signer.verkey, now=now)


def test_a_lifetime_just_over_the_longest_is_named_with_its_fraction(signer: Signer):
    sig = sign(signer, {"a": 1}, ts=AT_T0, exp="2026-10-04T09:01:00.400Z")
    with pytest.raises(StaleSignature, match=r"valid for 60\.4s; this verifier accepts at most 60s"):
        verify(sig, {"a": 1}, signer.verkey, now=T0)


@pytest.mark.parametrize("ts, exp, says", [
    ("2026-10-04T09:00:00", "2026-10-04T09:00:30", "signature.ts carries no time zone"),
    (AT_T0, "2026-10-04T09:00:30", "signature.exp carries no time zone"),
    ("yesterday", "2026-10-04T09:00:30.000Z", "signature.ts is not RFC 3339"),
    (AT_T0, "soon", "signature.exp is not RFC 3339"),
])
def test_a_malformed_timestamp_is_invalid_signature_not_stale(signer: Signer, ts, exp, says):
    """No clock makes a timestamp that is not one fresh: re-signing the same way fails the same
    way. A malformed signature object (spec), not the one retryable layer."""
    sig = sign(signer, {"a": 1}, ts=ts, exp=exp)
    with pytest.raises(InvalidSignature, match=says) as exc:
        verify(sig, {"a": 1}, signer.verkey, now=T0)
    assert exc.value.aid == signer.aid
    assert not exc.value.layer.retryable


def test_signing_with_a_malformed_timestamp_is_a_value_error(signer: Signer):
    with pytest.raises(ValueError, match="RFC 3339"):
        sign(signer, {"a": 1}, ts="yesterday")


def test_time_is_checked_before_the_recipient(signer: Signer):
    sig = sign(signer, {"a": 1}, ts=AT_T0, audience=Audience(SERVER, "http://elsewhere.test/mcp"))
    with pytest.raises(StaleSignature):
        verify(sig, {"a": 1}, signer.verkey, now=T0 + timedelta(hours=1))


# --------------------------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------------------------- #

def test_replay_is_rejected(signer: Signer):
    params = {"a": 1}
    sig, seen = sign(signer, params), store()

    verify(sig, params, signer.verkey, replay_store=seen)
    with pytest.raises(StaleSignature, match=r"already presented \(its nonce is spent\)"):
        verify(sig, params, signer.verkey, replay_store=seen)


def test_the_same_call_signed_twice_is_two_calls(signer: Signer):
    """Each signature has its own nonce; a client that repeats a call on purpose re-signs it."""
    params, seen = {"name": "submit_filing", "arguments": {"form": "A1"}}, store()
    verify(sign(signer, params), params, signer.verkey, replay_store=seen)
    verify(sign(signer, params), params, signer.verkey, replay_store=seen)


def test_a_forged_signature_does_not_spend_the_nonce(signer: Signer):
    params, seen = {"a": 1}, store()
    genuine = sign(signer, params)
    forged = dict(genuine, sig="0B" + "A" * 86)
    with pytest.raises(InvalidSignature):
        verify(forged, params, signer.verkey, replay_store=seen)
    verify(genuine, params, signer.verkey, replay_store=seen)


def test_the_claim_lasts_until_the_signature_can_no_longer_verify(signer: Signer):
    class Recording(MemoryReplayStore):
        def claim(self, aid, nonce, expires_at):
            self.last = expires_at
            return super().claim(aid, nonce, expires_at)

    seen = Recording(memory_since=LONG_AGO)
    verify(sign(signer, {"a": 1}, ts=AT_T0), {"a": 1}, signer.verkey, replay_store=seen, now=T0)
    # exp + 2 * skew: one skew past the last instant the time check accepts, so a copy checked
    # just before that instant and claimed just after still finds the claim.
    assert seen.last == T0 + timedelta(seconds=30 + 2 * 60)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_copy_checked_at_the_expiry_boundary_and_claimed_after_it_is_a_replay(
    signer: Signer, kind: str, tmp_path
):
    """The time check accepts until exp + skew inclusive; the claim is made a moment later, on the
    store's own clock. A claim that lapsed at exp + skew was swept by then, and the copy passed."""
    clock = [LONG_AGO]  # each store's memory began long ago
    tick = lambda: clock[0]  # noqa: E731
    seen = (MemoryReplayStore(clock=tick) if kind == "memory"
            else SqliteReplayStore(tmp_path / "replay.sqlite3", clock=tick))
    clock[0] = T0
    params = {"a": 1}
    sig = sign(signer, params, ts=AT_T0)  # exp = T0 + 30 s; the verifier's skew is 60 s

    verify(sig, params, signer.verkey, replay_store=seen, now=T0)

    boundary = T0 + timedelta(seconds=30 + 60)
    clock[0] = boundary + timedelta(milliseconds=1)  # the claim, a millisecond after the check
    try:
        with pytest.raises(StaleSignature, match=r"already presented \(its nonce is spent\)"):
            verify(sig, params, signer.verkey, replay_store=seen, now=boundary)
    finally:
        if kind == "sqlite":
            seen.close()


def test_a_signature_from_before_the_memory_began_is_stale(signer: Signer):
    """After a restart the store has forgotten what it accepted; anything that could have been
    accepted before is refused rather than accepted twice."""
    restarted = MemoryReplayStore(memory_since=T0 + timedelta(seconds=5))
    sig = sign(signer, {"a": 1}, ts=AT_T0)
    with pytest.raises(StaleSignature, match="replay memory began"):
        verify(sig, {"a": 1}, signer.verkey, replay_store=restarted, now=T0 + timedelta(seconds=6))


def test_after_the_horizon_a_fresh_signature_passes(signer: Signer):
    restarted = MemoryReplayStore(memory_since=T0)
    later = T0 + timedelta(seconds=61)
    sig = sign(signer, {"a": 1}, ts="2026-10-04T09:01:01.000Z")
    verify(sig, {"a": 1}, signer.verkey, replay_store=restarted, now=later)


def test_precheck_needs_no_key(signer: Signer):
    """Everything up to the digest is decided without the signer's key state."""
    sig = sign(signer, {"a": 1})
    parsed = precheck_request(sig, {"a": 1}, recipient=ME)
    assert parsed.aid == signer.aid and parsed.aud == {"aid": SERVER, "url": URL}


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


def test_a_string_is_not_a_list_of_its_characters():
    """`"TW"` used to cover a requirement of `["T"]`: the held string was read as a set of letters."""
    ok, _ = scope_satisfied({"regions": ["T"]}, {"regions": "TW"})
    assert ok is False


def test_a_scope_of_the_wrong_type_is_unsatisfied_not_an_exception():
    ok, reason = scope_satisfied({"regions": ["TW"]}, {"regions": 5})
    assert ok is False and "regions" in reason
    ok, _ = scope_satisfied({"maxAmount": 10}, {"maxAmount": True})
    assert ok is False
