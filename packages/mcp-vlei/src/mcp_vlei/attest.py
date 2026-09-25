"""Attestations — mode (b), the "letter of confirmation".

One party that has already verified an identity signs a statement saying so, and a second party
trusts that statement after checking the first party's signature. This is how one government office
writes to another to confirm a record, and it is what turns inter-agency lookup into a verifiable
agent call rather than a form in the post.

The transitivity is real and is stated plainly: accepting an attestation is trusting the attesting
party's *judgment*, not a credential you checked yourself. :func:`verify_attestation` therefore
requires the attesting party's own verification key to have been established independently — it will
not take the attestation's word for who signed it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ChainInvalid, InvalidSignature, StaleSignature
from .signing import Signer, canonicalize, cesr_decode_signature, cesr_decode_verkey
from .verifier import VerificationResult

__all__ = ["make_attestation", "verify_attestation", "Attestation", "DEFAULT_MAX_AGE_SECONDS"]

#: How old an attestation may be before a relying party should re-ask. Much longer than a request
#: signature's freshness window: an attestation is a statement about a past verification, not a
#: live authorization, and the point of mode (b) is to avoid a round trip per call.
DEFAULT_MAX_AGE_SECONDS = 3600


def _signable(body: dict[str, Any]) -> bytes:
    """Everything except the signature itself, canonicalized."""
    return canonicalize({k: v for k, v in body.items() if k != "sig"})


#: How far ahead of this clock a `verifiedAt` may be before it is refused.
DEFAULT_CLOCK_SKEW_SECONDS = 60


@dataclass
class Attestation:
    verifier_aid: str
    subject_aid: str
    lei: str
    verified_at: str
    role: str | None = None
    credential_said: str | None = None

    def to_wire(self, sig: str) -> dict[str, Any]:
        body = {
            "verifierAid": self.verifier_aid,
            "subjectAid": self.subject_aid,
            "lei": self.lei,
            "verifiedAt": self.verified_at,
        }
        if self.role:
            body["role"] = self.role
        if self.credential_said:
            body["credentialSaid"] = self.credential_said
        body["sig"] = sig
        return body


def make_attestation(
    signer: Signer,
    result: VerificationResult,
    *,
    verified_at: str | None = None,
) -> dict[str, Any]:
    """Sign a statement that ``signer`` verified ``result``.

    Only ever called by a party that actually performed the verification. A gateway that has just
    validated a caller's chain is the canonical caller; it already holds everything the statement
    asserts.
    """
    att = Attestation(
        verifier_aid=signer.aid,
        subject_aid=result.aid,
        lei=result.lei,
        role=result.role,
        credential_said=result.credential_said,
        verified_at=verified_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    unsigned = att.to_wire(sig="")
    del unsigned["sig"]
    return att.to_wire(sig=signer.sign(_signable(unsigned)))


def verify_attestation(
    attestation: dict[str, Any],
    *,
    verifier_verkey: str | Sequence[str],
    expected_subject_aid: str | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    now: datetime | None = None,
    threshold: int = 1,
) -> VerificationResult:
    """Check an attestation and return what it establishes.

    ``verifier_verkey`` must come from the attesting party's own verified identity — established
    through mode (a) — and never from the attestation itself. That is the whole safety property:
    an attestation from an unverified party is worth nothing, and this signature would happily
    verify under a key the attester chose for itself.
    """
    required = ("verifierAid", "subjectAid", "lei", "verifiedAt", "sig")
    missing = [k for k in required if not attestation.get(k)]
    if missing:
        raise ChainInvalid(f"attestation is missing {', '.join(missing)}")

    if expected_subject_aid and attestation["subjectAid"] != expected_subject_aid:
        raise ChainInvalid(
            f"attestation is about {attestation['subjectAid']}, "
            f"not the party in question ({expected_subject_aid})"
        )

    try:
        verified_at = datetime.fromisoformat(attestation["verifiedAt"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ChainInvalid("verifiedAt is not RFC 3339") from exc

    if verified_at.tzinfo is None:
        raise ChainInvalid("verifiedAt carries no time zone")
    now = now or datetime.now(timezone.utc)
    age = now - verified_at
    if age < -timedelta(seconds=DEFAULT_CLOCK_SKEW_SECONDS):
        # A verification that has not happened yet never ages past the limit, so a far-future
        # `verifiedAt` would make an attestation valid indefinitely.
        raise StaleSignature(
            f"attestation claims a verification {int(-age.total_seconds())}s in the future"
        )
    if age > timedelta(seconds=max_age_seconds):
        raise StaleSignature(
            f"attestation describes a verification {int(age.total_seconds())}s old, "
            f"beyond the {max_age_seconds}s limit; ask the attesting party again"
        )

    if threshold > 1:
        # An attestation carries one signature. An attester whose keys require several has not
        # attested with one of them, whoever holds it — the same rule a request signer meets.
        raise InvalidSignature(
            f"the attesting party's keys require {threshold} signatures; an attestation carries "
            "one",
            aid=attestation["verifierAid"],
        )
    body = {k: v for k, v in attestation.items() if k != "sig"}
    keys = [verifier_verkey] if isinstance(verifier_verkey, str) else list(verifier_verkey)
    try:
        signature = cesr_decode_signature(attestation["sig"])
    except (ValueError, TypeError) as exc:
        raise InvalidSignature("attestation signature is not valid CESR",
                               aid=attestation["verifierAid"]) from exc
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(key)).verify(
                signature, _signable(body)
            )
            break
        except _CryptoInvalidSignature:
            continue
    else:
        raise InvalidSignature(
            "attestation signature does not verify under the attesting party's key",
            aid=attestation["verifierAid"],
        )

    return VerificationResult(
        aid=attestation["subjectAid"],
        lei=attestation["lei"],
        role=attestation.get("role"),
        credential_said=attestation.get("credentialSaid"),
        holder_aid=attestation["subjectAid"],
        source="attestation",
        # Whose judgment this rests on. A relying party that accepted an attestation did not check
        # the credential; it trusted a party that says it did, and the record has to name them.
        attested_by=attestation["verifierAid"],
        revocation_checked=False,
        signatures_checked=False,
    )
