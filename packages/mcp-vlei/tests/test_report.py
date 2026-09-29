"""The verification report — what a viewer and an auditor see."""

from __future__ import annotations

import json

import pytest

from mcp_vlei.report import CHECK_ORDER, VerificationReport


def run(report: VerificationReport, *names: str) -> None:
    for name in names:
        report.start(name)
        report.passed(name)


def test_every_check_appears_even_when_not_reached():
    """Absent and not-reached are different statements; the report makes the second one visible."""
    report = VerificationReport(tool="register_member")
    run(report, "credential_present")
    report.start("freshness")
    report.failed("freshness", "stale_signature", "outside the window")

    names = [check["name"] for check in report.as_dict()["checks"]]
    assert names == list(CHECK_ORDER)

    by_name = {check["name"]: check for check in report.as_dict()["checks"]}
    assert by_name["credential_present"]["passed"] is True
    assert by_name["freshness"]["passed"] is False
    assert by_name["authority"]["passed"] is None


def test_the_verdict_names_the_failing_layer():
    report = VerificationReport(tool="submit_filing")
    run(report, *CHECK_ORDER[:6])
    report.start("revocation")
    report.failed("revocation", "revoked", "withdrawn in the issuer's log")

    assert report.allowed is False
    assert report.failure.layer == "revoked"
    assert "REFUSED: revoked" in report.as_text(color=False)
    assert report.as_dict()["layer"] == "revoked"


def test_checks_before_the_failure_are_kept():
    """The point of the report: six things were established before the seventh stopped the call."""
    report = VerificationReport()
    run(report, *CHECK_ORDER[:6])
    report.start("revocation")
    report.failed("revocation", "revoked", "withdrawn")

    passed = [c for c in report.as_dict()["checks"] if c["passed"] is True]
    assert len(passed) == 6


def test_a_clean_run_is_allowed():
    report = VerificationReport(tool="register_member")
    run(report, *CHECK_ORDER)
    report.lei, report.role = "984500ABCDEF12345678", "member-registration"

    assert report.allowed is True
    text = report.as_text(color=False)
    assert "ALLOWED" in text and "984500ABCDEF12345678" in text


def test_skipped_is_recorded_as_a_caveat():
    """"We chose not to check" must not read the same as "we checked"."""
    report = VerificationReport()
    run(report, *CHECK_ORDER[:6])
    report.start("revocation")
    report.skipped("revocation", "no revocation source configured")

    assert report.allowed is True
    assert any("no revocation source" in caveat for caveat in report.as_dict()["caveats"])
    assert "!" in report.as_text(color=False)


# --------------------------------------------------------------------------------------------- #
# What a report may carry
# --------------------------------------------------------------------------------------------- #

def test_the_report_carries_no_credential_content():
    """An ECR names a natural person. The report carries identifiers, never the credential."""
    report = VerificationReport(tool="register_member")
    run(report, *CHECK_ORDER)
    report.lei = "984500ABCDEF12345678"
    report.role = "member-registration"
    report.credential_said = "EM3weUShBeSCTj7iyoWibnx5OTNq2QhEVsySsjA63qbJ"
    report.holder_aid = "EHLragWzyPdQ_JFPHAQXn3IqdeQaVRRqy_iDvMXYwqz4"
    report.delegate_aid = "EPP835IzHST8vWQpLfF84faXo3ygoE45WYv9NdL3EqIo"

    serialized = json.dumps(report.as_dict())
    for forbidden in ("personLegalName", "ACDC10JSON", '"a":{', "-----BEGIN"):
        assert forbidden not in serialized

    identity = report.as_dict()["identity"]
    assert set(identity) == {"lei", "role", "credentialSaid", "holderAid", "delegateAid"}


def test_as_dict_is_json_serializable():
    report = VerificationReport(tool="t")
    run(report, *CHECK_ORDER)
    json.dumps(report.as_dict())


# --------------------------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------------------------- #

def test_no_color_suppresses_escapes(monkeypatch: pytest.MonkeyPatch):
    report = VerificationReport(tool="t")
    run(report, *CHECK_ORDER)

    monkeypatch.setenv("NO_COLOR", "1")
    assert "\033[" not in report.as_text()
    monkeypatch.delenv("NO_COLOR")
    assert "\033[" in report.as_text(color=True)


def test_text_reads_correctly_without_colour():
    """A projector, a colour-blind viewer and a piped log all need the symbol, not the colour."""
    report = VerificationReport(tool="t")
    run(report, *CHECK_ORDER[:2])
    report.start("digest")
    report.failed("digest", "digest_mismatch", "arguments were altered after signing")

    lines = report.as_text(color=False).splitlines()
    failing = next(line for line in lines if "digest_mismatch" in line)
    assert failing.strip()[0] not in ("", " ")


def test_marks_fall_back_when_the_terminal_cannot_encode_them(monkeypatch: pytest.MonkeyPatch):
    """A Windows console on a CJK code page cannot print a check mark; a crash mid-demo is worse."""
    import sys

    from mcp_vlei import report as module

    class Cp950Stdout:
        encoding = "cp950"

    monkeypatch.setattr(sys, "stdout", Cp950Stdout())
    assert module._marks() == module._MARKS_ASCII


def test_a_skipped_check_says_so_in_the_record():
    """A dict that reads `passed: True` for a check nobody ran is how a skipped signature once
    looked verified. A skipped check is marked as skipped, whatever else it carries."""
    report = VerificationReport()
    run(report, *CHECK_ORDER[:6])
    report.start("revocation")
    report.skipped("revocation", "no revocation source configured")
    checks = {c["name"]: c for c in report.as_dict()["checks"]}

    assert checks["revocation"]["skipped"] is True
    assert checks["chain"]["skipped"] is False
