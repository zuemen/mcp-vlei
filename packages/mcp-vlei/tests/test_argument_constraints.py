"""A tool may bound the arguments of a call, not only the credential that makes it.

Scope compares what the credential carries with what the tool declares; it does not read the call.
Some rules are about the call: a labour-insurance enrolment may be filed on the start date or up to
ten days ahead, not fifteen. A requirement's `arguments` states such rules as deployment policy; a
call that breaks one is refused as `scope_exceeded`, in the same verification report as every other
check.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from conftest import Ctx  # noqa: E402
from mcp_vlei.signing import argument_rules_problem, arguments_satisfied, parse_utc_offset
from mcp_vlei.testing import World
from test_extension import build, call_next, layer_of, present

TODAY = date(2026, 9, 29)
WINDOW = {"start_date": {"dateWithinDays": [0, 10]}}
ENROL = {"credential": "ECR", "role": "member-registration", "arguments": WINDOW}


@pytest.mark.parametrize("days, ok", [(0, True), (10, True), (5, True), (11, False), (-1, False),
                                      (15, False)])
def test_a_date_must_fall_inside_the_window(days, ok):
    start = (TODAY + timedelta(days=days)).isoformat()
    assert arguments_satisfied(WINDOW, {"start_date": start}, today=TODAY)[0] is ok


@pytest.mark.parametrize("value", [None, "", "2026-13-01", "29/09/2026", 20260929, "2026-09-29T00:00"])
def test_a_missing_or_unreadable_date_is_refused(value):
    arguments = {} if value is None else {"start_date": value}
    ok, reason = arguments_satisfied(WINDOW, arguments, today=TODAY)
    assert not ok and "start_date" in reason


def test_an_unknown_rule_is_refused_rather_than_ignored():
    ok, reason = arguments_satisfied({"start_date": {"somethingNew": 1}}, {"start_date": "x"},
                                     today=TODAY)
    assert not ok and "somethingNew" in reason


def test_no_rules_is_no_constraint():
    assert arguments_satisfied(None, {"anything": 1}, today=TODAY) == (True, "")


@pytest.mark.parametrize("rules", [
    ["start_date"],                                        # not an object of rules
    "start_date",
    {"start_date": {}},                                    # a rule that says nothing
    {"start_date": {"dateWithinDays": None}},
    {"start_date": {"dateWithinDays": "ab"}},
    {"start_date": {"dateWithinDays": ["0", "10"]}},
    {"start_date": {"dateWithinDays": [0, 10, 20]}},
    {"start_date": {"dateWithinDays": [False, True]}},     # a bool is not a number of days
    {"start_date": {"dateWithinDays": [0.5, 10]}},         # refused before the fix too, by range
])
def test_a_malformed_rule_refuses_the_call_and_says_why(rules):
    """A deployment's mistake is a refusal with a reason, never an exception: an exception has no
    failure layer, and in the gateway it becomes a denial nobody can read."""
    ok, reason = arguments_satisfied(rules, {"start_date": TODAY.isoformat()}, today=TODAY)
    assert not ok and reason


@pytest.mark.parametrize("arguments", [["2026-09-29"], "2026-09-29", 5])
def test_arguments_that_are_not_an_object_are_refused_not_raised(arguments):
    ok, reason = arguments_satisfied(WINDOW, arguments, today=TODAY)
    assert not ok and reason


@pytest.mark.parametrize("rules, problem", [
    (WINDOW, None),
    (None, None),
    ({"start_date": {}}, "start_date"),
    ({"start_date": {"dateWithinDays": [0, "10"]}}, "dateWithinDays"),
    ({"start_date": {"somethingNew": 1}}, "somethingNew"),
])
def test_a_rule_can_be_checked_before_any_call(rules, problem):
    """So a deployment can refuse to start with a policy it would refuse every call under."""
    found = argument_rules_problem(rules)
    assert (found is None) if problem is None else (problem in found)


@pytest.mark.parametrize("text, hours", [("+08:00", 8), ("-05:30", -5.5), ("+14:00", 14), ("", None)])
def test_a_utc_offset_is_read_strictly(text, hours):
    offset = parse_utc_offset(text)
    assert (offset is None) if hours is None else offset.utcoffset(None) == timedelta(hours=hours)


@pytest.mark.parametrize("text", ["+8", "UTC+8", "+25:00", "+14:30", "+08:60", "+٠٨:00"])
def test_a_malformed_utc_offset_is_an_error(text):
    with pytest.raises(ValueError):
        parse_utc_offset(text)


@pytest.fixture
def world() -> World:
    return World()


async def test_a_call_outside_the_window_is_refused_in_the_report(world, tmp_path):
    ext = build(world, tmp_path, {"enroll_employee": ENROL}, today=lambda: TODAY)
    later = (TODAY + timedelta(days=15)).isoformat()

    result = await ext.intercept_tool_call(
        present(world, "enroll_employee", {"person_ref": "EMP-0002", "start_date": later}),
        Ctx(), call_next)

    assert layer_of(result) == "scope_exceeded"
    report = ext.records[-1]["report"]
    authority = next(c for c in report["checks"] if c["name"] == "authority")
    assert authority["passed"] is False and "start_date" in authority["detail"]


async def test_a_call_inside_the_window_is_allowed(world, tmp_path):
    ext = build(world, tmp_path, {"enroll_employee": ENROL}, today=lambda: TODAY)

    result = await ext.intercept_tool_call(
        present(world, "enroll_employee", {"person_ref": "EMP-0001",
                                           "start_date": TODAY.isoformat()}),
        Ctx(), call_next)

    assert not result.is_error
