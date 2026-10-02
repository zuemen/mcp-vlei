"""The proxy as Claude starts it — a STDIO subprocess — against the running gateway on :3000.

Skipped unless ``VLEI_LIVE=1``: these need the stack from ``scripts/reset-demo.sh``, the operator's
LE from ``scripts/bootstrap-regulator.sh`` and, for the forged profile, ``scripts/bootstrap-forged.sh``.

The revocation test changes the shared environment — it revokes the demo ECR, then re-issues one
(about a minute) — so it also needs ``VLEI_LIVE_REVOKE=1``.

    VLEI_LIVE=1 VLEI_LIVE_REVOKE=1 pytest examples/credential-proxy/tests/test_live.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import PROXY_DIR, ROOT
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from mcp_vlei.namespace import keys as namespace_keys
from mcp_vlei.signing import parse_utc_offset, today_at

pytestmark = pytest.mark.skipif(os.environ.get("VLEI_LIVE") != "1",
                                reason="needs the running stack; set VLEI_LIVE=1")
K = namespace_keys()
TODAY = today_at(parse_utc_offset("+08:00"))  # the gateway counts days at +08:00
COMPOSE = ["docker", "compose", "-f", str(ROOT / "scripts" / "docker-compose.yml")]


def proxy_process(profile: str, log: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(PROXY_DIR / "proxy.py")],
        env={"VLEI_PROFILE": profile, "VLEI_PROXY_LOG": str(log),
             "PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
    )


async def call(profile: str, log: Path, tool: str, arguments: dict[str, Any]) -> tuple[str, Any]:
    async with Client(proxy_process(profile, log), read_timeout_seconds=120) as claude:
        tools = {t.name for t in (await claude.list_tools()).tools}
        assert tool in tools, f"proxy exposed {sorted(tools)}; instructions: {claude.instructions}"
        result = await claude.call_tool(tool, arguments)
    text = next(b.text for b in result.content if getattr(b, "text", None))
    return text, result


def enrol(days: int = 0, person: str = "EMP-0901") -> dict[str, Any]:
    return {"person_ref": person, "start_date": (TODAY + timedelta(days=days)).isoformat(),
            "salary_grade": 3}


async def test_live_the_gateway_is_verified_and_its_four_tools_carry_requirements(tmp_path):
    async with Client(proxy_process("demo", tmp_path / "relay.log"), read_timeout_seconds=120) as claude:
        tools = {t.name: t for t in (await claude.list_tools()).tools}
        instructions = claude.instructions or ""
    assert "verified before connecting" in instructions and "984500LABORSIM000054" in instructions
    assert set(tools) == {"list_insured", "enroll_employee", "withdraw_employee", "adjust_insured_salary"}
    assert tools["adjust_insured_salary"].meta[K.requires]["role"] == "labor-insurance-payroll"
    assert "職務角色為 labor-insurance-payroll" in tools["adjust_insured_salary"].description


async def test_live_demo_enrolment_passes(tmp_path):
    text, result = await call("demo", tmp_path / "relay.log", "enroll_employee", enrol())
    assert not result.is_error, text
    assert result.meta[K.report]["allowed"] is True


async def test_live_demo_salary_adjustment_is_role_mismatch(tmp_path):
    text, result = await call("demo", tmp_path / "relay.log", "adjust_insured_salary",
                              {"person_ref": "EMP-0901", "salary_grade": 5})
    assert result.is_error and text.startswith("role_mismatch: "), text


async def test_live_demo_fifteen_days_ahead_is_scope_exceeded(tmp_path):
    text, result = await call("demo", tmp_path / "relay.log", "enroll_employee", enrol(15))
    assert result.is_error and text.startswith("scope_exceeded: "), text


async def test_live_forged_enrolment_is_unknown_root(tmp_path):
    if not (ROOT / "credentials" / "forged" / "env.json").is_file():
        pytest.skip("run scripts/bootstrap-forged.sh first")
    text, result = await call("forged", tmp_path / "relay.log", "enroll_employee", enrol())
    assert result.is_error and text.startswith("unknown_root: "), text
    lines = (tmp_path / "relay.log").read_text(encoding="utf-8").splitlines()
    assert lines[-1].endswith("profile=forged tool=enroll_employee result=refused reason=unknown_root")


@pytest.mark.skipif(os.environ.get("VLEI_LIVE_REVOKE") != "1",
                    reason="revokes the demo ECR, then re-issues it; set VLEI_LIVE_REVOKE=1")
async def test_live_after_revocation_it_is_revoked(tmp_path):
    env = json.loads((ROOT / "credentials" / "env.json").read_text(encoding="utf-8"))
    subprocess.run(
        [*COMPOSE, "exec", "-T", "keri-cli", "kli", "vc", "revoke", "--name", "le", "--alias", "le",
         "--registry-name", "leRegistry", "--said", env["ecrSaid"], "--send", env["ecrAid"]],
        check=True, capture_output=True, timeout=120,
    )
    try:
        # The withdrawal is read back from the witness; give it the time the console allows.
        deadline = time.monotonic() + 30
        while True:
            text, result = await call("demo", tmp_path / "relay.log", "enroll_employee", enrol())
            if text.startswith("revoked: ") or time.monotonic() > deadline:
                break
        assert result.is_error and text.startswith("revoked: "), text
    finally:
        subprocess.run(["bash", str(ROOT / "scripts" / "bootstrap-credentials.sh"), "--reissue"],
                       check=True, capture_output=True, timeout=600)
    # And the re-issued credential is presented by the same profile, without restarting anything.
    text, result = await call("demo", tmp_path / "relay.log", "enroll_employee", enrol())
    assert not result.is_error, text
