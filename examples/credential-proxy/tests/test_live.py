"""The proxy as Claude starts it — a STDIO subprocess — against a running gateway.

Skipped unless ``VLEI_LIVE=1`` **and** ``VLEI_GATEWAY_URL`` names the gateway: there is no default,
so these tests never pick the live stack by accident. Against the parallel v0.3 stack,
``scripts/v03-stack.sh env`` prints every variable to export (the gateway on :33000, its credentials,
its keri-cli). Every ``VLEI_*`` variable is handed on to the proxy subprocess.

They need the stack's credentials, the operator's LE from ``scripts/bootstrap-regulator.sh`` and,
for the forged profile, ``scripts/bootstrap-forged.sh``.

The revocation test changes the shared environment — it revokes the demo ECR, then re-issues one
(about a minute) — so it also needs ``VLEI_LIVE_REVOKE=1``.

    VLEI_LIVE=1 VLEI_LIVE_REVOKE=1 pytest examples/credential-proxy/tests/test_live.py -v
"""

from __future__ import annotations

import json
import os
import shlex
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

pytestmark = pytest.mark.skipif(
    os.environ.get("VLEI_LIVE") != "1" or not os.environ.get("VLEI_GATEWAY_URL"),
    reason="needs a running stack: set VLEI_LIVE=1 and VLEI_GATEWAY_URL (no default, on purpose)")
K = namespace_keys()
TODAY = today_at(parse_utc_offset("+08:00"))  # the gateway counts days at +08:00
COMPOSE = (shlex.split(os.environ["VLEI_COMPOSE_CMD"]) if os.environ.get("VLEI_COMPOSE_CMD")
           else ["docker", "compose", "-f", str(ROOT / "scripts" / "docker-compose.yml")])
CREDENTIALS = Path(os.environ.get("VLEI_CREDENTIALS_DIR") or ROOT / "credentials")
PLAIN_URL = os.environ.get("VLEI_PLAIN_URL", "http://127.0.0.1:8090/mcp")


def proxy_process(profile: str, log: Path) -> StdioServerParameters:
    env = {k: v for k, v in os.environ.items() if k.startswith("VLEI_") or k == "MCP_VLEI_NAMESPACE"}
    env.update({"VLEI_PROFILE": profile, "VLEI_PROXY_LOG": str(log),
                "PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")})
    if profile == "plain":
        env["VLEI_GATEWAY_URL"] = PLAIN_URL
    return StdioServerParameters(command=sys.executable, args=[str(PROXY_DIR / "proxy.py")], env=env)


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
    if not (CREDENTIALS / "forged" / "env.json").is_file():
        pytest.skip("run scripts/bootstrap-forged.sh first")
    text, result = await call("forged", tmp_path / "relay.log", "enroll_employee", enrol())
    assert result.is_error and text.startswith("unknown_root: "), text
    lines = (tmp_path / "relay.log").read_text(encoding="utf-8").splitlines()
    assert lines[-1].endswith("profile=forged tool=enroll_employee result=refused reason=unknown_root")


@pytest.mark.skipif(os.environ.get("VLEI_LIVE_REVOKE") != "1",
                    reason="revokes the demo ECR, then re-issues it; set VLEI_LIVE_REVOKE=1")
async def test_live_after_revocation_it_is_revoked(tmp_path):
    env = json.loads((CREDENTIALS / "env.json").read_text(encoding="utf-8"))
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


async def test_live_plain_files_and_the_server_knows_only_a_name(tmp_path):
    """The before half, as Claude Desktop runs it: plain profile → the before-mode simulator on
    127.0.0.1:8090. It files — and records only the name the client gave itself."""
    import httpx2
    from mcp.types import Implementation

    params = proxy_process("plain", tmp_path / "relay.log")
    async with Client(params, read_timeout_seconds=120,
                      client_info=Implementation(name="Claude Desktop", version="live-test")) as claude:
        result = await claude.call_tool("enroll_employee", enrol(person="EMP-0951"))
    assert not result.is_error, result.content
    async with httpx2.AsyncClient() as http:
        filings = (await http.get(PLAIN_URL.rsplit("/mcp", 1)[0] + "/ledger")).json()["filings"]
    mine = [f for f in filings if f.get("personRef") == "EMP-0951"]
    assert mine and mine[-1]["filedBy"] == {"declaredClient": "Claude Desktop live-test", "verified": False}


# ------------------------------------------------------------------------------------------- #
# v0.3 on a running gateway: a replay, a call for another endpoint, a v0.2 signature.
# `list_insured` only: it reads, so these probes file nothing.
# ------------------------------------------------------------------------------------------- #

def _agent() -> tuple[Any, dict[str, Any], Any]:
    for path in (ROOT / "examples" / "my-agent", ROOT / "examples" / "regulator"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import gateway_client
    from kli_signer import agent_signer

    env = json.loads((CREDENTIALS / "env.json").read_text(encoding="utf-8"))
    return agent_signer(), env, gateway_client


async def _signed(tool: str, arguments: dict[str, Any], audience: Any = None) -> dict[str, Any]:
    signer, env, gateway_client = _agent()
    url = os.environ["VLEI_GATEWAY_URL"]
    return gateway_client.signed_meta(
        credential=(CREDENTIALS / "ecr.cesr").read_text(encoding="utf-8").strip(), signer=signer,
        tool=tool, arguments=arguments,
        audience=audience or await gateway_client.audience_for(url),
        delegated_aid=env.get("agentAid") or None, credential_said=env["ecrSaid"],
    )


async def test_live_a_replayed_call_is_refused_by_the_gateway():
    _, _, gateway_client = _agent()
    url = os.environ["VLEI_GATEWAY_URL"]
    meta = await _signed("list_insured", {})
    first = await gateway_client.call_through_gateway(url, "list_insured", {}, meta)
    again = await gateway_client.call_through_gateway(url, "list_insured", {}, meta)
    assert first["allowed"] is True, first["text"]
    assert again["layer"] == "stale_signature" and "nonce is spent" in again["text"], again["text"]


async def test_live_a_call_signed_for_another_endpoint_is_audience_mismatch():
    from mcp_vlei.audience import Audience

    _, _, gateway_client = _agent()
    url = os.environ["VLEI_GATEWAY_URL"]
    real = await gateway_client.audience_for(url)
    meta = await _signed("list_insured", {}, audience=Audience(real.aid, "http://elsewhere.invalid/mcp"))
    out = await gateway_client.call_through_gateway(url, "list_insured", {}, meta)
    assert out["layer"] == "audience_mismatch", out["text"]


async def test_live_a_v02_signature_is_unsupported_version():
    from datetime import datetime, timezone

    from mcp_vlei.signing import digest_params

    signer, _, gateway_client = _agent()
    url = os.environ["VLEI_GATEWAY_URL"]
    meta = await _signed("list_insured", {})
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    digest = digest_params({"name": "list_insured", "arguments": {}})
    meta[K.signature] = {"aid": signer.aid, "ts": ts, "digest": digest, "alg": "Ed25519",
                         "sig": signer.sign(f"tools/call\n{ts}\n{digest}".encode())}
    out = await gateway_client.call_through_gateway(url, "list_insured", {}, meta)
    assert out["layer"] == "unsupported_version", out["text"]
