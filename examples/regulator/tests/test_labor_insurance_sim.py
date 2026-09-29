"""labor-insurance-sim on its own: it trusts the gateway's headers, and contains nothing else.

Simulated — not connected to the Bureau of Labor Insurance. The server runs for real (uvicorn on
127.0.0.1) and is reached with the SDK client over streamable HTTP, so the `Context` it is handed is
the SDK's own.
"""

from __future__ import annotations

import ast
import base64
import json
from contextlib import asynccontextmanager
from datetime import date
from typing import Any, AsyncIterator

import httpx2
import pytest
from conftest import ARGS, REGULATOR, labor, serve
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

LEI = "984500ABCDEF12345678"
REPORT = {
    "tool": "enroll_employee",
    "allowed": True,
    "layer": None,
    "identity": {"lei": LEI, "role": "labor-insurance-filing"},
    "checks": [{"name": "credential_present", "passed": True}],
}
HEADERS = {
    "x-vlei-lei": LEI,
    "x-vlei-role": "labor-insurance-filing",
    "x-vlei-holder-aid": "EHolderAid",
    "x-vlei-delegate-aid": "EAgentAid",
    "x-vlei-report": base64.urlsafe_b64encode(json.dumps(REPORT).encode()).decode().rstrip("="),
    "x-vlei-namespace": "org.gleif.vlei",
}


@pytest.fixture(autouse=True)
def fresh_records():
    labor.INSURED.clear()
    yield
    labor.INSURED.clear()


@asynccontextmanager
async def connected(headers: Any = None) -> AsyncIterator[Client]:
    async with serve(labor.create_app()) as base:
        async with httpx2.AsyncClient(headers=headers) as http:
            async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
                yield client


async def test_an_enrolment_runs_with_gateway_headers_and_the_receipt_says_what_it_received():
    async with connected(HEADERS) as client:
        result = await client.call_tool("enroll_employee", ARGS)

    assert result.is_error is False, result.content
    receipt = result.structured_content
    assert receipt["simulated"] == "Simulated — not connected to the Bureau of Labor Insurance"
    assert receipt["employer"] == "00000000"
    assert receipt["record"]["personRef"] == "EMP-0001"
    assert receipt["record"]["status"] == "insured"
    assert receipt["record"]["filedBy"] == {"lei": LEI, "role": "labor-insurance-filing",
                                            "holderAid": "EHolderAid", "agentAid": "EAgentAid"}
    assert receipt["receivedHeaders"] == {k: v for k, v in HEADERS.items()
                                          if k not in ("x-vlei-report", "x-vlei-namespace")}
    assert result.meta["org.gleif.vlei/report"] == REPORT


async def test_an_employer_lists_only_its_own_insured():
    async with connected(HEADERS) as client:
        await client.call_tool("enroll_employee", ARGS)
    labor.INSURED["11111111"] = {"EMP-0099": {"personRef": "EMP-0099", "status": "insured"}}
    async with connected(HEADERS) as client:
        listed = await client.call_tool("list_insured", {})

    assert listed.is_error is False
    body = listed.structured_content
    assert body["employer"]["unifiedBusinessNumber"] == "00000000"
    assert [r["personRef"] for r in body["insured"]] == ["EMP-0001"]


async def test_an_entity_with_no_unified_business_number_is_refused():
    async with connected({**HEADERS, "x-vlei-lei": "5493001KJTIIGC8Y1R17"}) as client:
        result = await client.call_tool("list_insured", {})
    assert result.is_error is True and "registeredAs" in result.content[0].text


async def test_only_fictitious_person_references_are_accepted():
    """Nothing shaped like a national ID number enters this simulation."""
    async with connected(HEADERS) as client:
        for person_ref in ("A123456789", "a123456789", "F223456789", "EMP-1", "EMP-00001",
                           "Chen Wei-Ting", "EMP-０００１", "EMP-٠٠٠١"):
            result = await client.call_tool("enroll_employee", {**ARGS, "person_ref": person_ref})
            assert result.is_error is True and "EMP-0001" in result.content[0].text, person_ref
    assert labor.INSURED == {}


async def test_withdrawal_and_salary_adjustment_act_on_an_enrolled_employee():
    async with connected(HEADERS) as client:
        await client.call_tool("enroll_employee", ARGS)
        adjusted = await client.call_tool("adjust_insured_salary",
                                          {"person_ref": "EMP-0001", "salary_grade": 5})
        withdrawn = await client.call_tool("withdraw_employee",
                                           {"person_ref": "EMP-0001",
                                            "end_date": date.today().isoformat()})
        again = await client.call_tool("withdraw_employee",
                                       {"person_ref": "EMP-0001",
                                        "end_date": date.today().isoformat()})

    assert adjusted.structured_content["record"]["salaryGrade"] == 5
    assert withdrawn.structured_content["record"]["status"] == "withdrawn"
    assert again.is_error is True and "not enrolled" in again.content[0].text


async def test_enrolling_the_same_person_again_replaces_the_record():
    async with connected(HEADERS) as client:
        await client.call_tool("enroll_employee", ARGS)
        second = await client.call_tool("enroll_employee", {**ARGS, "salary_grade": 7})
    assert second.is_error is False
    assert second.structured_content["note"] == "already enrolled; record replaced"
    assert labor.INSURED["00000000"]["EMP-0001"]["salaryGrade"] == 7


async def test_an_empty_delegate_header_is_a_holder_signing_directly():
    async with connected({**HEADERS, "x-vlei-delegate-aid": ""}) as client:
        result = await client.call_tool("enroll_employee", ARGS)
    assert result.is_error is False
    assert "x-vlei-delegate-aid" not in result.structured_content["receivedHeaders"]


async def test_without_the_gateway_every_tool_refuses():
    async with connected() as client:
        enrolled = await client.call_tool("enroll_employee", ARGS)
        listed = await client.call_tool("list_insured", {})
    for result in (enrolled, listed):
        assert result.is_error is True
        assert "must be reached through the authorization gateway" in result.content[0].text


async def test_an_identity_header_sent_twice_is_refused():
    """Two writers of one identity header — say, a client and the gateway — is not an identity."""
    duplicated = [*HEADERS.items(), ("x-vlei-lei", "5493001KJTIIGC8Y1R17")]
    async with connected(duplicated) as client:
        result = await client.call_tool("enroll_employee", ARGS)
    assert result.is_error is True
    assert "ambiguous" in result.content[0].text


async def test_a_host_the_gateway_does_not_use_is_refused():
    """DNS-rebinding protection stays on; only the gateway's and local names are admitted."""
    async with serve(labor.create_app()) as base:
        async with httpx2.AsyncClient() as http:
            response = await http.post(
                f"{base}/mcp", headers={"host": "evil.example", "content-type": "application/json",
                                        "accept": "application/json, text/event-stream"},
                content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            )
    assert response.status_code == 421


def test_the_simulator_imports_nothing_that_could_verify():
    """The claim of the example, as a test: no vLEI package, no crypto, no way to reach a witness."""
    tree = ast.parse((REGULATOR / "labor-insurance-sim" / "server.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not imported & {"mcp_vlei", "cryptography", "blake3", "keri", "nacl", "httpx", "httpx2"}


def test_every_tool_says_it_is_a_simulation():
    for tool in labor.mcp._tool_manager.list_tools():
        assert "Simulated" in (tool.description or ""), tool.name
