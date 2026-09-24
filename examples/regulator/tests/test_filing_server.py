"""filing-server on its own: it trusts the gateway's headers, and contains nothing else.

The server runs for real (uvicorn on 127.0.0.1) and is reached with the SDK 2.2.0 client over
streamable HTTP, so the `Context` it is handed is the SDK's own — the thing a `ctx: Any` parameter
never received.
"""

from __future__ import annotations

import ast
import base64
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx2
import pytest
from conftest import ARGS, REGULATOR, filing, serve
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

REPORT = {
    "tool": "submit_filing",
    "allowed": True,
    "layer": None,
    "identity": {"lei": "984500ABCDEF12345678", "role": "regulatory-filing"},
    "checks": [{"name": "credential_present", "passed": True}],
}
HEADERS = {
    "x-vlei-lei": "984500ABCDEF12345678",
    "x-vlei-role": "regulatory-filing",
    "x-vlei-holder-aid": "EHolderAid",
    "x-vlei-delegate-aid": "EAgentAid",
    "x-vlei-report": base64.urlsafe_b64encode(json.dumps(REPORT).encode()).decode().rstrip("="),
}


@pytest.fixture(autouse=True)
def fresh_filings():
    filing.FILINGS.clear()
    yield
    filing.FILINGS.clear()


@asynccontextmanager
async def connected(headers: Any = None) -> AsyncIterator[Client]:
    async with serve(filing.create_app()) as base:
        async with httpx2.AsyncClient(headers=headers) as http:
            async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
                yield client


async def test_submit_filing_runs_with_gateway_headers_and_the_receipt_says_what_it_received():
    async with connected(HEADERS) as client:
        result = await client.call_tool("submit_filing", ARGS)

    assert result.is_error is False, result.content
    receipt = result.structured_content
    assert receipt["status"] == "ACCEPTED"
    assert receipt["submittedBy"] == {
        "lei": "984500ABCDEF12345678",
        "role": "regulatory-filing",
        "holderAid": "EHolderAid",
        "agentAid": "EAgentAid",
    }
    assert receipt["receivedHeaders"] == {k: v for k, v in HEADERS.items() if k != "x-vlei-report"}
    assert receipt["reportReceived"] is True
    assert result.meta["org.gleif.vlei/report"] == REPORT
    assert json.loads(result.content[0].text) == receipt
    assert filing.FILINGS["984500ABCDEF12345678"][0]["form"] == "A1"


async def test_an_empty_delegate_header_is_a_holder_signing_directly():
    async with connected({**HEADERS, "x-vlei-delegate-aid": ""}) as client:
        result = await client.call_tool("submit_filing", ARGS)

    assert result.is_error is False
    assert "x-vlei-delegate-aid" not in result.structured_content["receivedHeaders"]
    assert result.structured_content["submittedBy"]["agentAid"] == ""


async def test_without_the_gateway_protected_tools_refuse():
    async with connected() as client:
        result = await client.call_tool("submit_filing", ARGS)
        public = await client.call_tool("list_forms", {})

    assert result.is_error is True
    assert "must be reached through the authorization gateway" in result.content[0].text
    assert public.is_error is False


async def test_an_identity_header_sent_twice_is_refused():
    """Two writers of one identity header — say, a client and the gateway — is not an identity."""
    duplicated = [*HEADERS.items(), ("x-vlei-lei", "5493001KJTIIGC8Y1R17")]
    async with connected(duplicated) as client:
        result = await client.call_tool("submit_filing", ARGS)

    assert result.is_error is True
    assert "ambiguous" in result.content[0].text


async def test_an_entity_reads_its_own_filings_and_no_one_elses():
    async with connected(HEADERS) as client:
        await client.call_tool("submit_filing", ARGS)
        own = await client.call_tool("get_filing_status", {"lei": "984500ABCDEF12345678"})
        other = await client.call_tool("get_filing_status", {"lei": "5493001KJTIIGC8Y1R17"})

    assert own.is_error is False
    assert len(own.structured_content["filings"]) == 1
    assert other.is_error is True and "not theirs to read" in other.content[0].text


async def test_a_host_the_gateway_does_not_use_is_refused():
    """DNS-rebinding protection stays on; only the gateway's and local names are admitted."""
    async with serve(filing.create_app()) as base:
        async with httpx2.AsyncClient() as http:
            response = await http.post(
                f"{base}/mcp", headers={"host": "evil.example", "content-type": "application/json",
                                        "accept": "application/json, text/event-stream"},
                content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
            )
    assert response.status_code == 421


def test_the_filing_server_imports_nothing_that_could_verify():
    """The claim of the example, as a test: no vLEI package, no crypto, no way to reach a witness."""
    tree = ast.parse((REGULATOR / "filing-server" / "server.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not imported & {"mcp_vlei", "cryptography", "blake3", "keri", "nacl", "httpx", "httpx2"}
