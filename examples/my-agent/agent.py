"""An agent that presents a vLEI credential.

Claude as the model, the official MCP client for transport, ``VleiClient`` for identity. The skill
and workflow from ``skills/vlei-identity/`` are loaded as the system prompt, so the rules the model
follows are the same text a reader of this repo can audit — not something baked into this file.

Run::

    export ANTHROPIC_API_KEY=...
    python examples/my-agent/agent.py "register Chen Wei-Ting, weiting@example.org.tw"

What this file is responsible for: transport, credentials, and handing the model accurate facts.
What the *model* is responsible for, guided by the skill: deciding whether this agent is entitled
to call a tool, and what to do about each named failure layer.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from anthropic import AsyncAnthropic
from mcp.client.http import http_client
from mcp.client.session import ClientSession

from mcp_vlei import VleiClient
from mcp_vlei.errors import VleiError

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "skills" / "vlei-identity"
CREDENTIALS = ROOT / "credentials"
KEYS = Path(__file__).parent / "keys"

SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8080/mcp")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")


def system_prompt() -> str:
    """The skill and workflow, verbatim.

    Loading them rather than paraphrasing them is the point of task 2: the rules a reviewer reads
    are the rules the model is given.
    """
    return "\n\n".join(
        [
            (SKILLS / "SKILL.md").read_text(encoding="utf-8"),
            (SKILLS / "workflow.md").read_text(encoding="utf-8"),
            "You are acting as an autonomous agent for the legal entity named in your ECR "
            "credential. Follow the workflow above stage by stage. Before calling any tool, state "
            "which stage you are at and what you checked. Never claim a verification passed when "
            "it was skipped or unavailable.",
        ]
    )


def env() -> dict[str, Any]:
    path = CREDENTIALS / "env.json"
    if not path.exists():
        sys.exit(
            "credentials/env.json not found — run `bash scripts/bootstrap-credentials.sh` first."
        )
    return json.loads(path.read_text())


def to_anthropic_tools(tools: Any) -> list[dict[str, Any]]:
    """Convert MCP tool definitions for the Messages API, keeping the requirement visible.

    The requirement is appended to the description on purpose: the model must be able to see, from
    the tool list alone, that a tool needs a role — that is what lets it decide at stage 4 rather
    than by attempting the call.
    """
    out = []
    for tool in getattr(tools, "tools", tools):
        name = getattr(tool, "name", None) or tool["name"]
        description = getattr(tool, "description", "") or tool.get("description", "")
        schema = getattr(tool, "inputSchema", None) or tool.get("inputSchema", {})
        meta = (getattr(tool, "_meta", None) or tool.get("_meta") or {})
        requires = meta.get("org.gleif.vlei/requires")
        if requires:
            description += (
                f"\n\nRequires an {requires['credential']} credential"
                + (f" with role {requires['role']!r}" if requires.get("role") else "")
                + (f", scope {requires['scope']}" if requires.get("scope") else "")
                + "."
            )
        out.append({"name": name, "description": description, "input_schema": schema})
    return out


async def run(task: str) -> None:
    cfg = env()
    claude = AsyncAnthropic()

    async with http_client(SERVER_URL) as (read, write):
        async with ClientSession(read, write) as raw:
            session = VleiClient(
                raw,
                credential=CREDENTIALS / "ecr.cesr",
                key_store=KEYS,
                delegated_aid=cfg.get("agentAid") or cfg["ecrAid"],
                accepted_roots=cfg["acceptedRoots"],
                verifier_url=cfg["verifierUrl"],
                verify_server=True,
                on_unverified_server="stop",
                role=cfg.get("role"),
                scope=cfg.get("scope", {}),
            )

            # Stages 1-2: verify the server before anything is called.
            identity = await session.connect()
            if identity:
                print(f"server verified: LEI {identity.lei} (credential via {identity.source})")
            else:
                print("server presented no organizational identity — unverified")

            # Stage 3: read the requirements.
            tools = await session.list_tools()

            messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
            for _ in range(8):
                response = await claude.messages.create(
                    model=MODEL,
                    max_tokens=2048,
                    system=[{"type": "text", "text": system_prompt(), "cache_control": {"type": "ephemeral"}}],
                    tools=to_anthropic_tools(tools),
                    messages=messages,
                )

                for block in response.content:
                    if block.type == "text" and block.text.strip():
                        print(f"\n{block.text.strip()}")

                if response.stop_reason != "tool_use":
                    return

                messages.append({"role": "assistant", "content": response.content})
                results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    # Stage 4: entitlement, decided here rather than by attempting the call.
                    entitlement = session.entitlement_for(block.name)
                    if not entitlement:
                        print(f"  [stage 4] not calling {block.name}: {entitlement.reason}")
                        results.append({
                            "type": "tool_result", "tool_use_id": block.id, "is_error": True,
                            "content": f"not entitled: {entitlement.reason}",
                        })
                        continue

                    # Stages 5-6.
                    print(f"  [stage 5] calling {block.name}")
                    try:
                        result = await session.call_tool(block.name, block.input)
                        content = _render(result)
                        is_error = bool(getattr(result, "isError", False) or (isinstance(result, dict) and result.get("isError")))
                        print(f"  [stage 6] {'refused' if is_error else 'ok'}: {content.splitlines()[0][:100]}")
                    except VleiError as exc:
                        content, is_error = exc.to_text(), True
                        print(f"  [stage 6] {exc.layer.value}")
                    results.append({
                        "type": "tool_result", "tool_use_id": block.id,
                        "is_error": is_error, "content": content,
                    })

                messages.append({"role": "user", "content": results})


def _render(result: Any) -> str:
    content = getattr(result, "content", None) or (result.get("content") if isinstance(result, dict) else [])
    parts = []
    for item in content:
        text = getattr(item, "text", None) or (item.get("text") if isinstance(item, dict) else None)
        if text:
            parts.append(text)
    return "\n".join(parts) or json.dumps(result, default=str)[:500]


if __name__ == "__main__":
    task = " ".join(sys.argv[1:]) or "List the upcoming events, then register Chen Wei-Ting (weiting@example.org.tw) as a member."
    asyncio.run(run(task))
