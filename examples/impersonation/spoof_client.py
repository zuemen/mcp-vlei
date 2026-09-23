"""The same client, three times, changing only what it says about itself.

One binary, one server, one request — `reserve_gpu_quota(50)`. The only variable is `client_info`.
If the protocol could distinguish an honest caller from one claiming to be someone else, the three
runs would differ somewhere other than in what was asked for.

Run::

    python examples/impersonation/spoof_client.py

Nothing here is run against any third party's service. The server is `vendor_server.py`, in this
directory, and the policy it applies is ours.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp import StdioServerParameters
from mcp.client.client import Client
from mcp.types import Implementation

SERVER = Path(__file__).with_name("vendor_server.py")
HOURS = 50

RUNS: list[tuple[str, Implementation | None]] = [
    (
        "honest",
        Implementation(name="zuemen-script", version="0.1.0"),
    ),
    (
        "impersonating",
        # Everything a well-known client would plausibly send. None of it is checked by anything.
        Implementation(
            name="Claude Desktop",
            version="1.2.3",
            description="Anthropic official client",
            websiteUrl="https://claude.ai",
        ),
    ),
    (
        "omitted",
        # Not "no claim": the SDK supplies its own default, so the server receives a name either
        # way. There is no way to decline to identify yourself.
        None,
    ),
]


async def run_once(label: str, client_info: Implementation | None) -> dict[str, Any]:
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    kwargs: dict[str, Any] = {"client_info": client_info} if client_info else {}
    async with Client(params, **kwargs) as client:
        result = await client.call_tool("reserve_gpu_quota", {"hours": HOURS})
    payload = _structured(result)
    return {"label": label, **payload}


def _structured(result: Any) -> dict[str, Any]:
    import json

    content = getattr(result, "structured_content", None)
    if isinstance(content, dict):
        return content
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
    return {}


async def main() -> None:
    print(f"\n  requesting {HOURS} GPU hours, three times, changing only client_info\n")
    header = f"  {'run':<15} {'name as received':<30} {'tier':<9} approved"
    print(header)
    print("  " + "-" * (len(header) - 2))

    results = []
    for label, info in RUNS:
        outcome = await run_once(label, info)
        results.append(outcome)
        received = (outcome.get("clientInfoAsReceived") or {}).get("name", "(none)")
        print(
            f"  {label:<15} {received:<30} {outcome.get('tier', '?'):<9} "
            f"{outcome.get('approved', '?')} hours"
        )

    approved = {r["label"]: r.get("approved") for r in results}
    print(
        f"\n  Same binary, same request. Approved: "
        f"honest {approved.get('honest')}h, impersonating {approved.get('impersonating')}h, "
        f"omitted {approved.get('omitted')}h."
    )
    print(
        "  No layer of the stack observed a difference between these runs, because there was\n"
        "  no verifiable statement to compare against.\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
