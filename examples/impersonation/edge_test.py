"""What the `clientInfo` fields will accept.

`spoof_client.py` shows that a plausible claim is believed. This asks a narrower question: is
anything about the claim checked at all? Wrong types, extra fields, absurd lengths, a `websiteUrl`
that is not a URL, an icon pointing at a scheme a browser should never follow.

Each row reports whether the value was **rejected** before reaching the server, or **accepted** and
delivered. Rejected is the SDK's validation doing its job; accepted is a field a server could read
and act on.

Read the result carefully, because it is easy to overstate. A field being accepted is not a
vulnerability — the specification says not to trust these fields, so carrying them unchecked is
consistent with what they are for. What the table shows is that **nothing downstream can tell a
careful claim from a careless one**, which is the same gap from a different angle.

Run::

    python examples/impersonation/edge_test.py

Nothing here is run against any third party's service.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp import StdioServerParameters
from mcp.client.client import Client

SERVER = Path(__file__).with_name("vendor_server.py")

CASES: list[tuple[str, dict[str, Any]]] = [
    ("baseline", {"name": "zuemen-script", "version": "0.1.0"}),
    ("wrong type for version", {"name": "a", "version": 123}),
    ("wrong type for name", {"name": ["a", "b"], "version": "1.0"}),
    ("extra unknown field", {"name": "a", "version": "1.0", "trustLevel": "high"}),
    ("very long name (200k chars)", {"name": "A" * 200_000, "version": "1.0"}),
    ("websiteUrl is not a URL", {"name": "a", "version": "1.0", "websiteUrl": "not a url"}),
    ("websiteUrl is javascript:", {"name": "a", "version": "1.0", "websiteUrl": "javascript:alert(1)"}),
    (
        "icon src is a data: URI",
        {"name": "a", "version": "1.0",
         "icons": [{"src": "data:text/html;base64,PHNjcmlwdD4=", "mimeType": "text/html"}]},
    ),
    (
        "icon src is file:",
        {"name": "a", "version": "1.0",
         "icons": [{"src": "file:///etc/passwd", "mimeType": "image/png"}]},
    ),
    ("name is empty", {"name": "", "version": "1.0"}),
    ("version omitted", {"name": "a"}),
    ("name claims another vendor", {"name": "Claude Desktop", "version": "1.2.3"}),
]


async def attempt(case: dict[str, Any]) -> tuple[str, str]:
    """Return (outcome, detail): whether the claim was rejected locally or delivered."""
    from mcp.types import Implementation

    try:
        info = Implementation.model_validate(case)
    except Exception as exc:  # noqa: BLE001 - the type of rejection is the finding
        return "rejected by validation", type(exc).__name__

    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    try:
        async with Client(params, client_info=info) as client:
            result = await client.call_tool("reserve_gpu_quota", {"hours": 1})
    except Exception as exc:  # noqa: BLE001
        return "rejected in transport", type(exc).__name__

    received = _received_name(result)
    return "accepted", f"server saw name={received!r}"


def _received_name(result: Any) -> Any:
    import json

    content = getattr(result, "structured_content", None)
    if not isinstance(content, dict):
        for item in getattr(result, "content", []) or []:
            text = getattr(item, "text", None)
            if text:
                try:
                    content = json.loads(text)
                except json.JSONDecodeError:
                    return "(unparsed)"
                break
    info = (content or {}).get("clientInfoAsReceived") or {}
    name = info.get("name")
    return name if not isinstance(name, str) or len(name) <= 24 else f"{name[:21]}…"


async def main() -> None:
    print("\n  clientInfo field boundaries\n")
    header = f"  {'case':<28} {'outcome':<22} detail"
    print(header)
    print("  " + "-" * (len(header) + 20))

    accepted = 0
    for label, case in CASES:
        outcome, detail = await attempt(case)
        accepted += outcome == "accepted"
        print(f"  {label:<28} {outcome:<22} {detail}")

    print(
        f"\n  {accepted} of {len(CASES)} claims reached the server unchanged.\n"
        "  Accepting them is consistent with what these fields are for — the specification says\n"
        "  not to trust them. The gap is that nothing downstream can tell a careful claim from a\n"
        "  careless one, because there is nothing to compare either against.\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
