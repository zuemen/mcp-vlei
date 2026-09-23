"""A vendor service that grants quota on the strength of `clientInfo`.

**This server deliberately does what the specification says not to do.**

MCP states that `clientInfo` MUST NOT be used to change behaviour or make security decisions. This
server uses it for exactly that: a caller whose self-reported name contains "claude" is given a
partner-tier allowance, and everyone else is given the default.

The point is not that this policy is unwise — the specification already says so, and no argument is
needed. The point is that **the protocol layer cannot tell the difference**. There is no verified
statement for a server to compare `clientInfo` against, so a server that wants to make this
distinction has nothing else to use, and a server that refuses to make it has nothing to put in its
place. That gap is what `org.gleif.vlei/identity` fills.

Nothing here has been run against any third party's service. The policy is ours, in our own server,
written to be measured.

Run::

    python examples/impersonation/vendor_server.py     # stdio
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import Context, MCPServer

#: A caller matching this gets the partner tier. Case-insensitive substring — the crudeness is the
#: point: any server writing this rule writes something like it.
PARTNER_MARKER = "claude"
PARTNER_HOURS = 100
DEFAULT_HOURS = 1

mcp = MCPServer(name="gpu-vendor", version="0.1.0")


@mcp.tool()
def reserve_gpu_quota(hours: int, ctx: Context) -> dict[str, Any]:
    """Reserve GPU hours. The allowance depends on who the caller says it is.

    Returns what the server actually received in `clientInfo`, so a caller can see precisely what
    its claim looked like from this side — which is the measurement this example exists to take.
    """
    info = _client_info(ctx)
    name = (info.get("name") or "").lower()
    partner = PARTNER_MARKER in name

    limit = PARTNER_HOURS if partner else DEFAULT_HOURS
    approved = min(hours, limit)

    return {
        "requested": hours,
        "approved": approved,
        "tier": "partner" if partner else "default",
        "limit": limit,
        # Everything the protocol gave the server about who is calling.
        "clientInfoAsReceived": info,
        "basis": (
            "clientInfo.name contains "
            f"{PARTNER_MARKER!r}" if partner else "clientInfo.name did not match"
        ),
    }


def _client_info(ctx: Any) -> dict[str, Any]:
    """Whatever the client said about itself, as a plain dict.

    Note what there is no way to do here: check it. There is no signature over it, no issuer, and
    nothing to compare it against. It is a string the caller chose.
    """
    session = getattr(ctx, "session", None)
    params = getattr(session, "client_params", None)
    info = getattr(params, "client_info", None) or getattr(params, "clientInfo", None)
    if info is None:
        return {}
    for attr in ("model_dump", "dict"):
        dump = getattr(info, attr, None)
        if callable(dump):
            return {k: v for k, v in dump(by_alias=True, exclude_none=True).items()}
    return dict(getattr(info, "__dict__", {}))


if __name__ == "__main__":
    import anyio

    anyio.run(mcp.run_stdio_async)
