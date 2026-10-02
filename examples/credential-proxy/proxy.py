"""Credential proxy: Claude on one side over STDIO, the labour-insurance gateway on the other.

Claude Desktop and Claude Code start local MCP servers over STDIO and know nothing about vLEI. This
one stands between them and the gateway and does four things, and nothing else:

1. **Verifies the gateway first.** It reads the operator's LE credential from the gateway's
   ``/.well-known/vlei`` and verifies the chain to an accepted root, and the issuers' transaction
   event logs for revocation, before a single tool is listed. If that fails, no tools are listed,
   nothing is signed or sent, and the reason is in the server's instructions and the log.
2. **Relays the tool list as it is,** ``_meta`` requirements included, adding one sentence in
   Chinese and English on the role each tool requires.
3. **Signs every call** in the KERI keystore with ``kli sign``, as the agent's delegated AID. The
   private key never leaves the keystore. The ``credential``, ``credentialSaid``,
   ``delegatedAid`` and ``signature`` keys are attached under the extension's namespace.
4. **Returns what the gateway answered.** A refusal's first line is its failure layer
   (``revoked: …``), in the gateway's own words.

Which identity it presents is fixed when it starts, by ``VLEI_PROFILE`` (``demo`` or ``forged``).
No tool changes it: the model must not be able to choose whose credential it acts under.

Each relayed call is logged as one line: time, profile, tool, result and failure layer. The
credential and the arguments are never logged.

Simulated: the labour-insurance system behind the gateway is not connected to the Bureau of Labor
Insurance. Every identity is fictional.

    VLEI_PROFILE=demo python examples/credential-proxy/proxy.py      # what Claude starts
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol, TextIO
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (ROOT / "packages" / "mcp-vlei" / "src", ROOT / "examples" / "my-agent"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import httpx  # noqa: E402
import httpx2  # noqa: E402
from mcp import types  # noqa: E402
from mcp.client.client import Client  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402

from mcp_vlei import VleiCapability, VleiClient  # noqa: E402
from mcp_vlei.errors import VleiError  # noqa: E402
from mcp_vlei.namespace import Keys  # noqa: E402
from mcp_vlei.namespace import keys as namespace_keys  # noqa: E402
from mcp_vlei.verifier import VerificationResult  # noqa: E402

DEFAULT_GATEWAY = "http://localhost:3000/mcp"
DEFAULT_WITNESS = "http://localhost:5642"
DEFAULT_LOG = HERE / "relay.log"
SIMULATED = "Simulated — not connected to the Bureau of Labor Insurance"


# ------------------------------------------------------------------------------------------- #
# Profile: whose credential, fixed at start
# ------------------------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Profile:
    """Everything presented on a call, read from one credentials folder."""

    name: str
    credential: Path          #: the CESR stream presented on every protected call
    credential_said: str      #: which credential in that stream is the one presented
    delegated_aid: str | None  #: the agent's delegated AID; None when the holder signs directly
    keystore: str             #: the KERI keystore and alias `kli sign` uses
    lei: str
    entity: str
    role: str


def profile_folders(root: Path = ROOT) -> dict[str, Path]:
    return {"demo": root / "credentials", "forged": root / "credentials" / "forged"}


def load_profile(name: str, root: Path = ROOT) -> Profile:
    """The profile's identity as the bootstrap scripts left it. Raises on anything missing."""
    folders = profile_folders(root)
    if name not in folders:
        raise ValueError(f"VLEI_PROFILE must be one of {', '.join(sorted(folders))}; got {name!r}")
    folder = folders[name]
    script = "bootstrap-forged.sh" if name == "forged" else "bootstrap-credentials.sh"
    for path in (folder / "env.json", folder / "ecr.cesr"):
        if not path.is_file():
            raise FileNotFoundError(f"{path} not found: run scripts/{script} first")
    env = json.loads((folder / "env.json").read_text(encoding="utf-8"))
    agent = env.get("agentAid") or None
    return Profile(
        name=name,
        credential=folder / "ecr.cesr",
        credential_said=env["ecrSaid"],
        delegated_aid=agent,
        keystore=env.get("agentKeystore") or ("agent" if agent else "ecr"),
        lei=env.get("lei", ""),
        entity=env.get("leName", ""),
        role=env.get("role", ""),
    )


def accepted_roots(root: Path = ROOT, environ: dict[str, str] | None = None) -> list[str]:
    """The roots the gateway's LE must chain to: VLEI_ACCEPTED_ROOTS, else the demo chain's."""
    env = os.environ if environ is None else environ
    roots = [r.strip() for r in env.get("VLEI_ACCEPTED_ROOTS", "").split(",") if r.strip()]
    if roots:
        return roots
    main = root / "credentials" / "env.json"
    return list(json.loads(main.read_text(encoding="utf-8")).get("acceptedRoots", [])) if main.is_file() else []


def witness_url(root: Path = ROOT, environ: dict[str, str] | None = None) -> str:
    """Where the issuers' logs are read: VLEI_WITNESS_URL, else the one ``scripts/.env`` sets.

    The scripts read ``scripts/.env`` for machine-local witness ports (Windows reserves 5642-5644 on
    some machines). Only that one key is read from it; nothing else in the file is loaded.
    """
    env = os.environ if environ is None else environ
    if env.get("VLEI_WITNESS_URL", "").strip():
        return env["VLEI_WITNESS_URL"].strip()
    dotenv = root / "scripts" / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, _, value = line.strip().partition("=")
            if key == "VLEI_WITNESS_URL" and value.strip():
                return value.strip().strip('"').strip("'")
    return DEFAULT_WITNESS


def label_for(lei: str, root: Path = ROOT) -> str:
    """A name for an LEI, from this machine's own bootstrap output, marked as such.

    An LE credential carries the LEI and nothing else; the name belongs to the LEI record, and these
    test LEIs have none. So the name shown is the one the bootstrap scripts recorded locally.
    """
    for env_path in sorted((root / "credentials").glob("**/env.json")):
        try:
            env = json.loads(env_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if env.get("lei") == lei and env.get("leName"):
            return env["leName"]
    return ""


# ------------------------------------------------------------------------------------------- #
# What Claude reads: the tool list, with one sentence added
# ------------------------------------------------------------------------------------------- #

def requirement_sentence(requires: dict[str, Any]) -> str:
    """One sentence, Chinese then English, on what a tool's ``requires`` asks of the caller."""
    credential = str(requires.get("credential") or "ECR")
    role = requires.get("role")
    article = "an" if credential[:1] in "AEIOU" else "a"
    zh = [f"需要 {credential} 憑證" + (f"，職務角色為 {role}" if role else "（任何職務角色）")]
    en = [f"Requires {article} {credential} credential" + (f" with the role {role}" if role else " (any role)")]
    for field, rule in (requires.get("arguments") or {}).items():
        window = (rule or {}).get("dateWithinDays") if isinstance(rule, dict) else None
        if isinstance(window, list) and len(window) == 2:
            low, high = window
            if low == 0:
                zh.append(f"{field} 須在今天到 {high} 天後之間")
                en.append(f"{field} from today to {high} days ahead")
            else:
                zh.append(f"{field} 須在 {low} 到 {high} 天後之間")
                en.append(f"{field} {low} to {high} days ahead")
    if requires.get("scope"):
        zh.append("並受授權範圍限制")
        en.append("within the scope it states")
    return "vLEI：" + "；".join(zh) + "。 / vLEI: " + "; ".join(en) + "."


def describe(tool: types.Tool, requires_key: str) -> types.Tool:
    """The tool as the gateway listed it, ``_meta`` untouched, with the sentence appended."""
    requires = (tool.meta or {}).get(requires_key)
    if not isinstance(requires, dict):
        return tool
    sentence = requirement_sentence(requires)
    description = f"{tool.description}\n\n{sentence}" if tool.description else sentence
    return tool.model_copy(update={"description": description})


# ------------------------------------------------------------------------------------------- #
# The log: one line per relayed call, never the credential, never the arguments
# ------------------------------------------------------------------------------------------- #

_SAFE = re.compile(r"[^A-Za-z0-9_.:-]")


def _token(value: Any, limit: int = 64) -> str:
    """A log field that cannot break the line or forge another: tool names come from the model."""
    text = _SAFE.sub("?", str(value))[:limit]
    return text or "-"


class RelayLog:
    def __init__(self, path: Path | None = DEFAULT_LOG, stream: TextIO | None = None) -> None:
        self.path = path
        self.stream = sys.stderr if stream is None else stream

    def _write(self, line: str) -> None:
        print(line, file=self.stream, flush=True)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def call(self, *, profile: str, tool: str, result: str, reason: str | None = None) -> str:
        when = datetime.now().astimezone().isoformat(timespec="seconds")
        line = (f"{when} profile={_token(profile)} tool={_token(tool)} "
                f"result={_token(result)} reason={_token(reason or '-')}")
        self._write(line)
        return line

    def event(self, text: str) -> None:
        """Start-up facts: whether and how the gateway was verified. Identifiers only."""
        when = datetime.now().astimezone().isoformat(timespec="seconds")
        self._write(f"{when} {text}")


# ------------------------------------------------------------------------------------------- #
# The far side: the gateway
# ------------------------------------------------------------------------------------------- #

class GatewayLike(Protocol):
    async def published(self) -> dict[str, Any]: ...
    async def list_tools(self) -> types.ListToolsResult: ...
    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        meta: dict[str, Any] | None = None) -> types.CallToolResult: ...


class Gateway:
    """The gateway's MCP endpoint, one connection per request, and its published LE.

    One connection per request: a refused call ends as an HTTP 403 on the ``tools/call`` POST, which
    the SDK surfaces as a transport error. A fresh session per call keeps one refusal from touching
    the next call, and survives the gateway being restarted between takes.
    """

    def __init__(self, url: str, *, roots: list[str] | None = None, timeout: float = 30.0,
                 keys: Keys | None = None) -> None:
        self.url = url
        self.roots = list(roots or [])
        self.timeout = timeout
        self.keys = keys or namespace_keys()

    @property
    def well_known_url(self) -> str:
        """RFC 8615: at the origin, whatever path the MCP endpoint has."""
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, "/.well-known/vlei", "", ""))

    async def published(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.get(self.well_known_url)
        if response.status_code != 200:
            raise LookupError(f"{self.well_known_url} answered HTTP {response.status_code}")
        document = response.json()
        if not isinstance(document, dict) or not document.get("credential"):
            raise LookupError(f"{self.well_known_url} publishes no credential")
        return document

    def _client(self, http: httpx2.AsyncClient) -> Client:
        # Declares the extension at initialize, as a client presenting a credential should.
        capability = VleiCapability(presents=["ECR"], accepted_roots=self.roots or None)
        return Client(streamable_http_client(self.url, http_client=http), extensions=[capability])

    async def list_tools(self) -> types.ListToolsResult:
        http = httpx2.AsyncClient(timeout=httpx2.Timeout(self.timeout))
        async with http:
            async with self._client(http) as client:
                return await client.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        meta: dict[str, Any] | None = None) -> types.CallToolResult:
        refusals: list[dict[str, Any]] = []

        async def capture(response: httpx2.Response) -> None:
            if response.request.method != "POST" or response.status_code < 400:
                return
            body = await response.aread()
            try:
                payload = json.loads(body) if body else None
            except ValueError:
                payload = None
            refusals.append({
                "status": response.status_code,
                "payload": payload if isinstance(payload, dict) else None,
                "body": body.decode("utf-8", "replace")[:300],
                "failure": response.headers.get("x-vlei-failure"),
            })

        http = httpx2.AsyncClient(
            timeout=httpx2.Timeout(self.timeout, read=max(self.timeout, 60.0)),
            event_hooks={"response": [capture]},
        )
        try:
            async with http:
                async with self._client(http) as client:
                    return await client.call_tool(name, arguments, meta=meta)
        except MCPError as exc:
            return refusal(refusals, f"{exc.error.message} (JSON-RPC {exc.error.code})", self.keys)
        except Exception as exc:  # noqa: BLE001 - Claude is told what happened; the proxy keeps running
            return refusal(refusals, f"transport error: {_innermost(exc)}", self.keys)


def refusal(refusals: list[dict[str, Any]], fallback: str, keys: Keys) -> types.CallToolResult:
    """A call that never reached the tool, as a tool error whose first line is why.

    Prefers the authorizer's own words (``{"layer", "message", "report"}``, the 403 body); then a
    refusal without a layer (``refused: …``); then a gateway that could not be reached
    (``unavailable: …``).
    """
    for item in reversed(refusals):
        payload = item["payload"] or {}
        if "layer" in payload and "message" in payload:
            layer = payload.get("layer") or item["failure"]
            text = f"{layer}: {payload['message']}" if layer else f"refused: {payload['message']}"
            meta: dict[str, Any] = {keys.failure: {"layer": layer, "message": payload["message"]}}
            if payload.get("report"):
                meta[keys.report] = payload["report"]
            return _error(text, meta)
    if refusals:
        last = refusals[-1]
        prefix = last["failure"] or "refused"
        return _error(f"{prefix}: the gateway refused the call (HTTP {last['status']}) {last['body']}".rstrip())
    return _error(f"unavailable: {fallback}")


def _error(text: str, meta: dict[str, Any] | None = None) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True,
                                meta=meta or None)


def _innermost(exc: BaseException) -> str:
    inner = getattr(exc, "exceptions", None)
    return _innermost(inner[0]) if inner else f"{type(exc).__name__}: {exc}"


# ------------------------------------------------------------------------------------------- #
# The relay
# ------------------------------------------------------------------------------------------- #

class _Published:
    """What ``VleiClient.connect`` reads, built from the gateway's published document.

    The gateway relays its backend's capabilities, which do not advertise the extension, so there is
    nothing to discover; the LE is read from the RFC 8615 location and handed to ``connect`` as if
    it had come with discovery. Verification is the package's own, unchanged: LE type, chain to an
    accepted root, revocation from the witness.
    """

    def __init__(self, gateway: GatewayLike, credential: str, keys: Keys) -> None:
        self._gateway = gateway
        self.server_capabilities = SimpleNamespace(extensions={keys.extension: {}})
        self.prior_discover = SimpleNamespace(meta={keys.credential: credential})

    async def list_tools(self) -> types.ListToolsResult:
        return await self._gateway.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        meta: dict[str, Any] | None = None) -> types.CallToolResult:
        return await self._gateway.call_tool(name, arguments, meta=meta)


class Relay:
    """Verify the gateway, then relay tools and calls under one fixed profile."""

    def __init__(self, profile: Profile, gateway: GatewayLike, *, signer: Any,
                 accepted_roots: list[str], witness_url: str | None,
                 witness_client: Any = None, log: RelayLog | None = None,
                 reload: Any = None) -> None:
        self.profile = profile
        self.gateway = gateway
        self.signer = signer
        self.accepted_roots = list(accepted_roots)
        self.witness_url = witness_url
        self.witness_client = witness_client
        self.log = log or RelayLog()
        #: Re-reads the same profile — never another — so a credential re-issued after a revocation
        #: is presented without restarting Claude. The name is fixed; only its files are re-read.
        self._reload = reload or (lambda: load_profile(profile.name))
        self.keys = namespace_keys()
        self.verified: VerificationResult | None = None
        self.reason: str | None = "not yet connected"
        self.tools: list[types.Tool] = []
        self._client: VleiClient | None = None

    async def connect(self) -> bool:
        """Verify the gateway's LE; on success, read and describe its tools."""
        try:
            document = await self.gateway.published()
            client = VleiClient(
                _Published(self.gateway, document["credential"], self.keys),
                credential=self.profile.credential,
                credential_said=self.profile.credential_said,
                signer=self.signer,
                delegated_aid=self.profile.delegated_aid or self.signer.aid,
                accepted_roots=self.accepted_roots,
                verify_server=True,
                witness_url=self.witness_url,
                witness_client=self.witness_client,
                role=self.profile.role or None,
            )
            identity = await client.connect()
            if identity is None:
                raise LookupError("the gateway's LE could not be verified")
            identity.source = "well-known"
            listed = await client.list_tools()
        except VleiError as exc:
            return self._unverified(f"{exc.layer.value}: {exc.message}")
        except ValueError as exc:
            # No accepted root, no witness: a configuration that cannot verify anything.
            return self._unverified(f"misconfigured: {exc}")
        except Exception as exc:  # noqa: BLE001 - unreachable, malformed: still a reason to refuse
            return self._unverified(f"unavailable: {_innermost(exc)}")
        self._client, self.verified, self.reason = client, identity, None
        self.tools = [describe(tool, self.keys.requires) for tool in listed.tools]
        self.log.event(
            f"gateway verified: LEI {identity.lei}, root {identity.root_aid}, "
            f"revocation {'checked' if identity.revocation_checked else 'NOT checked'}; "
            f"{len(self.tools)} tools; profile={self.profile.name}"
        )
        return True

    def _unverified(self, reason: str) -> bool:
        self._client, self.verified, self.tools = None, None, []
        self.reason = reason
        self.log.event(f"gateway NOT verified, no tools exposed: {_token(reason.split(':', 1)[0])}")
        return False

    def instructions(self) -> str:
        if self.verified is None:
            return (
                f"The labour-insurance gateway could not be verified ({self.reason}). No tools are "
                "exposed, and nothing will be signed or sent. "
                f"無法驗證勞保閘道（{self.reason}），因此不提供任何工具，也不會簽署或送出任何東西。"
            )
        lei = self.verified.lei
        name = label_for(lei)
        operator = f"LEI {lei}" + (f" ({name}, as recorded locally)" if name else "")
        return (
            f"This server relays the labour-insurance gateway ({SIMULATED}). The gateway was "
            f"verified before connecting: its operator's LE credential, {operator}, chains to the "
            f"accepted root {self.verified.root_aid}"
            + (", and is not revoked" if self.verified.revocation_checked else "")
            + f". Every call is signed in the local KERI keystore and presents the ECR credential of "
            f"{self.profile.entity or 'the legal entity'} (role {self.profile.role}); profile "
            f"{self.profile.name}. The gateway decides; a refusal's first line names the check that "
            "failed. Every identity is fictional. "
            f"本伺服器轉送勞保模擬閘道（模擬，未連接勞動部勞工保險局）。連線前已驗證閘道營運者的 LE 憑證"
            f"（{operator}）。每次呼叫都在本機 KERI 金鑰庫簽章，出示 {self.profile.entity or '法人'} 的"
            f"角色憑證（{self.profile.role}）。是否放行由閘道決定；被拒時第一行就是失敗原因。所有身分皆為虛構。"
        )

    def _refresh(self) -> None:
        """The same profile's files again: a re-issued credential replaces a revoked one."""
        if self._client is None:
            return
        try:
            current = self._reload()
        except (OSError, ValueError, KeyError):
            return
        if current.name != self.profile.name:
            return
        if current.credential_said != self.profile.credential_said:
            self._client.credential = current.credential.read_text(encoding="utf-8").strip()
            self._client.credential_said = current.credential_said
            self.profile = current

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        if self._client is None and not await self.connect():
            self.log.call(profile=self.profile.name, tool=name, result="refused",
                          reason="gateway_unverified")
            return _error(f"gateway_unverified: {self.reason}. Nothing was signed or sent. "
                          "閘道未通過驗證，沒有簽署也沒有送出任何東西。")
        self._refresh()
        try:
            result = await self._client.call_tool(name, arguments)
        except VleiError as exc:
            self.log.call(profile=self.profile.name, tool=name, result="refused",
                          reason=exc.layer.value)
            return _error(f"{exc.layer.value}: {exc.message}")
        outcome, reason = classify(result, self.keys)
        self.log.call(profile=self.profile.name, tool=name, result=outcome, reason=reason)
        return result


def classify(result: types.CallToolResult, keys: Keys) -> tuple[str, str | None]:
    """allowed · refused (a failure layer) · system (verified, then the system said no) · unavailable."""
    if not result.is_error:
        return "allowed", None
    meta = result.meta or {}
    failure = meta.get(keys.failure) or {}
    if failure.get("layer"):
        return "refused", failure["layer"]
    if (meta.get(keys.report) or {}).get("allowed") is True:
        return "system", "business_rule"
    first = next((block.text for block in result.content or [] if getattr(block, "text", None)), "")
    head = first.split(":", 1)[0]
    if head == "unavailable":
        return "unavailable", "transport"
    return "refused", head if head and " " not in head else "refused"


# ------------------------------------------------------------------------------------------- #
# The near side: Claude
# ------------------------------------------------------------------------------------------- #

def build_server(relay: Relay) -> Server:
    """An MCP server whose only tools are the gateway's. Nothing here changes the profile."""

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        if relay.verified is None:
            await relay.connect()
        return types.ListToolsResult(tools=list(relay.tools))

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await relay.call_tool(params.name, params.arguments)

    return Server(
        "vlei-credential-proxy",
        version="0.1.0",
        instructions=relay.instructions(),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def docker_can_find_compose(environ: dict[str, str] | None = None) -> None:
    """Docker Desktop finds its ``compose`` plugin under ``%ProgramFiles%``.

    MCP clients start servers with a small environment: the SDK passes a dozen variables, and
    ``ProgramFiles`` is not among them. Without it every ``kli sign`` fails with "unknown command:
    docker compose", and the proxy could never sign anything.
    """
    env = os.environ if environ is None else environ
    if os.name == "nt" and not env.get("ProgramFiles"):
        env["ProgramFiles"] = (env.get("SYSTEMDRIVE") or "C:") + "\\Program Files"


def main() -> int:
    import anyio
    from mcp.server.stdio import stdio_server

    docker_can_find_compose()
    name = os.environ.get("VLEI_PROFILE", "demo").strip() or "demo"
    try:
        profile = load_profile(name)
        from kli_signer import keystore_signer

        signer = keystore_signer(profile.keystore, profile.keystore)
    except (ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"credential-proxy: {exc}", file=sys.stderr)
        return 2
    log_path = os.environ.get("VLEI_PROXY_LOG", "").strip()
    relay = Relay(
        profile,
        Gateway(os.environ.get("VLEI_GATEWAY_URL", DEFAULT_GATEWAY).strip(), roots=accepted_roots()),
        signer=signer,
        accepted_roots=accepted_roots(),
        witness_url=witness_url(),
        log=RelayLog(Path(log_path) if log_path else DEFAULT_LOG),
    )

    async def run() -> None:
        await relay.connect()
        server = build_server(relay)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(run)
    return 0


__all__ = [
    "Gateway", "Profile", "Relay", "RelayLog", "accepted_roots", "build_server", "classify",
    "describe", "docker_can_find_compose", "label_for", "load_profile", "refusal",
    "requirement_sentence", "witness_url",
]

if __name__ == "__main__":
    sys.exit(main())
