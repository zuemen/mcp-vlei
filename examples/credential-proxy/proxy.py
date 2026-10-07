"""Credential proxy: Claude on one side over STDIO, the labour-insurance gateway on the other.

Claude Desktop and Claude Code start local MCP servers over STDIO and know nothing about vLEI. This
one stands between them and the gateway and does four things, and nothing else:

1. **Verifies the gateway first.** It reads the operator's LE credential from the gateway's
   ``/.well-known/vlei``, verifies the chain to an accepted root and the issuers' logs for
   revocation, and challenges the gateway to prove it holds the operator's key (``vlei-pop/0.3``) —
   every key state read from the three demo witnesses, two of which must agree — before a single
   tool is listed. It verifies again every five minutes (or the gateway's ``ttlMs``) before
   presenting anything. If that fails, no tools are listed, nothing is signed or sent, and the
   reason is in the server's instructions and the log.
2. **Relays the tool list as it is,** ``_meta`` requirements included, adding one sentence in
   Chinese and English on the role each tool requires.
3. **Signs every call** (``vlei-sig/0.3``: for this gateway's operator and URL, with a nonce and
   a 30-second expiry) in the KERI keystore with ``kli sign``, as the agent's delegated AID. The
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
import subprocess
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
from mcp_vlei.kel import normalise_witness_urls  # noqa: E402
from mcp_vlei.namespace import Keys  # noqa: E402
from mcp_vlei.namespace import keys as namespace_keys  # noqa: E402
from mcp_vlei.verifier import VerificationResult  # noqa: E402

#: Where the bootstrap scripts wrote credentials (VLEI_CREDENTIALS_DIR, else credentials/): the
#: agent's signer reads env.json by the same rule, so there is one copy of it.
from kli_signer import credentials_dir  # noqa: E402  (examples/my-agent, on sys.path above)

DEFAULT_GATEWAY = "http://localhost:3000/mcp"
#: The before-mode simulator (deploy/agentgateway, bound to 127.0.0.1): what VLEI_PROFILE=plain reaches.
DEFAULT_PLAIN = "http://localhost:8090/mcp"
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
    base = credentials_dir(root)
    return {"demo": base, "forged": base / "forged"}


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
    main = credentials_dir(root, env) / "env.json"
    return list(json.loads(main.read_text(encoding="utf-8")).get("acceptedRoots", [])) if main.is_file() else []


def _setting(name: str, root: Path, env: dict[str, str] | Any) -> str:
    """One key, from the environment or else from ``scripts/.env`` — nothing else in that file is
    read. The scripts keep machine-local witness ports there (Windows reserves 5642-5644 on some
    machines)."""
    if env.get(name, "").strip():
        return env[name].strip()
    dotenv = root / "scripts" / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, _, value = line.strip().partition("=")
            if key == name and value.strip():
                return value.strip().strip('"').strip("'")
    return ""


def witness_url(root: Path = ROOT, environ: dict[str, str] | None = None) -> str:
    """The first witness: VLEI_WITNESS_URL, else the one ``scripts/.env`` sets."""
    env = os.environ if environ is None else environ
    return _setting("VLEI_WITNESS_URL", root, env) or DEFAULT_WITNESS


#: Dropped the same way ``mcp_vlei.client`` drops them when comparing origins: a witness URL
#: without a port still has one — the scheme's default — and must not be mistaken for "no port to
#: expand from" and collapsed to a single witness.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _host_port(hostname: str, port: int) -> str:
    """``hostname:port``, bracketing an IPv6 literal. ``urlsplit`` strips the brackets from
    ``.hostname`` (``[::1]`` becomes ``::1``); they must go back on before the URL is reassembled,
    or ``::1:5643`` is parsed as a different, invalid address."""
    return f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"


def witness_urls(root: Path = ROOT, environ: dict[str, str] | None = None) -> list[str]:
    """Every witness key event logs are read from — compared, and a majority required, as
    vlei-authz does. VLEI_WITNESS_URLS (comma-separated, environment or ``scripts/.env``); else the
    demo's three, which ``kli witness demo`` serves on consecutive ports from VLEI_WITNESS_URL's."""
    env = os.environ if environ is None else environ
    listed = _setting("VLEI_WITNESS_URLS", root, env)
    if listed:
        return [u.strip() for u in listed.split(",") if u.strip()]
    first = witness_url(root, env)
    parts = urlsplit(first)
    if not parts.hostname:
        return [first]
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(parts.scheme.lower())
    if port is None:
        # A scheme this module does not know a default port for, and none was given: there is no
        # base to expand from, so one witness is all that can be said — not three at a guessed port.
        return [first]
    return [urlunsplit((parts.scheme, _host_port(parts.hostname, port + i), parts.path, "", ""))
            for i in range(3)]


def _witness_list(witness_url: str | list[str] | None) -> list[str]:
    """Normalise ``Relay.witness_url`` exactly as ``WitnessKeyStates`` does (one URL, several, or
    none; one spelling each, each once), so what this logs always matches what the client actually
    configures."""
    return normalise_witness_urls(witness_url)


def _quorum_for(urls: list[str]) -> int:
    """The default majority quorum ``WitnessKeyStates`` computes for this many witnesses — the only
    quorum the proxy ever asks for; it never overrides ``witness_quorum``."""
    return len(urls) // 2 + 1 if urls else 0


def label_for(lei: str, root: Path = ROOT) -> str:
    """A name for an LEI, from this machine's own bootstrap output, marked as such.

    An LE credential carries the LEI and nothing else; the name belongs to the LEI record, and these
    test LEIs have none. So the name shown is the one the bootstrap scripts recorded locally.
    """
    for env_path in sorted(credentials_dir(root).glob("**/env.json")):
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
        #: The name the client in front of the proxy (Claude Desktop) gave itself, handed on as is:
        #: the gateway then records which client the call came from beside what it verified.
        self.client_info: Any = None

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

    def _client(self, http: httpx2.AsyncClient, client_info: Any = None) -> Client:
        # Declares the extension at initialize, as a client presenting a credential should.
        capability = VleiCapability(presents=["ECR"], accepted_roots=self.roots or None)
        extra = {"client_info": client_info} if client_info is not None else {}
        return Client(streamable_http_client(self.url, http_client=http), extensions=[capability], **extra)

    async def list_tools(self) -> types.ListToolsResult:
        http = httpx2.AsyncClient(timeout=httpx2.Timeout(self.timeout))
        async with http:
            async with self._client(http) as client:
                return await client.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        meta: dict[str, Any] | None = None, client_info: Any = None) -> types.CallToolResult:
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
                async with self._client(http, client_info if client_info is not None else self.client_info) as client:
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

    def __init__(self, gateway: GatewayLike, document: dict[str, Any], keys: Keys) -> None:
        self._gateway = gateway
        # What the document says about checking the gateway: the signature format it verifies,
        # where to challenge it, how long a verification may be relied on.
        offered = {k: document[k] for k in ("signatureFormats", "pop", "ttlMs") if k in document}
        self.server_capabilities = SimpleNamespace(extensions={keys.extension: offered})
        self.prior_discover = SimpleNamespace(meta={keys.credential: document["credential"]})

    async def list_tools(self) -> types.ListToolsResult:
        return await self._gateway.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        meta: dict[str, Any] | None = None) -> types.CallToolResult:
        return await self._gateway.call_tool(name, arguments, meta=meta)


class Relay:
    """Verify the gateway, then relay tools and calls under one fixed profile."""

    def __init__(self, profile: Profile, gateway: GatewayLike, *, signer: Any,
                 accepted_roots: list[str], witness_url: str | list[str] | None,
                 witness_client: Any = None, log: RelayLog | None = None,
                 reload: Any = None, pop_client: Any = None,
                 recheck_seconds: float = 300) -> None:
        self.profile = profile
        self.gateway = gateway
        self.signer = signer
        self.accepted_roots = list(accepted_roots)
        self.witness_url = witness_url
        self.witness_client = witness_client
        self.pop_client = pop_client
        self.recheck_seconds = recheck_seconds
        self.log = log or RelayLog()
        #: Re-reads the same profile — never another — so a credential re-issued after a revocation
        #: is presented without restarting Claude. The name is fixed; only its files are re-read.
        self._reload = reload or (lambda: load_profile(profile.name))
        self.keys = namespace_keys()
        #: What the client actually asks of its witnesses (spec §6.2): logged at startup, once,
        #: identifiers only — never key material.
        self._witness_urls = _witness_list(witness_url)
        self._quorum = _quorum_for(self._witness_urls)
        caveat = "; one witness: duplicity not checked" if len(self._witness_urls) == 1 else ""
        self.log.event(
            f"witnesses: {', '.join(self._witness_urls) or '(none)'} "
            f"(quorum {self._quorum} of {len(self._witness_urls)}){caveat}"
        )
        self.verified: VerificationResult | None = None
        self.reason: str | None = "not yet connected"
        self.tools: list[types.Tool] = []
        self._client: VleiClient | None = None

    async def connect(self) -> bool:
        """Verify the gateway's LE; on success, read and describe its tools."""
        try:
            document = await self.gateway.published()
            client = VleiClient(
                _Published(self.gateway, document, self.keys),
                credential=self.profile.credential,
                credential_said=self.profile.credential_said,
                signer=self.signer,
                delegated_aid=self.profile.delegated_aid or self.signer.aid,
                accepted_roots=self.accepted_roots,
                verify_server=True,
                witness_url=self.witness_url,
                witness_client=self.witness_client,
                role=self.profile.role or None,
                endpoint_url=self.gateway.url,
                pop_client=self.pop_client,
                recheck_seconds=self.recheck_seconds,
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
        proof = client.server_proof
        if proof is None:
            # Not a legitimate "unproven, continuing" state to narrate: this Relay always
            # constructs its VleiClient with pop="required" (never "off"), so a verified identity
            # with no proof of possession would mean that invariant broke, not that the operator
            # chose to skip it. Fail loudly rather than print a warn-and-continue-looking message.
            raise RuntimeError(
                "the gateway was verified but did not prove possession of its key, although this "
                "Relay always requires it (pop='required'); VleiClient.server_proof is None"
            )
        held = (f"key held by {proof.responder_aid} "
                f"({'delegated by the LE' if proof.delegated else 'the LE itself'}), "
                f"witnesses {proof.agreeing}/{proof.configured} agree (quorum {self._quorum})")
        self.log.event(
            f"gateway verified: LEI {identity.lei}, root {identity.root_aid}, "
            f"revocation {'checked' if identity.revocation_checked else 'NOT checked'}; "
            f"{held}; {len(self.tools)} tools; profile={self.profile.name}"
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
            if self._client is not None and self._client.server_identity is None:
                # The gateway failed its re-check: no more tools until a reconnect verifies it.
                self._unverified(f"{exc.layer.value}: {exc.message}")
            return _error(f"{exc.layer.value}: {exc.message}")
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:   # the keystore could not sign
            self.log.call(profile=self.profile.name, tool=name, result="unavailable", reason="signer")
            return _error(f"unavailable: the local keystore could not sign ({_innermost(exc)}). "
                          "Nothing was sent. 本機金鑰庫無法簽章，沒有送出任何東西。")
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

class PlainRelay:
    """VLEI_PROFILE=plain: MCP as it is today — the before half of the before-and-after.

    No credential, no signature, no verification of the server: tools are relayed and calls passed
    on with nothing attached. The one thing passed through is the name the client (Claude Desktop)
    gave itself, because that is all an MCP server learns of its caller today — and the point of
    the comparison is that any program can give the same name.
    """

    def __init__(self, gateway: GatewayLike, *, log: RelayLog | None = None) -> None:
        self.gateway = gateway
        self.log = log or RelayLog()
        self.profile = SimpleNamespace(name="plain")
        self.keys = namespace_keys()
        self.tools: list[types.Tool] = []
        self.verified = None
        self.reason: str | None = "not yet connected"

    async def connect(self) -> bool:
        try:
            self.tools = list((await self.gateway.list_tools()).tools)
        except Exception as exc:  # noqa: BLE001
            self.tools, self.reason = [], f"unavailable: {_innermost(exc)}"
            self.log.event(f"plain: the server is not answering ({_token(self.reason.split(':', 1)[0])})")
            return False
        self.reason = None
        self.log.event(f"plain: {len(self.tools)} tools, nothing verified, nothing signed; profile=plain")
        return True

    def instructions(self) -> str:
        return (
            f"This server relays the labour-insurance system the way MCP works today ({SIMULATED}): "
            "no credential, no signature, and nothing is verified. The system will know only the "
            "name your client gives itself. "
            "本伺服器照今天 MCP 的做法轉送：不附憑證、不簽章、什麼都不驗證。系統只會知道你的客戶端自稱的名字。"
        )

    async def call_tool(self, name: str, arguments: dict[str, Any] | None,
                        client_info: Any = None) -> types.CallToolResult:
        if not self.tools and not await self.connect():
            self.log.call(profile="plain", tool=name, result="unavailable", reason="transport")
            return _error(f"unavailable: {self.reason}")
        result = await self.gateway.call_tool(name, arguments, client_info=client_info)
        outcome, reason = classify(result, self.keys)
        self.log.call(profile="plain", tool=name, result=outcome, reason=reason)
        return result


def _client_info(ctx: Any) -> Any:
    """The name the client gave this server at initialize, to hand on unchanged."""
    try:
        params = ctx.session.client_params
        return getattr(params, "client_info", None) if params is not None else None
    except Exception:  # noqa: BLE001
        return None


def build_server(relay: Any) -> Server:
    """An MCP server whose only tools are the upstream's. Nothing here changes the profile."""

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        if not relay.tools:
            await relay.connect()
        return types.ListToolsResult(tools=list(relay.tools))

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        info = _client_info(ctx)
        if info is not None and hasattr(relay.gateway, "client_info"):
            relay.gateway.client_info = info
        if isinstance(relay, PlainRelay):
            return await relay.call_tool(params.name, params.arguments, client_info=_client_info(ctx))
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
    log_path = os.environ.get("VLEI_PROXY_LOG", "").strip()
    if name == "plain":
        # The before half: nothing to load, nothing to sign with — that is the point.
        plain = PlainRelay(Gateway(os.environ.get("VLEI_GATEWAY_URL", DEFAULT_PLAIN).strip()),
                           log=RelayLog(Path(log_path) if log_path else DEFAULT_LOG))

        async def run_plain() -> None:
            await plain.connect()
            server = build_server(plain)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())

        anyio.run(run_plain)
        return 0
    try:
        profile = load_profile(name)
        from kli_signer import LazyKeystoreSigner

        # Read from the keystore at the first signature: kli through Docker takes seconds, and
        # initialize must be answered before the client gives up on this server.
        signer = LazyKeystoreSigner(profile.keystore, profile.keystore)
    except (ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"credential-proxy: {exc}", file=sys.stderr)
        return 2
    relay = Relay(
        profile,
        Gateway(os.environ.get("VLEI_GATEWAY_URL", DEFAULT_GATEWAY).strip(), roots=accepted_roots()),
        signer=signer,
        accepted_roots=accepted_roots(),
        witness_url=witness_urls(),
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
    "Gateway", "PlainRelay", "Profile", "Relay", "RelayLog", "accepted_roots", "build_server", "classify",
    "credentials_dir", "describe", "docker_can_find_compose", "label_for", "load_profile", "refusal",
    "requirement_sentence", "witness_url", "witness_urls",
]

if __name__ == "__main__":
    sys.exit(main())
