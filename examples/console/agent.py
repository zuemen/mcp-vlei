"""A real Claude agent for the story page: Claude Code, headless, with one MCP connection.

The page asks; this starts ``claude -p`` with a single MCP server — ``labor-today`` (the credential
proxy's plain profile: MCP as it is today) or ``labor-vlei`` (its demo profile: the ECR presented,
every call signed) — and only that server's one tool allowed. What comes back is Claude's own
stream: the tool it chose, what the server answered, what it told the person. Nothing on Claude's
side is scripted; the console chooses only the request and the connection.

Local only. It spends the operator's Claude account, so the public page never offers it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PROXY = ROOT / "examples" / "credential-proxy" / "proxy.py"

#: The two connections, named as in the Claude Desktop configuration (examples/credential-proxy/README.md).
SIDES = {"before": ("labor-today", "plain"), "after": ("labor-vlei", "demo")}
#: What the person asks, and the one tool Claude may use for it.
ASKS = {
    "enrol": ("enroll_employee", {"zh": "幫 EMP-0001 今天加保，投保薪資第 3 級",
                                  "en": "Enrol EMP-0001 from today, salary grade 3."}),
    "adjust": ("adjust_insured_salary", {"zh": "把 EMP-0001 的投保薪資調到第 5 級",
                                         "en": "Raise EMP-0001's insured salary to grade 5."}),
}
#: Every tool the labour-insurance system offers. Claude is offered only the one it is asked to use:
#: given the others, it took detours (list_insured first) that Claude Code's own permissions
#: refused, and a refusal on the page read as if the gateway had made it.
SERVER_TOOLS = ("enroll_employee", "withdraw_employee", "adjust_insured_salary", "list_insured")
#: For the screen: short answers read in a recording. How to answer, never what to do.
STYLE = ("Reply in the language of the request, in at most three short sentences. "
         "No tables, no headings, no lists.")
#: The page's language, said outright and appended to STYLE: "the language of the request" alone lost
#: to an operator's own CLAUDE.md once (the first English video answered in Chinese in two scenes).
LANGUAGE = {"en": "Reply in English.", "zh": "用繁體中文回答。"}
#: ToolSearch only: Claude Code may defer MCP tool schemas behind it. No shell, no files, no web.
BUILTIN_TOOLS = "ToolSearch"
TIMEOUT = 180.0
#: Variables by which the console, when started from a Claude Code session, would mark the child
#: as nested inside it.
NESTING = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SSE_PORT")


def write_config(directory: Path, side: str, python: str = sys.executable) -> Path:
    """The MCP configuration with the one server for ``side``: the credential proxy, as Desktop has it.

    The proxy's ``plain`` profile and its ``demo``/``forged`` profiles both read the one variable
    ``VLEI_GATEWAY_URL`` (``examples/credential-proxy/proxy.py``) — ``plain`` for the before-mode
    simulator, the others for the real gateway — and `_run`'s child inherits this process's whole
    environment. On the live console neither ``VLEI_GATEWAY_URL`` nor ``VLEI_BEFORE_URL`` is ever
    set, so both profiles keep their own defaults and this config stays exactly `{"VLEI_PROFILE":
    …}`, as before. Under ``scripts/demo-parallel.sh``, ``VLEI_GATEWAY_URL`` is already this
    console's own calls' URL — the parallel *gateway* — which is exactly what the ``plain`` side
    must not inherit, or its "before" run would reach the gateway instead of the before simulator.
    ``VLEI_BEFORE_URL``, set only there, is the signal: when it is set, each side's config pins its
    own ``VLEI_GATEWAY_URL`` explicitly — ``plain`` to ``VLEI_BEFORE_URL`` + "/mcp", the others to
    this process's own ``VLEI_GATEWAY_URL`` — so neither one is left to inherit the other's.
    """
    server, profile = SIDES[side]
    path = directory / f"{server}.json"
    env: dict[str, str] = {"VLEI_PROFILE": profile}
    before_url = os.environ.get("VLEI_BEFORE_URL", "").strip()
    if before_url:
        if profile == "plain":
            env["VLEI_GATEWAY_URL"] = f"{before_url.rstrip('/')}/mcp"
        else:
            gateway_url = os.environ.get("VLEI_GATEWAY_URL", "").strip()
            if gateway_url:
                env["VLEI_GATEWAY_URL"] = gateway_url
    config = {"mcpServers": {server: {"command": python, "args": [str(PROXY)], "env": env}}}
    path.write_text(json.dumps(config, indent=1), encoding="utf-8")
    return path


def style(lang: str) -> str:
    """STYLE with the reply language for ``lang`` ("en" or "zh") appended."""
    return f"{STYLE} {LANGUAGE[lang]}"


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def temp_roots() -> list[Path]:
    """Where a working directory for Claude may go, best first: the system's own temp directories.

    On Windows ``tempfile.gettempdir()`` is the user's ``AppData\\Local\\Temp`` — under the home —
    so the system temp directory (``%SystemRoot%\\Temp``) comes first.
    """
    roots: list[Path] = []
    if os.name == "nt":
        roots.append(Path(os.environ.get("SystemRoot") or r"C:\Windows") / "Temp")
    roots.append(Path(tempfile.gettempdir()))
    if os.name != "nt":
        roots += [Path("/tmp"), Path("/var/tmp")]
    return roots


def fresh_workdir(home: Path | None = None, roots: list[Path] | None = None,
                  fallback: Path | None = None) -> Path:
    """A fresh, empty directory for ``claude -p`` to run in, outside the user's home.

    Claude Code reads every CLAUDE.md from its working directory up to the root. Run anywhere under
    the home, it would read the operator's own (for instance one asking for replies in another
    language) — instructions the demo agent must never get. So: a fresh directory under the first
    writable temp root outside the home. Only if there is none, one under the worktree's
    ``.v03/agent-runs/``; that one *is* under the home in a home checkout, so a CLAUDE.md at the home
    would still be read there.
    """
    home = Path.home() if home is None else home
    for root in temp_roots() if roots is None else roots:
        if not root.is_dir() or _inside(root, home):
            continue
        try:
            return Path(tempfile.mkdtemp(prefix="vlei-agent-", dir=root))
        except OSError:
            continue
    fallback = ROOT / ".v03" / "agent-runs" if fallback is None else fallback
    fallback.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="vlei-agent-", dir=fallback))


def command(claude: str, config: Path, side: str, ask: str, lang: str, model: str | None = None) -> list[str]:
    server, _ = SIDES[side]
    tool, prompts = ASKS[ask]
    argv = [claude, "-p", prompts[lang],
            "--mcp-config", str(config), "--strict-mcp-config",
            "--tools", BUILTIN_TOOLS,
            "--allowedTools", f"mcp__{server}__{tool}",
            "--disallowedTools", ",".join(f"mcp__{server}__{other}" for other in SERVER_TOOLS if other != tool),
            "--output-format", "stream-json", "--verbose",
            "--append-system-prompt", style(lang)]
    if model:
        argv += ["--model", model]
    return argv


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
    return ""


def apply(run: dict[str, Any], message: dict[str, Any]) -> None:
    """Fold one message of Claude's stream-json output into the run, as the page shows it."""
    kind = message.get("type")
    if kind == "system" and message.get("subtype") == "init":
        run["model"] = message.get("model")
        run["connected"] = [s.get("name") for s in message.get("mcp_servers") or []
                            if s.get("status") == "connected"]
    elif kind == "assistant":
        for block in (message.get("message") or {}).get("content") or []:
            if block.get("type") == "text" and str(block.get("text", "")).strip():
                run["events"].append({"kind": "say", "text": block["text"].strip()})
            elif block.get("type") == "tool_use" and str(block.get("name", "")).startswith("mcp__"):
                _, server, tool = block["name"].split("__", 2)
                run["events"].append({"kind": "call", "id": block.get("id"), "server": server, "tool": tool,
                                      "arguments": block.get("input") or {}, "status": "running"})
    elif kind == "user":
        for block in (message.get("message") or {}).get("content") or []:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            call = next((e for e in run["events"]
                         if e["kind"] == "call" and e.get("id") == block.get("tool_use_id")), None)
            if call is not None:   # a ToolSearch result has no call of ours: not shown
                call["status"] = "refused" if block.get("is_error") else "done"
                call["result"] = _text(block.get("content"))[:1200]
    elif kind == "result":
        ok = message.get("subtype") == "success" and not message.get("is_error")
        run["status"] = "done" if ok else "error"
        run["durationMs"] = message.get("duration_ms")
        if not ok:
            run["error"] = str(message.get("result") or message.get("subtype") or "failed")[:300]


class Agent:
    """One request at a time, each a fresh ``claude -p``; the last few kept for the page."""

    def __init__(self, claude: str | None = None, model: str | None = None,
                 workdir: Path | None = None, python: str = sys.executable) -> None:
        self.claude = claude or os.environ.get("VLEI_CLAUDE_BIN") or shutil.which("claude")
        self.model = model or os.environ.get("VLEI_AGENT_MODEL") or None
        self.python = python
        self._workdir = workdir
        self.runs: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def workdir(self) -> Path:
        if self._workdir is None:
            self._workdir = fresh_workdir()
        return self._workdir

    @property
    def busy(self) -> bool:
        return any(run["status"] == "running" for run in self.runs)

    def start(self, side: Any, ask: Any, lang: Any = "zh") -> dict[str, Any]:
        if side not in SIDES or ask not in ASKS:
            raise ValueError("side must be before or after; ask must be enrol or adjust")
        lang = lang if lang in ("zh", "en") else "zh"
        if not self.claude:
            raise LookupError("the claude CLI is not on PATH (set VLEI_CLAUDE_BIN)")
        with self._lock:
            if self.busy:
                raise RuntimeError("Claude is still working on the previous request")
            run = {"id": uuid.uuid4().hex[:12], "at": datetime.now(timezone.utc).isoformat(),
                   "side": side, "ask": ask, "lang": lang, "server": SIDES[side][0],
                   "prompt": ASKS[ask][1][lang], "status": "running", "events": [], "model": None}
            self.runs = [*self.runs[-19:], run]
        threading.Thread(target=self._run, args=(run,), daemon=True).start()
        return run

    def _run(self, run: dict[str, Any]) -> None:
        env = {k: v for k, v in os.environ.items() if k not in NESTING}
        try:
            config = write_config(self.workdir, run["side"], self.python)
            argv = command(self.claude, config, run["side"], run["ask"], run["lang"], self.model)
            with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as errors:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors,
                                        cwd=self.workdir, env=env, text=True, encoding="utf-8", errors="replace")
                timer = threading.Timer(TIMEOUT, proc.kill)
                timer.start()
                try:
                    for line in proc.stdout:
                        try:
                            apply(run, json.loads(line))
                        except (ValueError, AttributeError, TypeError):
                            continue
                    proc.wait()
                finally:
                    timer.cancel()
                if run["status"] == "running":
                    errors.seek(0)
                    run["status"] = "error"
                    run["error"] = (errors.read().strip() or f"claude exited with {proc.returncode}")[-300:]
        except OSError as exc:
            run["status"], run["error"] = "error", f"{type(exc).__name__}: {exc}"[:300]
