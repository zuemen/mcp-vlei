"""The real-Claude runner behind the story page's buttons: what it starts, and how it reads Claude."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CONSOLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONSOLE))

import agent  # noqa: E402
from test_interactive import _client, _load  # noqa: E402


def test_claude_gets_one_connection_one_tool_and_no_shell_files_or_web(tmp_path):
    config = agent.write_config(tmp_path, "after", python="py")
    servers = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]
    assert list(servers) == ["labor-vlei"]
    assert servers["labor-vlei"]["env"] == {"VLEI_PROFILE": "demo"}
    assert servers["labor-vlei"]["args"] == [str(agent.PROXY)]

    argv = agent.command("claude", config, "after", "adjust", "zh")
    assert argv[:3] == ["claude", "-p", "把 EMP-0001 的投保薪資調到第 5 級"]
    assert "--strict-mcp-config" in argv          # not the person's other MCP servers
    assert argv[argv.index("--tools") + 1] == "ToolSearch"
    assert argv[argv.index("--allowedTools") + 1] == "mcp__labor-vlei__adjust_insured_salary"
    # The server's other tools are not offered at all: a refused detour (list_insured, refused by
    # Claude Code's own permissions) read on screen as if the gateway had refused it.
    hidden = argv[argv.index("--disallowedTools") + 1].split(",")
    assert sorted(hidden) == ["mcp__labor-vlei__enroll_employee", "mcp__labor-vlei__list_insured",
                              "mcp__labor-vlei__withdraw_employee"]

    before = json.loads(agent.write_config(tmp_path, "before").read_text(encoding="utf-8"))["mcpServers"]
    assert before["labor-today"]["env"] == {"VLEI_PROFILE": "plain"}


def test_claude_is_told_the_pages_language_after_the_style_line(tmp_path):
    config = agent.write_config(tmp_path, "after", python="py")
    for lang, line in (("en", "Reply in English."), ("zh", "用繁體中文回答。")):
        argv = agent.command("claude", config, "after", "enrol", lang)
        assert argv[argv.index("--append-system-prompt") + 1] == f"{agent.STYLE} {line}"
    # The request itself is unchanged.
    assert agent.command("claude", config, "after", "enrol", "en")[2] == "Enrol EMP-0001 from today, salary grade 3."


def test_the_workdir_is_fresh_and_outside_the_home(tmp_path):
    home, system = tmp_path / "home", tmp_path / "system-temp"
    (home / "AppData" / "Local" / "Temp").mkdir(parents=True)
    system.mkdir()
    roots = [home / "AppData" / "Local" / "Temp", tmp_path / "missing", system]
    first = agent.fresh_workdir(home=home, roots=roots, fallback=tmp_path / "fallback")
    second = agent.fresh_workdir(home=home, roots=roots, fallback=tmp_path / "fallback")
    assert first.parent == system and second.parent == system and first != second
    assert first.is_dir() and list(first.iterdir()) == []


def test_with_every_temp_root_under_the_home_the_workdir_goes_to_the_fallback(tmp_path):
    home = tmp_path / "home"
    (home / "Temp").mkdir(parents=True)
    workdir = agent.fresh_workdir(home=home, roots=[home / "Temp"], fallback=tmp_path / "agent-runs")
    assert workdir.parent == tmp_path / "agent-runs"


def test_on_this_machine_claude_runs_where_no_claude_md_is_read(monkeypatch):
    """The default choice, for real: outside the home, and no CLAUDE.md in it or any ancestor."""
    runner = agent.Agent(claude="claude")
    workdir = runner.workdir
    try:
        assert not str(workdir.resolve()).lower().startswith(str(Path.home().resolve()).lower())
        assert not any((d / name).exists() for d in (workdir, *workdir.parents)
                       for name in ("CLAUDE.md", "CLAUDE.local.md"))

        seen: dict = {}

        class Proc:
            returncode = 0
            stdout = iter([json.dumps({"type": "result", "subtype": "success", "is_error": False}) + "\n"])

            def wait(self):
                return 0

            def kill(self):
                pass

        def popen(argv, **kwargs):
            seen.update(kwargs, argv=argv)
            return Proc()

        monkeypatch.setattr(agent.subprocess, "Popen", popen)
        run = {"side": "after", "ask": "enrol", "lang": "en", "status": "running", "events": []}
        runner._run(run)
        assert run["status"] == "done"
        assert seen["cwd"] == workdir
        assert seen["argv"][seen["argv"].index("--append-system-prompt") + 1].endswith("Reply in English.")
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)


def test_without_before_url_the_config_is_unchanged(tmp_path, monkeypatch):
    """The live console never sets VLEI_BEFORE_URL: both sides' config stays VLEI_PROFILE alone,
    whatever VLEI_GATEWAY_URL happens to be in this process's own environment."""
    monkeypatch.delenv("VLEI_BEFORE_URL", raising=False)
    monkeypatch.setenv("VLEI_GATEWAY_URL", "http://localhost:3000/mcp")
    before = json.loads(agent.write_config(tmp_path, "before").read_text(encoding="utf-8"))["mcpServers"]
    after = json.loads(agent.write_config(tmp_path, "after").read_text(encoding="utf-8"))["mcpServers"]
    assert before["labor-today"]["env"] == {"VLEI_PROFILE": "plain"}
    assert after["labor-vlei"]["env"] == {"VLEI_PROFILE": "demo"}


def test_under_the_parallel_stack_each_side_gets_its_own_gateway_url(tmp_path, monkeypatch):
    """scripts/demo-parallel.sh exports one VLEI_GATEWAY_URL (the parallel *gateway*, for this
    console's own calls) and VLEI_BEFORE_URL (the parallel before simulator). Without this, the
    child Claude starts for "before" would inherit VLEI_GATEWAY_URL and reach the real gateway
    instead of the before simulator — scene 1 of the video would be wrong."""
    monkeypatch.setenv("VLEI_BEFORE_URL", "http://127.0.0.1:38090")
    monkeypatch.setenv("VLEI_GATEWAY_URL", "http://localhost:33000/mcp")
    before = json.loads(agent.write_config(tmp_path, "before").read_text(encoding="utf-8"))["mcpServers"]
    after = json.loads(agent.write_config(tmp_path, "after").read_text(encoding="utf-8"))["mcpServers"]
    assert before["labor-today"]["env"] == {
        "VLEI_PROFILE": "plain", "VLEI_GATEWAY_URL": "http://127.0.0.1:38090/mcp",
    }
    assert after["labor-vlei"]["env"] == {
        "VLEI_PROFILE": "demo", "VLEI_GATEWAY_URL": "http://localhost:33000/mcp",
    }


def test_claudes_stream_becomes_what_the_page_shows():
    run = {"status": "running", "events": []}
    stream = [
        {"type": "system", "subtype": "init", "model": "claude-x",
         "mcp_servers": [{"name": "labor-vlei", "status": "connected"}]},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t0", "name": "ToolSearch", "input": {"query": "select:x"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t0", "content": ""}]}},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "mcp__labor-vlei__adjust_insured_salary",
             "input": {"person_ref": "EMP-0001", "salary_grade": 5}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "is_error": True,
                                                  "content": [{"type": "text", "text": "role_mismatch: no"}]}]}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": " Refused: wrong role. "}]}},
        {"type": "result", "subtype": "success", "is_error": False, "duration_ms": 1234},
    ]
    for message in stream:
        agent.apply(run, message)
    assert run["model"] == "claude-x" and run["connected"] == ["labor-vlei"]
    assert run["status"] == "done" and run["durationMs"] == 1234
    call, say = run["events"]                      # ToolSearch is Claude Code's own, not shown
    assert call == {"kind": "call", "id": "t1", "server": "labor-vlei", "tool": "adjust_insured_salary",
                    "arguments": {"person_ref": "EMP-0001", "salary_grade": 5},
                    "status": "refused", "result": "role_mismatch: no"}
    assert say == {"kind": "say", "text": "Refused: wrong role."}


def test_a_failed_run_says_why():
    run = {"status": "running", "events": []}
    agent.apply(run, {"type": "result", "subtype": "error_max_turns", "is_error": True})
    assert run["status"] == "error" and run["error"] == "error_max_turns"


def test_only_the_offered_requests_one_at_a_time(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        agent.Agent(claude="claude", workdir=tmp_path).start("sideways", "enrol")
    with pytest.raises(ValueError):
        agent.Agent(claude="claude", workdir=tmp_path).start("after", "rm -rf")
    monkeypatch.delenv("VLEI_CLAUDE_BIN", raising=False)
    monkeypatch.setattr(agent.shutil, "which", lambda name: None)
    with pytest.raises(LookupError):
        agent.Agent(workdir=tmp_path).start("after", "enrol")
    busy = agent.Agent(claude="claude", workdir=tmp_path)
    busy.runs.append({"status": "running"})
    with pytest.raises(RuntimeError):
        busy.start("after", "enrol")


async def test_the_public_page_never_starts_claude():
    module = _load(public=True)
    async with _client(module) as client:
        refused = await client.post("/api/agent/run", json={"side": "after", "ask": "enrol"})
        listed = (await client.get("/api/agent/runs")).json()
    assert refused.status_code == 403
    assert listed == {"available": False, "busy": False, "runs": []}


async def test_a_bad_request_is_refused_before_anything_starts():
    module = _load()
    async with _client(module) as client:
        response = await client.post("/api/agent/run", json={"side": "after", "ask": "something else"})
    assert response.status_code == 400
    assert module.AGENT.runs == []
