"""Trust Console — the backend that drives the recording.

Design: `docs/DEMO-CONSOLE.md`.

The right-hand column of this console is not illustrative. Every check it shows is run by
`packages/mcp-vlei` against a real credential chain, a real key event log and a real transaction
event log, and every call it shows is actually made:

* scenes 1-3 run the `VleiIdentity` extension — the class the association server runs — in process;
* scene 4 sends the call through agentgateway, where `vlei-authz` verifies it and a legacy filing
  server with no vLEI code executes it;
* scene 5 sends the call to `examples/skill-server/`, a server written from the build-time skill.

A scene whose component is not running says so. It does not fall back to anything else.

Where the environment comes from is stated in `/state` (`evidence`):

* **issued** — `scripts/bootstrap-credentials.sh` has been run and its witness is reachable. The
  agent signs with its delegated AID's key inside the KERI keystore (`kli sign`); the console never
  holds it. Revocation is `kli vc revoke`, read back from the witness.
* **minted** — no environment. `mcp_vlei.testing.World` mints a real KERI deployment in process:
  real key event logs, registries and issuances, served by an in-process witness. Same code path,
  no network. Scenes 4 and 5 still need their servers.

Run::

    pip install -e packages/mcp-vlei
    python examples/console/app.py        # http://localhost:8800
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.errors import VleiError
from mcp_vlei.report import _LABEL, CHECK_ORDER, VerificationReport
from mcp_vlei.signing import sign_request
from mcp_vlei.verifier import OfflineVerifier

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).parent / "static"
CREDENTIALS = ROOT / "credentials"

GATEWAY_URL = os.environ.get("VLEI_GATEWAY_URL", "http://localhost:3000/mcp")
SKILL_SERVER_URL = os.environ.get("VLEI_SKILL_SERVER_URL", "http://127.0.0.1:8082/mcp")

SCENE_COUNT = 6


def _load_local_env() -> None:
    """`scripts/.env` holds machine-local ports; the scripts and the containers read it too."""
    path = ROOT / "scripts" / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


_load_local_env()


def _reachable(witness: str) -> bool:
    try:
        return httpx.get(f"{witness}/oobi", timeout=2.0).status_code < 500
    except httpx.HTTPError:
        return False


# ------------------------------------------------------------------------------------------- #
# The environment: issued by the bootstrap, or minted in process
# ------------------------------------------------------------------------------------------- #

class Environment:
    """The credentials, keys and witness the console works against."""

    def __init__(self) -> None:
        witness = os.environ.get("VLEI_WITNESS_URL", "http://localhost:5642")
        env_file = CREDENTIALS / "env.json"
        forced_minted = os.environ.get("VLEI_CONSOLE_MINTED") == "1"
        self.live = (
            not forced_minted
            and env_file.exists()
            and (CREDENTIALS / "ecr.cesr").exists()
            and _reachable(witness)
        )
        self._signer: Any = None

        if self.live:
            env = json.loads(env_file.read_text(encoding="utf-8"))
            self.world = None
            self.root = env["acceptedRoots"][0]
            self.lei = env["lei"]
            self.role = env.get("role", "regulatory-filing")
            self.holder = env["ecrAid"]
            self.delegate = env.get("agentAid") or env["ecrAid"]
            self.witness = witness
            self.le_file = CREDENTIALS / "le.cesr"
        else:
            from mcp_vlei.testing import LEI, World

            self.world = World(role="regulatory-filing", label="console")
            self.root = self.world.root.pre
            self.lei = LEI
            self.role = "regulatory-filing"
            self.holder = self.world.holder.pre
            self.delegate = self.world.agent.pre
            self.witness = "http://in-process-witness"
            self.le_file = Path(tempfile.mkdtemp()) / "le.cesr"
            self.le_file.write_text(self.world.le_stream, encoding="utf-8")

    # -- what changes over a session --------------------------------------------------------- #

    @property
    def chain(self) -> str:
        if self.world is not None:
            return self.world.ecr_stream
        return (CREDENTIALS / "ecr.cesr").read_text(encoding="utf-8")

    @property
    def said(self) -> str:
        if self.world is not None:
            return self.world.ecr_credential.said
        return json.loads((CREDENTIALS / "env.json").read_text(encoding="utf-8"))["ecrSaid"]

    @property
    def le_stream(self) -> str:
        return self.le_file.read_text(encoding="utf-8").strip()

    def witness_client(self) -> httpx.AsyncClient | None:
        return self.world.witness_client() if self.world is not None else None

    @property
    def evidence(self) -> dict[str, str]:
        if self.live:
            return {"credentials": "issued", "revocation": "witness",
                    "signing": "keystore (kli sign)", "witness": self.witness}
        return {"credentials": "minted", "revocation": "in-process witness",
                "signing": "in-process key", "witness": "in process"}

    def signer(self) -> Any:
        """The agent's signer. Live: its key stays in the KERI keystore and `kli sign` signs."""
        if self._signer is None:
            if self.world is not None:
                self._signer = Signer.from_seed(self.world.agent.pre, self.world.agent.seed)
            else:
                sys.path.insert(0, str(ROOT / "examples" / "my-agent"))
                from kli_signer import agent_signer  # noqa: PLC0415

                self._signer = agent_signer()
        return self._signer

    # -- scene 3 ------------------------------------------------------------------------------ #

    async def revoke(self) -> None:
        """Withdraw the agent's ECR in the legal entity's transaction event log."""
        if self.world is not None:
            self.world.le_registry.revoke(self.world.ecr_credential.said)
            return
        env = json.loads((CREDENTIALS / "env.json").read_text(encoding="utf-8"))
        await _run(
            "docker", "compose", "-f", str(ROOT / "scripts" / "docker-compose.yml"),
            "exec", "-T", "keri-cli", "kli", "vc", "revoke",
            "--name", "le", "--alias", "le", "--registry-name", "leRegistry",
            "--said", env["ecrSaid"], "--send", env["ecrAid"],
        )

    async def reissue(self) -> None:
        """Issue a fresh ECR after a revocation, so the scenes after 3 have one to present."""
        if self.world is not None:
            self.world.reissue_ecr(datetime.now(timezone.utc).isoformat())
            return
        await _run("bash", str(ROOT / "scripts" / "bootstrap-credentials.sh"), "--reissue")


async def _run(*argv: str) -> str:
    # `docker compose exec` needs Git Bash's path conversion off, or container paths are rewritten.
    # A bash script must not inherit that: its own `curl -o /dev/null` then reaches the native curl
    # unconverted and fails to write. The bootstrap turns it off itself, around its `kli` calls.
    env = dict(os.environ)
    if argv[0] == "docker":
        env["MSYS_NO_PATHCONV"] = "1"
    else:
        env.pop("MSYS_NO_PATHCONV", None)
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
    )
    out, _ = await process.communicate()
    text = out.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:3])} failed: {text[-400:]}")
    return text


ENV = Environment()


# ------------------------------------------------------------------------------------------- #
# Scenes
# ------------------------------------------------------------------------------------------- #

SCENES: dict[int, dict[str, Any]] = {
    0: {"title": "Impersonation", "mode": "plain", "tool": "reserve_gpu_quota",
        "target": "impersonation"},
    1: {"title": "A verified call", "mode": "vlei", "tool": "submit_filing",
        "target": "extension"},
    2: {"title": "Client without the extension", "mode": "plain", "tool": "submit_filing",
        "target": "extension"},
    3: {"title": "Revocation", "mode": "vlei", "tool": "submit_filing",
        "target": "extension"},
    4: {"title": "Through the gateway", "mode": "vlei", "tool": "submit_filing",
        "target": "gateway", "serverLabel": "regulator-gateway"},
    5: {"title": "A server written from the skill", "mode": "vlei", "tool": "submit_filing",
        "target": "skill-server", "serverLabel": "skill-server",
        "serverNote": "generated from skill"},
}

ARGUMENTS = {"form": "A1", "period": "2026Q2", "payload": {"totalAssets": 84_200_000}}

#: Scene 0's claim, the one it actually sends. Everything a well-known client would plausibly
#: send, and nothing that anything checks.
IMPERSONATION_CLAIM = {
    "name": "Claude Desktop",
    "version": "1.2.3",
    "description": "Anthropic official client",
    "websiteUrl": "https://claude.ai",
}
IMPERSONATION_HOURS = 50

#: Filled by the first scene-0 load and reused: spawning the server takes a couple of seconds, and
#: it answers the same way every time.
_impersonation_result: dict[str, Any] | None = None


async def _run_impersonation() -> dict[str, Any]:
    """Call `examples/impersonation/vendor_server.py` and return what it actually granted.

    Scene 0's number is measured, not asserted. A hardcoded "50 hours" would be the one thing on
    screen written by hand — precisely the thing someone should ask about in questions.
    """
    global _impersonation_result
    if _impersonation_result is not None:
        return _impersonation_result

    from mcp import StdioServerParameters
    from mcp.client.client import Client
    from mcp.types import Implementation

    server = ROOT / "examples" / "impersonation" / "vendor_server.py"
    fallback = {"approved": None, "tier": None, "received": None, "live": False}
    if not server.exists():
        _impersonation_result = fallback
        return fallback

    try:
        params = StdioServerParameters(command=sys.executable, args=[str(server)])
        async with Client(params, client_info=Implementation(**IMPERSONATION_CLAIM)) as client:
            result = await client.call_tool("reserve_gpu_quota", {"hours": IMPERSONATION_HOURS})
        payload = getattr(result, "structured_content", None)
        if not isinstance(payload, dict):
            for item in getattr(result, "content", []) or []:
                text = getattr(item, "text", None)
                if text:
                    payload = json.loads(text)
                    break
        payload = payload or {}
        _impersonation_result = {
            "approved": payload.get("approved"),
            "tier": payload.get("tier"),
            "received": (payload.get("clientInfoAsReceived") or {}).get("name"),
            "live": True,
        }
    except Exception:  # noqa: BLE001 - a scene that cannot measure says so rather than inventing
        _impersonation_result = fallback
    return _impersonation_result


def requirement() -> dict[str, Any]:
    return {"credential": "ECR", "role": ENV.role}


# ------------------------------------------------------------------------------------------- #
# Running a scene
# ------------------------------------------------------------------------------------------- #

def _signed_meta() -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign the scene's call as the agent. Returns (request _meta, signature)."""
    signer = ENV.signer()
    signature = sign_request(signer, "tools/call", {"name": "submit_filing", "arguments": ARGUMENTS})
    meta = {
        "org.gleif.vlei/credential": ENV.chain,
        "org.gleif.vlei/credentialSaid": ENV.said,
        "org.gleif.vlei/signature": signature,
    }
    if ENV.delegate != ENV.holder:
        meta["org.gleif.vlei/delegatedAid"] = ENV.delegate
    return meta, signature


def _extension() -> VleiIdentity:
    return VleiIdentity(
        le_credential=ENV.le_file,
        accepted_roots=[ENV.root],
        revocation_source="tel",
        witness_url=ENV.witness,
        witness_client=ENV.witness_client(),
    )


async def _in_process(scene: dict[str, Any], meta: dict[str, Any] | None) -> dict[str, Any]:
    """Run the extension's own verification on the call, exactly as `intercept_tool_call` would."""
    from mcp.types import CallToolRequestParams

    body: dict[str, Any] = {"name": scene["tool"], "arguments": ARGUMENTS}
    if meta:
        body["_meta"] = meta
    report = VerificationReport(tool=scene["tool"])
    try:
        await _extension().verify_call(
            CallToolRequestParams.model_validate(body), requirement(), report=report
        )
    except VleiError:
        pass
    return {"reachable": True, "report": report.as_dict()}


async def _remote(scene: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """Send the call to a real server — the gateway or the skill-generated one — and read back the
    report it attaches. Nothing here decides the outcome; the server does."""
    url = GATEWAY_URL if scene["target"] == "gateway" else SKILL_SERVER_URL
    try:
        if scene["target"] == "gateway":
            sys.path.insert(0, str(ROOT / "examples" / "regulator"))
            from gateway_client import call_through_gateway  # noqa: PLC0415

            outcome = await call_through_gateway(url, scene["tool"], ARGUMENTS, meta)
            if not outcome.get("allowed") and not outcome.get("layer") and str(
                outcome.get("text", "")
            ).startswith("transport error"):
                # Nothing refused this call: nothing received it.
                return {"reachable": False, "url": url, "error": outcome["text"][:240]}
            return {"reachable": True, "report": outcome.get("report"),
                    "allowed": outcome.get("allowed"), "layer": outcome.get("layer"),
                    "text": outcome.get("text"), "url": url}

        from mcp.client.client import Client
        from mcp_vlei import VleiCapability

        # Declare the extension, as a vLEI-aware client does: a server that requires it answers an
        # undeclared caller with -32021 before it verifies anything.
        async with Client(url, extensions=[VleiCapability()]) as client:
            try:
                result = await client.call_tool(scene["tool"], ARGUMENTS, meta=meta)
            except Exception as exc:  # noqa: BLE001 - a JSON-RPC refusal, reported as such
                return {"reachable": True, "report": None, "allowed": False,
                        "layer": getattr(getattr(exc, "error", None), "code", None) or
                        type(exc).__name__, "text": str(exc)[:240], "url": url}
        result_meta = getattr(result, "meta", None) or {}
        text = next((getattr(c, "text", "") for c in result.content or []), "")
        return {"reachable": True, "report": result_meta.get("org.gleif.vlei/report"),
                "allowed": not result.is_error,
                "layer": text.split(":", 1)[0] if result.is_error else None,
                "text": text, "url": url}
    except Exception as exc:  # noqa: BLE001 - an unreachable server is reported, not replaced
        return {"reachable": False, "url": url, "error": f"{type(exc).__name__}: {exc}"[:240]}


def _checks(report: dict[str, Any] | None, scene: dict[str, Any]) -> list[dict[str, Any]]:
    if scene["target"] == "impersonation" or report is None:
        # Scene 0 runs no checks at all: the server it models has nothing to check. A remote
        # scene whose server is down has no report to show.
        status = "skipped" if scene["target"] == "impersonation" else "pending"
        # The same labels scene 1 shows: scenes 0 and 1 are compared side by side, and the only
        # thing that should differ is whether anything ran.
        return [{"id": name, "label": _LABEL[name], "status": status,
                 "ms": None, "detail": None} for name in CHECK_ORDER]
    out = []
    for check in report["checks"]:
        status = {True: "pass", False: "fail", None: "pending"}[check["passed"]]
        out.append({
            "id": check["name"], "label": check["label"], "status": status,
            "ms": round(check["durationMs"], 1) if check["passed"] is True else None,
            "detail": check["detail"] if check["passed"] is False else None,
        })
    failed = next((i for i, c in enumerate(out) if c["status"] == "fail"), None)
    if failed is not None:
        for check in out[failed + 1:]:
            check["status"] = "skipped"
    return out


def _outcome(run: dict[str, Any], scene: dict[str, Any]) -> dict[str, Any]:
    if scene["target"] == "impersonation":
        measured = _impersonation_result or {}
        if measured.get("live"):
            note = (
                f"approved {measured['approved']} hours · {measured['tier']} tier · "
                f"granted on the name {measured['received']!r}, which the caller chose"
            )
        else:
            note = "the impersonation server could not be reached; nothing was measured"
        return {"status": "self-asserted", "layer": None, "note": note}
    if not run.get("reachable"):
        return {"status": "unavailable", "layer": None,
                "note": f"{run['url']} is not running — {run.get('error', '')}"}
    report = run.get("report") or {}
    failure = next((c for c in report.get("checks", []) if c.get("passed") is False), None)
    if failure:
        return {"status": "refused", "layer": failure.get("layer"), "note": failure.get("detail")}
    if run.get("allowed") is False:
        return {"status": "refused", "layer": run.get("layer"), "note": run.get("text")}
    note = {
        "gateway": f"executed by the filing server behind {run.get('url')}; it holds no vLEI code",
        "skill-server": f"executed by examples/skill-server at {run.get('url')}",
    }.get(scene["target"])
    return {"status": "allowed", "layer": None, "note": note}


async def _server_status() -> str:
    """The server's own LE credential, verified — not asserted by the console."""
    try:
        await OfflineVerifier([ENV.root]).verify(ENV.le_stream)
        return "valid"
    except VleiError:
        return "invalid"


def _agent_card(scene: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    if scene["target"] == "impersonation" or outcome["layer"] == "missing_credential":
        status = "unverified"
    elif outcome["status"] == "allowed":
        status = "valid"
    elif outcome["layer"] == "revoked":
        status = "revoked"
    elif outcome["status"] == "unavailable":
        status = "unverified"
    else:
        status = "refused"
    card = {"role": "AGENT", "type": "ECR", "lei": ENV.lei[:8] + "…", "label": ENV.role,
            "status": status}
    if status == "revoked" and _revoked_at:
        card["revokedAt"] = _revoked_at
    return card


def _truncate(value: str, keep: int = 18) -> str:
    return value if len(value) <= keep else value[:keep] + "…"


def _request_json(scene: dict[str, Any], meta: dict[str, Any] | None) -> str:
    if scene["mode"] == "plain":
        return json.dumps(
            {"clientInfo": dict(IMPERSONATION_CLAIM),
             "name": scene["tool"],
             "arguments": {"hours": IMPERSONATION_HOURS}
                          if scene["tool"] == "reserve_gpu_quota" else ARGUMENTS},
            indent=2, ensure_ascii=False,
        )
    meta = meta or {}
    signature = meta.get("org.gleif.vlei/signature", {})
    shown = {
        "org.gleif.vlei/credential": _truncate(meta.get("org.gleif.vlei/credential", "")),
        "org.gleif.vlei/signature": {
            "aid": signature.get("aid", ""),
            "ts": signature.get("ts", ""),
            "digest": _truncate(signature.get("digest", ""), 22),
            "sig": _truncate(signature.get("sig", ""), 22),
        },
        "org.gleif.vlei/credentialSaid": meta.get("org.gleif.vlei/credentialSaid", ""),
    }
    if "org.gleif.vlei/delegatedAid" in meta:
        shown["org.gleif.vlei/delegatedAid"] = meta["org.gleif.vlei/delegatedAid"]
    # ensure_ascii=False: the truncation mark is "…"; escaped, it showed on screen as its escape.
    return json.dumps({"_meta": shown, "name": scene["tool"], "arguments": ARGUMENTS}, indent=2,
                      ensure_ascii=False)


def _agent_diff() -> str:
    """Scene 4's claim that the agent did not change, measured: `git diff` of the agent's code."""
    try:
        out = subprocess.run(
            ["git", "diff", "--stat", "HEAD", "--", "examples/my-agent/"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"git diff could not run: {exc}"
    return out.stdout.strip() or "git diff HEAD -- examples/my-agent/ — no output"


# ------------------------------------------------------------------------------------------- #
# State
# ------------------------------------------------------------------------------------------- #

STATE: dict[str, Any] = {"scene": 0, "identities": {}, "request": {}, "verification": {}, "log": []}
_subscribers: list[asyncio.Queue] = []

#: When this session revoked the ECR, for the stamp on the card. Set only by an actual revocation.
_revoked_at: str | None = None


def _log(text: str) -> None:
    STATE["log"] = ([{"ts": datetime.now().strftime("%H:%M:%S"), "text": text}]
                    + STATE["log"])[:6]


async def _publish() -> None:
    for queue in list(_subscribers):
        await queue.put(dict(STATE))


async def load_scene(n: int) -> None:
    scene = SCENES[n]
    meta: dict[str, Any] | None = None
    if scene["target"] == "impersonation":
        await _run_impersonation()
        run: dict[str, Any] = {"reachable": True, "report": None}
    else:
        if scene["mode"] == "vlei":
            meta, _ = _signed_meta()
        if scene["target"] == "extension":
            run = await _in_process(scene, meta)
        else:
            run = await _remote(scene, meta or {})

    outcome = _outcome(run, scene)
    if scene["target"] == "gateway" and outcome["status"] == "allowed":
        outcome["agentDiff"] = _agent_diff()

    server = {"role": "SERVER", "type": "LE", "lei": ENV.lei[:8] + "…",
              "label": scene.get("serverLabel", "association-server"),
              "status": await _server_status() if scene["target"] != "impersonation"
              else "unverified"}
    if scene.get("serverNote"):
        server["note"] = scene["serverNote"]

    STATE["scene"] = n
    STATE["sceneTitle"] = scene["title"]
    STATE["identities"] = {"server": server, "agent": _agent_card(scene, outcome)}
    STATE["request"] = {"method": "tools/call", "name": scene["tool"],
                        "json": _request_json(scene, meta), "mode": scene["mode"],
                        "target": scene["target"]}
    STATE["verification"] = {"checks": _checks(run.get("report"), scene), "outcome": outcome}
    STATE["evidence"] = ENV.evidence

    # A scene that should allow but refuses because the credential is withdrawn needs a re-issue
    # before the take. Say so here rather than letting it be discovered mid-take.
    expects_allow = n in (1, 4, 5)
    withdrawn = outcome["status"] == "refused" and outcome["layer"] == "revoked"
    STATE["readiness"] = (
        ("the agent's ECR was revoked in scene 3 — press I to re-issue it before this scene"
         if _revoked_at else
         "the agent's credential was already revoked before this session — "
         "run scripts/bootstrap-credentials.sh --reissue before recording")
        if expects_allow and withdrawn else None
    )
    _log(f"scene {n} · {scene['title']}")
    await _publish()


# ------------------------------------------------------------------------------------------- #

@asynccontextmanager
async def _lifespan(_: FastAPI):
    """Load scene 0 before the first request, so a browser opened early is never blank."""
    await load_scene(0)
    yield


app = FastAPI(title="mcp-vlei trust console", lifespan=_lifespan)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/console.css")
async def css() -> FileResponse:
    return FileResponse(STATIC / "console.css", media_type="text/css")


@app.get("/console.js")
async def js() -> FileResponse:
    return FileResponse(STATIC / "console.js", media_type="application/javascript")


@app.get("/state")
async def state() -> JSONResponse:
    return JSONResponse(STATE)


@app.post("/scene/{n}")
async def scene(n: int) -> JSONResponse:
    if n not in SCENES:
        return JSONResponse({"error": f"scene {n} does not exist"}, status_code=404)
    await load_scene(n)
    return JSONResponse({"scene": n})


@app.post("/revoke")
async def revoke() -> JSONResponse:
    """Revoke the agent's ECR — for real — and verify the same call again.

    Live, this is `kli vc revoke`: the withdrawal is written to the legal entity's transaction event
    log and read back from the witness, the same place any relying party reads it. Minted, it is a
    `rev` event anchored in the in-process LE's key event log. Either way the console does not set
    anything: the next verification finds the revocation or it does not.
    """
    global _revoked_at
    try:
        await ENV.revoke()
    except RuntimeError as exc:
        _log(f"revocation failed: {exc}")
        await load_scene(3)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    _revoked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _log("ECR revoked in the issuer's transaction event log")
    # The witness may take a moment to receive the event; read it back until it shows.
    for _ in range(20):
        await load_scene(3)
        if STATE["verification"]["outcome"].get("layer") == "revoked":
            break
        await asyncio.sleep(1.5)
    return JSONResponse({"ok": True, "revokedAt": _revoked_at,
                         "layer": STATE["verification"]["outcome"].get("layer")})


@app.post("/reissue")
async def reissue() -> JSONResponse:
    """Issue a fresh ECR after scene 3, so scenes 4 and 5 have a credential to present."""
    global _revoked_at
    try:
        await ENV.reissue()
    except RuntimeError as exc:
        _log(f"re-issue failed: {exc}")
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    _revoked_at = None
    _log("a fresh ECR was issued to the holder")
    await load_scene(STATE.get("scene", 0))
    return JSONResponse({"ok": True, "said": ENV.said})


@app.post("/reset")
async def reset() -> JSONResponse:
    STATE["log"] = []
    await load_scene(0)
    return JSONResponse({"ok": True})


@app.get("/events")
async def events() -> StreamingResponse:
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.append(queue)

    async def stream():
        try:
            yield f"data: {json.dumps(STATE)}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(payload)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            if queue in _subscribers:
                _subscribers.remove(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    print("trust console on http://localhost:8800")
    for key, value in ENV.evidence.items():
        print(f"  {key + ':':13}{value}")
    print(f"  gateway:     {GATEWAY_URL}")
    print(f"  skill:       {SKILL_SERVER_URL}")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8800")), log_level="warning")
