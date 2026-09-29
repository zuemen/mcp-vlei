"""Trust Console — the backend that drives the recording.

The right-hand column of this console is not illustrative. Every check it shows is run by
`packages/mcp-vlei` against a real credential chain, a real key event log and a real transaction
event log, and every call it shows is actually made:

* scene 0 calls `examples/impersonation/`, a server that trusts `clientInfo`, and measures what it
  granted;
* scenes 1-4 are labour-insurance filings — **simulated, not connected to the Bureau of Labor
  Insurance** — sent through agentgateway, where `vlei-authz` verifies each call against its policy
  and `examples/regulator/labor-insurance-sim/`, which holds no vLEI code, executes it.

A scene whose component is not running says so. It does not fall back to anything else.

Where the environment comes from is stated in `/state` (`evidence`):

* **issued** — `scripts/bootstrap-credentials.sh` has been run and its witness is reachable. The
  agent signs with its delegated AID's key inside the KERI keystore (`kli sign`); the console never
  holds it. Revocation is `kli vc revoke`, read back from the witness.
* **minted** — no environment. `mcp_vlei.testing.World` mints a real KERI deployment in process:
  real key event logs, registries and issuances, served by an in-process witness. There is no
  gateway for a minted world to reach, so scenes 1-4 run the same `verify_call`, with the gateway's
  own `policy.json`, in process — and the outcome says so.

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
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.namespace import keys as namespace_keys
from mcp_vlei.errors import VleiError
from mcp_vlei.report import _LABEL, CHECK_ORDER, VerificationReport
from mcp_vlei.signing import parse_utc_offset, sign_request, today_at
from mcp_vlei.verifier import OfflineVerifier

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).parent / "static"
CREDENTIALS = ROOT / "credentials"

GATEWAY_URL = os.environ.get("VLEI_GATEWAY_URL", "http://localhost:3000/mcp")
#: Scene 0's second mode reads the observatory's actual records (examples/observatory/). A URL — the
#: observatory's read-only /observatory.json — wins over the local log file.
OBSERVATORY_URL = os.environ.get("VLEI_OBSERVATORY_URL") or None
OBSERVATORY_LOG = Path(os.environ.get(
    "VLEI_OBSERVATORY_LOG", ROOT / "examples" / "observatory" / "data" / "observations.jsonl"))

#: The gateway's policy for the labour-insurance simulator: the same file vlei-authz loads.
POLICY_FILE = ROOT / "examples" / "regulator" / "vlei-authz" / "policy.json"
#: On screen whenever a labour-insurance scene is.
SIMULATED = "Simulated — not connected to the Bureau of Labor Insurance"
#: The employer's unified business number, as its LEI record's registeredAs field would give it.
REGISTERED_AS_FILE = ROOT / "examples" / "regulator" / "labor-insurance-sim" / "registered_as.json"


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
            self.role = env.get("role", "labor-insurance-filing")
            self.holder = env["ecrAid"]
            self.delegate = env.get("agentAid") or env["ecrAid"]
            self.witness = witness
            self.le_file = CREDENTIALS / "le.cesr"
        else:
            from mcp_vlei.testing import LEI, World

            self.world = World(role="labor-insurance-filing", label="console")
            self.root = self.world.root.pre
            self.lei = LEI
            self.role = "labor-insurance-filing"
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

    # -- the revocation scene ----------------------------------------------------------------- #

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
        """Issue a fresh ECR after a revocation, so the next take has one to present."""
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
    1: {"title": "Enrolment on the start date", "mode": "vlei", "tool": "enroll_employee",
        "arguments": {"person_ref": "EMP-0001", "start_date": 0, "salary_grade": 3},
        "expect": "allowed"},
    2: {"title": "The same agent adjusts a salary", "mode": "vlei",
        "tool": "adjust_insured_salary", "arguments": {"person_ref": "EMP-0001", "salary_grade": 4},
        "expect": "role_mismatch"},
    3: {"title": "Filing fifteen days ahead", "mode": "vlei", "tool": "enroll_employee",
        "arguments": {"person_ref": "EMP-0002", "start_date": 15, "salary_grade": 3},
        "expect": "scope_exceeded"},
    4: {"title": "The handler's ECR is revoked", "mode": "vlei", "tool": "enroll_employee",
        "arguments": {"person_ref": "EMP-0003", "start_date": 0, "salary_grade": 3},
        "expect": "allowed, then revoked"},
}
#: The scene whose REVOKE button withdraws the agent's ECR, on camera.
REVOCATION_SCENE = 4
#: Where scenes 1-4 go: the real gateway when there is an issued environment to trust, or the same
#: verification in process for a minted world, which no gateway trusts. Chosen, never fallen back to.
LABOUR_TARGET = ("gateway" if os.environ.get("VLEI_CONSOLE_TARGET") == "gateway"
                 else "policy" if os.environ.get("VLEI_CONSOLE_TARGET") == "policy" else None)


def _target(scene: dict[str, Any]) -> str:
    if scene.get("target"):
        return scene["target"]
    return LABOUR_TARGET or ("gateway" if ENV.live else "policy")


def _arguments(scene: dict[str, Any]) -> dict[str, Any]:
    """The scene's arguments, with dates as days from today: the rule is relative to the day."""
    out = dict(scene.get("arguments") or {})
    for name in ("start_date", "end_date"):
        if isinstance(out.get(name), int):
            out[name] = (_today() + timedelta(days=out[name])).isoformat()
    return out


def _unified_business_number() -> str | None:
    try:
        table = json.loads(REGISTERED_AS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return (table.get(ENV.lei) or {}).get("registeredAs")


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


def _policy() -> dict[str, Any]:
    return json.loads(POLICY_FILE.read_text(encoding="utf-8"))["tools"]


#: The rows scene 0's observed mode puts on screen, in order. The page at /observatory shows all of
#: them; a projector gets the ones a room can read.
OBSERVED_ROWS = ("clientInfo", "protocolVersion", "capabilities", "userAgent", "era")


def _observatory_module() -> Any:
    import importlib.util

    path = ROOT / "examples" / "observatory" / "observations.py"
    spec = importlib.util.spec_from_file_location("observatory_observations", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _observed() -> dict[str, Any]:
    """Scene 0, observed mode: the real connector beside the replay, as the observatory recorded
    them. Read, never written here — with nothing recorded yet, the scene says so."""
    source = OBSERVATORY_URL or str(OBSERVATORY_LOG.relative_to(ROOT)
                                    if OBSERVATORY_LOG.is_relative_to(ROOT) else OBSERVATORY_LOG)
    try:
        if OBSERVATORY_URL:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(OBSERVATORY_URL)
                response.raise_for_status()
                data = response.json()
        else:
            obs = _observatory_module()
            data = obs.summary(obs.ObservationLog(OBSERVATORY_LOG))
    except Exception as exc:  # noqa: BLE001 - an unreadable observatory is shown, not papered over
        return {"available": False, "source": source,
                "reason": f"the observatory could not be read ({type(exc).__name__})"}
    if not data.get("real") or not data.get("replay"):
        missing = "real client" if not data.get("real") else "replay"
        return {"available": False, "source": source,
                "reason": f"no {missing} recorded yet — run the experiment in examples/observatory"}
    rows = [r for r in data.get("rows", []) if r.get("key") in OBSERVED_ROWS]
    return {"available": True, "source": source, "rows": rows, "note": data.get("note"),
            "realAt": data["real"].get("ts"), "replayAt": data["replay"].get("ts")}


def _observed_outcome(observed: dict[str, Any]) -> dict[str, Any]:
    """What the right-hand column says in observed mode. The observatory grants nothing, so the
    measured scene's "approved 50 hours" must not stay on screen beside its records."""
    if not observed.get("available"):
        return {"status": "unavailable", "layer": None, "headline": "NOTHING RECORDED YET",
                "note": observed.get("reason")}
    verdicts = {r["key"]: r["verdict"] for r in observed.get("rows", [])}
    if verdicts.get("clientInfo") == "same":
        note = ("the server received the same clientInfo from both · "
                "neither says which legal entity is acting, which agent, or what it may do")
    else:
        note = ("clientInfo differs between the two records · every field on both sides is "
                "still self-asserted, and none names a legal entity, an agent, or an authorisation")
    return {"status": "self-asserted", "layer": None, "headline": "INDISTINGUISHABLE",
            "note": note}



# ------------------------------------------------------------------------------------------- #
# Running a scene
# ------------------------------------------------------------------------------------------- #

#: Every `_meta` name on screen and on the wire: `MCP_VLEI_NAMESPACE`, or the provisional default.
KEYS = namespace_keys()


def _signed_meta(scene: dict[str, Any], arguments: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign the scene's call as the agent. Returns (request _meta, signature)."""
    signer = ENV.signer()
    signature = sign_request(signer, "tools/call", {"name": scene["tool"], "arguments": arguments})
    meta = {
        KEYS.credential: ENV.chain,
        KEYS.credential_said: ENV.said,
        KEYS.signature: signature,
    }
    if ENV.delegate != ENV.holder:
        meta[KEYS.delegated_aid] = ENV.delegate
    return meta, signature


def _witness_urls() -> list[str] | None:
    """VLEI_WITNESS_URLS, comma-separated: every caller's key log is compared across them, and a
    fork refused. Unset, the one VLEI_WITNESS_URL is asked and nothing is compared."""
    urls = [u.strip() for u in os.environ.get("VLEI_WITNESS_URLS", "").split(",") if u.strip()]
    return urls or None


#: "Today" as the gateway counts it (VLEI_POLICY_UTC_OFFSET, +08:00 in deploy/agentgateway), so
#: the dates the console stamps and the window they are checked against are the same days.
POLICY_UTC_OFFSET = parse_utc_offset(os.environ.get("VLEI_POLICY_UTC_OFFSET", "").strip())


def _today() -> date:
    return today_at(POLICY_UTC_OFFSET)


def _extension() -> VleiIdentity:
    return VleiIdentity(
        le_credential=ENV.le_file,
        accepted_roots=[ENV.root],
        revocation_source="tel",
        witness_url=ENV.witness,
        witness_urls=_witness_urls() if ENV.live else None,
        witness_client=ENV.witness_client(),
        today=_today,
    )


async def _in_process(scene: dict[str, Any], meta: dict[str, Any] | None,
                      arguments: dict[str, Any]) -> dict[str, Any]:
    """The gateway's verification, run here: `verify_call` with the gateway's own policy."""
    from mcp.types import CallToolRequestParams

    body: dict[str, Any] = {"name": scene["tool"], "arguments": arguments}
    if meta:
        body["_meta"] = meta
    report = VerificationReport(tool=scene["tool"])
    try:
        await _extension().verify_call(
            CallToolRequestParams.model_validate(body), _policy()[scene["tool"]], report=report
        )
    except VleiError:
        pass
    return {"reachable": True, "report": report.as_dict()}


async def _remote(scene: dict[str, Any], meta: dict[str, Any],
                  arguments: dict[str, Any]) -> dict[str, Any]:
    """Send the call through the gateway to the simulator, and read back the report the gateway
    attaches. Nothing here decides the outcome; the gateway does."""
    url = GATEWAY_URL
    try:
        sys.path.insert(0, str(ROOT / "examples" / "regulator"))
        from gateway_client import call_through_gateway  # noqa: PLC0415

        outcome = await call_through_gateway(url, scene["tool"], arguments, meta)
        if not outcome.get("allowed") and not outcome.get("layer") and str(
            outcome.get("text", "")
        ).startswith("transport error"):
            # Nothing refused this call: nothing received it.
            return {"reachable": False, "url": url, "error": outcome["text"][:240]}
        return {"reachable": True, "report": outcome.get("report"),
                "allowed": outcome.get("allowed"), "layer": outcome.get("layer"),
                "text": outcome.get("text"), "url": url}
    except Exception as exc:  # noqa: BLE001 - an unreachable server is reported, not replaced
        return {"reachable": False, "url": url, "error": f"{type(exc).__name__}: {exc}"[:240]}


def _checks(report: dict[str, Any] | None, scene: dict[str, Any]) -> list[dict[str, Any]]:
    if _target(scene) == "impersonation" or report is None:
        # Scene 0 runs no checks at all: the server it models has nothing to check. A remote
        # scene whose server is down has no report to show.
        status = "skipped" if _target(scene) == "impersonation" else "pending"
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
    if _target(scene) == "impersonation":
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
        "gateway": (f"executed by labor-insurance-sim behind {run.get('url')}; it holds no vLEI "
                    "code"),
        "policy": ("verified in process with the gateway's policy, not through the gateway "
                   "(VLEI_CONSOLE_TARGET=policy)" if ENV.live else
                   "verified in process with the gateway's policy — a minted world, which no "
                   "gateway trusts"),
    }.get(_target(scene))
    return {"status": "allowed", "layer": None, "note": note}


async def _server_status() -> str:
    """The server's own LE credential, verified — not asserted by the console."""
    try:
        await OfflineVerifier([ENV.root]).verify(ENV.le_stream)
        return "valid"
    except VleiError:
        return "invalid"


def _agent_card(scene: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    if _target(scene) == "impersonation" or outcome["layer"] == "missing_credential":
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


def _request_json(scene: dict[str, Any], meta: dict[str, Any] | None,
                  arguments: dict[str, Any]) -> str:
    if scene["mode"] == "plain":
        return json.dumps(
            {"clientInfo": dict(IMPERSONATION_CLAIM),
             "name": scene["tool"],
             "arguments": {"hours": IMPERSONATION_HOURS}
                          if scene["tool"] == "reserve_gpu_quota" else arguments},
            indent=2, ensure_ascii=False,
        )
    meta = meta or {}
    signature = meta.get(KEYS.signature, {})
    shown = {
        KEYS.credential: _truncate(meta.get(KEYS.credential, "")),
        KEYS.signature: {
            "aid": signature.get("aid", ""),
            "ts": signature.get("ts", ""),
            "digest": _truncate(signature.get("digest", ""), 22),
            "sig": _truncate(signature.get("sig", ""), 22),
        },
        KEYS.credential_said: meta.get(KEYS.credential_said, ""),
    }
    if KEYS.delegated_aid in meta:
        shown[KEYS.delegated_aid] = meta[KEYS.delegated_aid]
    # ensure_ascii=False: the truncation mark is "…"; escaped, it showed on screen as its escape.
    return json.dumps({"_meta": shown, "name": scene["tool"], "arguments": arguments}, indent=2,
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

STATE: dict[str, Any] = {"scene": 0, "identities": {}, "request": {}, "verification": {}, "log": [],
                         "sceneMode": "measured", "observed": None}
_subscribers: list[asyncio.Queue] = []

#: When this session revoked the ECR, for the stamp on the card. Set only by an actual revocation.
_revoked_at: str | None = None


def _log(text: str) -> None:
    STATE["log"] = ([{"ts": datetime.now().strftime("%H:%M:%S"), "text": text}]
                    + STATE["log"])[:6]


async def _publish() -> None:
    for queue in list(_subscribers):
        await queue.put(dict(STATE))


async def load_scene(n: int, *, just_revoked: bool = False) -> None:
    scene = SCENES[n]
    target = _target(scene)
    arguments = _arguments(scene)
    meta: dict[str, Any] | None = None
    if target == "impersonation":
        await _run_impersonation()
        run: dict[str, Any] = {"reachable": True, "report": None}
    else:
        meta, _ = _signed_meta(scene, arguments)
        run = (await _remote(scene, meta, arguments) if target == "gateway"
               else await _in_process(scene, meta, arguments))

    outcome = _outcome(run, scene)
    if target == "gateway" and outcome["status"] == "allowed":
        outcome["agentDiff"] = _agent_diff()

    labour = target != "impersonation"
    ubn = _unified_business_number()
    employer = {"role": "EMPLOYER", "type": "LE", "lei": ENV.lei,
                "label": (f"統一編號 {ubn} (test value)" if ubn else "no 統一編號 on record"),
                "note": "linked to the LEI by its record's registeredAs field",
                "status": await _server_status() if labour else "unverified"}
    server = {"role": "SERVER", "type": "SIM", "lei": "labor-insurance-sim",
              "label": "enrolment and withdrawal", "note": SIMULATED,
              "status": "simulated" if labour else "unverified"}

    STATE["scene"] = n
    STATE["sceneCount"] = len(SCENES)
    STATE["namespace"] = KEYS.namespace  # what the page picks out in red
    STATE["sceneTitle"] = scene["title"]
    if n != 0:
        STATE["sceneMode"] = "measured"
    observed = n == 0 and STATE.get("sceneMode") == "observed"
    STATE["observed"] = await _observed() if observed else None
    if observed:
        STATE["sceneTitle"] = "Impersonation · real client vs replay"
    STATE["banner"] = SIMULATED if labour else None
    STATE["identities"] = {"employer": employer, "agent": _agent_card(scene, outcome),
                           "server": server}
    STATE["request"] = {"method": "tools/call", "name": scene["tool"],
                        "json": _request_json(scene, meta, arguments), "mode": scene["mode"],
                        "target": target}
    STATE["verification"] = {"checks": _checks(run.get("report"), scene), "outcome": outcome}
    if observed:
        STATE["request"]["name"] = "echo_identity"
        STATE["verification"]["outcome"] = _observed_outcome(STATE["observed"])
    STATE["evidence"] = ENV.evidence

    # A scene that should allow but refuses because the credential is withdrawn needs a re-issue
    # before the take. Say so here rather than letting it be discovered mid-take.
    expects_allow = n in (1, REVOCATION_SCENE)
    withdrawn = outcome["status"] == "refused" and outcome["layer"] == "revoked"
    STATE["readiness"] = (
        (f"the agent's ECR was revoked in scene {REVOCATION_SCENE} — press I to re-issue it "
         "before the next take"
         if _revoked_at else
         "the agent's credential was already revoked before this session — "
         "run scripts/bootstrap-credentials.sh --reissue before recording")
        # Not on the frame right after REVOKE: that refusal is the scene's point, on camera. The
        # reminder comes the next time a scene is loaded, before the next take.
        if expects_allow and withdrawn and not just_revoked else None
    )
    _log(f"scene {n} · {STATE['sceneTitle']}"
         + (f" · read from {STATE['observed']['source']}" if observed else ""))
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


@app.post("/scene/0/mode/{mode}")
async def scene_0_mode(mode: str) -> JSONResponse:
    """Scene 0 has two modes: `measured` (the in-process impersonation server) and `observed`
    (the observatory's records of a real client and a replay)."""
    if mode not in ("measured", "observed"):
        return JSONResponse({"error": f"scene 0 has no mode {mode!r}"}, status_code=404)
    STATE["sceneMode"] = mode
    await load_scene(0)
    return JSONResponse({"scene": 0, "mode": mode})


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
        await load_scene(REVOCATION_SCENE)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    _revoked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _log("ECR revoked in the issuer's transaction event log")
    # The witness may take a moment to receive the event; read it back until it shows.
    for _ in range(20):
        await load_scene(REVOCATION_SCENE, just_revoked=True)
        if STATE["verification"]["outcome"].get("layer") == "revoked":
            break
        await asyncio.sleep(1.5)
    return JSONResponse({"ok": True, "revokedAt": _revoked_at,
                         "layer": STATE["verification"]["outcome"].get("layer")})


@app.post("/reissue")
async def reissue() -> JSONResponse:
    """Issue a fresh ECR after the revocation scene, so the next take has a credential to present."""
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
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8800")), log_level="warning")
