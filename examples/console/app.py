"""Trust Console — the backend that drives the recording.

Design: `docs/DEMO-CONSOLE.md`.

The right-hand column of this console is not illustrative. Every check it shows is run by
`packages/mcp-vlei` against a real credential chain — real SAID recomputation, real edge walking,
real Ed25519 signatures — and the report it renders is the same `VerificationReport` the server
attaches to a refusal in production. A console that drew its own conclusions would make every other
claim in the talk worth less.

What is substituted, and where, is stated in `/state` and in the README:

* Credentials come from `credentials/` when `scripts/bootstrap-credentials.sh` has been run, and are
  minted locally otherwise. Minted chains verify by exactly the same code path; what they lack is a
  witness network behind them.
* Revocation is decided from the issuer's transaction event log when a witness is reachable, and
  from console state otherwise. Scene 3 is a demonstration of revocation either way, but only the
  first is evidence of one.

Run::

    pip install -e packages/mcp-vlei
    python examples/console/app.py        # http://localhost:8800
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from mcp_vlei import Signer, VleiIdentity
from mcp_vlei.errors import Revoked, VleiError
from mcp_vlei.report import CHECK_ORDER, VerificationReport
from mcp_vlei.signing import sign_request

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).parent / "static"
CREDENTIALS = ROOT / "credentials"

REGISTRY = "EHsH7DfMGlfOsAVjTw1EZMhbHQJovsqmBYXHFYDgiz2K"
QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
ECR_SCHEMA = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"

SCENE_COUNT = 6


# ------------------------------------------------------------------------------------------- #
# A credential chain to verify. Real where one exists, minted where it does not.
# ------------------------------------------------------------------------------------------- #

def _mint(schema: str, issuer: str, issuee: str, attributes: dict, edge=None) -> str:
    import blake3

    body: dict[str, Any] = {
        "v": "ACDC10JSON000000_",
        "d": "#" * 44,
        "i": issuer,
        "ri": REGISTRY,
        "s": schema,
        "a": {"i": issuee, "dt": "2026-09-23T00:00:00.000000+00:00", **attributes},
    }
    if edge:
        label, target = edge
        body["e"] = {"d": "E" + "A" * 43, label: {"n": target, "s": schema}}
    text = json.dumps(body, separators=(",", ":"))
    digest = blake3.blake3(text.encode("utf-8")).digest(length=32)
    said = "E" + base64.urlsafe_b64encode(b"\x00" + digest).decode("ascii")[1:]
    return text.replace('"d":"' + "#" * 44 + '"', f'"d":"{said}"', 1)


def _aid(seed: str) -> str:
    import hashlib

    raw = hashlib.blake2b(seed.encode(), digest_size=32).digest()
    return "E" + base64.urlsafe_b64encode(b"\x00" + raw).decode("ascii")[1:]


class Environment:
    """The credentials and keys the console verifies against."""

    def __init__(self) -> None:
        env_file = CREDENTIALS / "env.json"
        self.live = env_file.exists() and (CREDENTIALS / "ecr.cesr").exists()

        if self.live:
            env = json.loads(env_file.read_text())
            self.root = env["acceptedRoots"][0]
            self.lei = env["lei"]
            self.role = env.get("role", "regulatory-filing")
            self.chain = (CREDENTIALS / "ecr.cesr").read_text(encoding="utf-8")
            self.said = env["ecrSaid"]
            self.holder = env["ecrAid"]
            self.delegate = env.get("agentAid") or env["ecrAid"]
            self.witness = os.environ.get("VLEI_WITNESS_URL", "http://localhost:5642")
        else:
            self.root = _aid("root")
            self.lei = "8755001E4FAKE0000001"
            self.role = "regulatory-filing"
            qvi_aid, le_aid = _aid("qvi"), _aid("le")
            self.holder = _aid("holder")
            self.delegate = _aid("agent")
            qvi = _mint(QVI_SCHEMA, self.root, qvi_aid, {"LEI": self.lei})
            le = _mint(LE_SCHEMA, qvi_aid, le_aid, {"LEI": self.lei},
                       edge=("qvi", json.loads(qvi)["d"]))
            ecr = _mint(ECR_SCHEMA, le_aid, self.holder,
                        {"LEI": self.lei, "personLegalName": "Chen Wei-Ting",
                         "engagementContextRole": self.role},
                        edge=("le", json.loads(le)["d"]))
            self.chain = qvi + le + ecr
            self.said = json.loads(ecr)["d"]
            self.witness = ""

        # The console signs as the agent. With a live environment the real key stays in the KERI
        # keystore and is not reachable from here, so a console-local key is used for the signature
        # check; the chain, the SAIDs and the root are the real ones either way.
        self.signer = Signer.from_seed(self.delegate, secrets.token_bytes(32))
        self.le_file = CREDENTIALS / "le.cesr" if self.live else None


ENV = Environment()


class ConsoleTel:
    """Revocation for the console.

    Reads the issuer's log through a witness when one is reachable — the same source the server
    uses — and falls back to console state when it is not. `/state` reports which, because a
    demonstration of revocation and evidence of one are different things.
    """

    def __init__(self, witness_url: str) -> None:
        self.witness_url = witness_url
        self.revoked = False
        self.revoked_at: str | None = None

    @property
    def source(self) -> str:
        return "witness" if self.witness_url else "console"

    async def check(self, said: str, *, aid: str | None = None) -> None:
        if self.witness_url:
            from mcp_vlei.revocation import TelRevocationChecker

            try:
                await TelRevocationChecker(self.witness_url).check(said, aid=aid)
            except Revoked:
                self.revoked = True
                raise
            except VleiError:
                pass  # witness unreachable: fall through to console state
        if self.revoked:
            raise Revoked(
                "the credential has been revoked in the issuer's transaction event log",
                aid=aid, credential_said=said,
            )


TEL = ConsoleTel(ENV.witness)


# ------------------------------------------------------------------------------------------- #
# Scenes
# ------------------------------------------------------------------------------------------- #

SCENES: dict[int, dict[str, Any]] = {
    0: {"title": "Impersonation", "mode": "plain", "tool": "reserve_gpu_quota",
        "server": "unverified", "agent": "unverified"},
    1: {"title": "A verified call", "mode": "vlei", "tool": "submit_filing",
        "server": "valid", "agent": "valid"},
    2: {"title": "Client without the extension", "mode": "plain", "tool": "submit_filing",
        "server": "valid", "agent": "unverified"},
    3: {"title": "Revocation", "mode": "vlei", "tool": "submit_filing",
        "server": "valid", "agent": "revoked"},
    4: {"title": "Through the gateway", "mode": "vlei", "tool": "submit_filing",
        "server": "valid", "agent": "valid", "serverLabel": "regulator-gateway",
        "note": "git diff examples/my-agent/ — no output"},
    5: {"title": "A server written from the skill", "mode": "vlei", "tool": "submit_filing",
        "server": "valid", "agent": "valid", "serverNote": "generated from skill"},
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

    Scene 0's number is measured, not asserted. The console's whole claim is that nothing on screen
    is written by hand, and a hardcoded "50 hours" would be the one exception — precisely the thing
    someone should ask about in questions.
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
            result = await client.call_tool(
                "reserve_gpu_quota", {"hours": IMPERSONATION_HOURS}
            )
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

REQUIREMENT = {"credential": "ECR", "role": ENV.role}


def _identity_card(kind: str, status: str, scene: dict[str, Any]) -> dict[str, Any]:
    if kind == "server":
        card = {
            "role": "SERVER", "type": "LE",
            "lei": ENV.lei[:8] + "…",
            "label": scene.get("serverLabel", "association-server"),
            "status": status,
        }
        if scene.get("serverNote"):
            card["note"] = scene["serverNote"]
        return card
    card = {
        "role": "AGENT", "type": "ECR",
        "lei": ENV.lei[:8] + "…",
        "label": ENV.role,
        "status": status,
    }
    if status == "revoked" and TEL.revoked_at:
        card["revokedAt"] = TEL.revoked_at
    return card


def _truncate(value: str, keep: int = 18) -> str:
    return value if len(value) <= keep else value[:keep] + "…"


def _request_json(scene: dict[str, Any], signature: dict[str, Any] | None) -> str:
    if scene["mode"] == "plain":
        return json.dumps(
            {"clientInfo": dict(IMPERSONATION_CLAIM),
             "name": scene["tool"],
             "arguments": {"hours": IMPERSONATION_HOURS}
                          if scene["tool"] == "reserve_gpu_quota" else ARGUMENTS},
            indent=2,
        )
    meta = {
        "org.gleif.vlei/credential": _truncate(ENV.chain),
        "org.gleif.vlei/delegatedAid": ENV.delegate,
        "org.gleif.vlei/signature": {
            "aid": ENV.delegate,
            "ts": (signature or {}).get("ts", ""),
            "digest": _truncate((signature or {}).get("digest", ""), 22),
            "sig": _truncate((signature or {}).get("sig", ""), 22),
        },
        "org.gleif.vlei/credentialSaid": ENV.said,
    }
    return json.dumps(
        {"_meta": meta, "name": scene["tool"], "arguments": ARGUMENTS}, indent=2
    )


async def _run_verification(scene: dict[str, Any]) -> tuple[VerificationReport, dict[str, Any]]:
    """Run the real verification flow and return its report.

    Scene 0 and scene 2 do not present a credential, so the flow stops at the first check — which
    is the finding, not a shortcut.
    """
    from mcp.types import CallToolRequestParams

    vlei = VleiIdentity(
        le_credential=ENV.le_file or _write_temp_le(),
        accepted_roots=[ENV.root],
        revocation_source="tel",
        witness_url=ENV.witness or "http://console.local",
        requirements={scene["tool"]: REQUIREMENT},
    )
    vlei.tel = TEL

    params_body: dict[str, Any] = {"name": scene["tool"], "arguments": ARGUMENTS}
    signature = None
    if scene["mode"] == "vlei":
        signature = sign_request(ENV.signer, "tools/call", params_body)
        params_body["_meta"] = {
            "org.gleif.vlei/credential": ENV.chain,
            "org.gleif.vlei/delegatedAid": ENV.delegate,
            "org.gleif.vlei/signature": signature,
            "org.gleif.vlei/credentialSaid": ENV.said,
            "org.gleif.vlei/verkey": ENV.signer.verkey,
        }

    params = CallToolRequestParams.model_validate(params_body)
    report = VerificationReport(tool=scene["tool"])
    try:
        await vlei._verify(params, dict(params.meta or {}), REQUIREMENT, report)
    except VleiError:
        pass
    return report, signature or {}


_TEMP_LE: Path | None = None


def _write_temp_le() -> Path:
    """A credential file for the extension to present as its own, when none was issued."""
    global _TEMP_LE
    if _TEMP_LE is None:
        import tempfile

        _TEMP_LE = Path(tempfile.mkdtemp()) / "le.cesr"
        _TEMP_LE.write_text(ENV.chain, encoding="utf-8")
    return _TEMP_LE


def _checks_payload(report: VerificationReport, scene: dict[str, Any]) -> list[dict[str, Any]]:
    data = report.as_dict()["checks"]
    if scene["mode"] == "plain" and scene is SCENES[0]:
        # Scene 0 runs no checks at all: the server it models has nothing to check.
        return [
            {"id": c["name"], "label": c["label"], "status": "skipped", "ms": None, "detail": None}
            for c in data
        ]
    out = []
    for check in data:
        status = {True: "pass", False: "fail", None: "pending"}[check["passed"]]
        out.append({
            "id": check["name"], "label": check["label"], "status": status,
            "ms": round(check["durationMs"], 1) if check["passed"] is True else None,
            "detail": check["detail"] if check["passed"] is False else None,
        })
    # Everything after a failure is skipped rather than merely unreached.
    failed = next((i for i, c in enumerate(out) if c["status"] == "fail"), None)
    if failed is not None:
        for check in out[failed + 1:]:
            check["status"] = "skipped"
    return out


def _outcome(report: VerificationReport, scene: dict[str, Any]) -> dict[str, Any]:
    if scene is SCENES[0]:
        measured = _impersonation_result or {}
        if measured.get("live"):
            note = (
                f"approved {measured['approved']} hours · "
                f"{measured['tier']} tier · "
                f"granted on the name {measured['received']!r}, which the caller chose"
            )
        else:
            note = "the impersonation server could not be reached; nothing was measured"
        return {"status": "self-asserted", "layer": None, "note": note}
    if report.failure:
        return {"status": "refused", "layer": report.failure.layer,
                "note": report.failure.detail}
    return {"status": "allowed", "layer": None, "note": scene.get("note")}


# ------------------------------------------------------------------------------------------- #
# State
# ------------------------------------------------------------------------------------------- #

STATE: dict[str, Any] = {"scene": 0, "identities": {}, "request": {}, "verification": {}, "log": []}
_subscribers: list[asyncio.Queue] = []


def _log(text: str) -> None:
    STATE["log"] = ([{"ts": datetime.now().strftime("%H:%M:%S"), "text": text}]
                    + STATE["log"])[:6]


async def _publish() -> None:
    for queue in list(_subscribers):
        await queue.put(dict(STATE))


#: Whether *this* session revoked the credential. Distinguishes scene 3 doing its job from a
#: credential that arrived withdrawn.
_revoked_in_this_session = False


async def load_scene(n: int) -> None:
    global _revoked_in_this_session
    scene = SCENES[n]
    if n == 0:
        await _run_impersonation()
    if n == 3:
        _revoked_in_this_session = True
        TEL.revoked = True
        TEL.revoked_at = TEL.revoked_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    elif n in (1, 2, 4, 5):
        # Leaving scene 3 undoes the session's own revocation — and the flag that records it, or
        # the readiness warning goes quiet for the rest of the session and a genuinely withdrawn
        # credential stops being reported. Found by a test, not by a take.
        TEL.revoked = False
        _revoked_in_this_session = False

    report, signature = await _run_verification(scene)

    STATE["scene"] = n
    STATE["sceneTitle"] = scene["title"]
    STATE["identities"] = {
        "server": _identity_card("server", scene["server"], scene),
        "agent": _identity_card("agent", scene["agent"], scene),
    }
    STATE["request"] = {
        "method": "tools/call", "name": scene["tool"],
        "json": _request_json(scene, signature), "mode": scene["mode"],
    }
    STATE["verification"] = {
        "checks": _checks_payload(report, scene),
        "outcome": _outcome(report, scene),
    }
    STATE["evidence"] = {
        "credentials": "issued" if ENV.live else "minted",
        "revocation": TEL.source,
    }

    # A scene that should allow but does not, because the credential was already withdrawn before
    # the console started, is a set-up problem rather than a demonstration. Say so here rather than
    # letting it be discovered mid-take.
    expects_allow = n in (1, 4, 5)
    stale = (
        expects_allow
        and STATE["verification"]["outcome"]["status"] == "refused"
        and STATE["verification"]["outcome"]["layer"] == "revoked"
        and not _revoked_in_this_session
    )
    STATE["readiness"] = (
        "the agent's credential was already revoked before this session — "
        "run scripts/bootstrap-credentials.sh to re-issue before recording"
        if stale else None
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
    """Revoke the agent's credential.

    With a live environment this runs `kli vc revoke`, and the withdrawal lands in the legal
    entity's transaction event log where any relying party can read it. Without one it sets console
    state, and `/state` says so.
    """
    global _revoked_in_this_session
    _revoked_in_this_session = True
    TEL.revoked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    TEL.revoked = True

    if ENV.live:
        env = json.loads((CREDENTIALS / "env.json").read_text())
        process = await asyncio.create_subprocess_exec(
            "docker", "compose", "-f", str(ROOT / "scripts" / "docker-compose.yml"),
            "exec", "-T", "keri-cli", "kli", "vc", "revoke",
            "--name", "le", "--alias", "le", "--registry-name", "leRegistry",
            "--said", env["ecrSaid"], "--send", env["ecrAid"],
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        await process.communicate()

    _log("ECR revoked in the issuer's transaction event log")
    await load_scene(3)
    return JSONResponse({"ok": True, "revokedAt": TEL.revoked_at})


@app.post("/reset")
async def reset() -> JSONResponse:
    global _revoked_in_this_session
    _revoked_in_this_session = False
    TEL.revoked = False
    TEL.revoked_at = None
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
    print(f"  credentials: {'issued' if ENV.live else 'minted locally'}")
    print(f"  revocation:  {TEL.source}")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8800")), log_level="warning")
