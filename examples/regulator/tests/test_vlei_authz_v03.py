"""vlei-authz at v0.3: the gateway knows its audience, remembers nonces across restarts, refuses a
body with two readings, and never writes the person's name down."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from conftest import ARGS, GATEWAY_URL, LONG_AGO, authz, authz_app, name_leaked, rpc, signed_meta, signer_for

from mcp_vlei.audience import Audience
from mcp_vlei.replay import SqliteReplayStore
from mcp_vlei.signing import digest_params
from test_vlei_authz import ask, refused


async def test_a_call_signed_for_another_gateway_is_audience_mismatch(world, tmp_path):
    meta = signed_meta(world, audience=Audience("E" + "X" * 43, GATEWAY_URL))
    body = refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
                   "audience_mismatch")
    assert "not for this server" in body["message"]
    digest = next(c for c in body["report"]["checks"] if c["name"] == "digest")
    assert digest["layer"] == "audience_mismatch"


async def test_a_call_signed_for_another_url_is_audience_mismatch(world, tmp_path):
    meta = signed_meta(world, url="http://localhost:3000/mcp")
    body = refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
                   "audience_mismatch")
    assert "signed for http://localhost:3000/mcp, which is not this server's endpoint" in body["message"]
    assert "gateway.test" not in body["message"]


async def test_a_v02_signature_is_unsupported_version(world, tmp_path):
    signer = signer_for(world.agent)
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    digest = digest_params({"name": "enroll_employee", "arguments": ARGS})
    legacy = {"aid": signer.aid, "ts": ts, "digest": digest, "alg": "Ed25519",
              "sig": signer.sign(f"tools/call\n{ts}\n{digest}".encode())}
    meta = {**signed_meta(world), "org.gleif.vlei/signature": legacy}
    body = refused(await ask(authz_app(world, tmp_path), rpc("enroll_employee", ARGS, meta)),
                   "unsupported_version")
    assert "vlei-sig/0.2" in body["message"]


async def test_a_body_with_a_repeated_member_name_is_digest_mismatch(world, tmp_path):
    """Python reads the last `salary_grade`, another parser the first: no digest covers both."""
    text = rpc("enroll_employee", ARGS, signed_meta(world)).decode()
    doubled = text.replace('"salary_grade": 3', '"salary_grade": 3, "salary_grade": 30', 1)
    assert doubled != text
    app = authz_app(world, tmp_path)
    body = refused(await ask(app, doubled.encode()), "digest_mismatch")
    assert "no single reading" in body["message"]
    assert app.state.audit.records[-1]["tool"] == "enroll_employee"


async def test_a_replay_after_a_restart_is_still_a_replay(world, tmp_path):
    """Not merely ``stale_signature``: a gateway restarted on a *different*, empty store would
    answer that layer too (the memory-horizon refusal), without having remembered anything. Pin
    the specific replay message, and that the restarted store read back the *persisted*
    ``memory_since`` rather than starting a fresh one of its own."""
    path = tmp_path / "state" / "replay.sqlite3"
    body = rpc("enroll_employee", ARGS, signed_meta(world))
    first = authz_app(world, tmp_path, replay_store=SqliteReplayStore(path, clock=lambda: LONG_AGO))
    assert (await ask(first, body)).status_code == 200

    restarted = authz_app(world, tmp_path, replay_store=SqliteReplayStore(path))
    assert restarted.state.identity._replay.memory_since == LONG_AGO
    result = refused(await ask(restarted, body), "stale_signature")
    assert "already presented" in result["message"] and "nonce is spent" in result["message"]


def test_the_gateway_will_not_start_without_its_audience(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    settings = authz.Settings.from_env({"VLEI_ACCEPTED_ROOTS": world.root.pre,
                                        "VLEI_LE_CREDENTIAL": str(le)})
    with pytest.raises(RuntimeError, match="VLEI_AUDIENCE_URLS"):
        settings.identity()


def test_settings_read_the_audience_and_the_replay_db(world, tmp_path):
    le = tmp_path / "le.cesr"
    le.write_text(world.le_stream, encoding="utf-8")
    settings = authz.Settings.from_env({
        "VLEI_ACCEPTED_ROOTS": world.root.pre, "VLEI_LE_CREDENTIAL": str(le),
        "VLEI_AUDIENCE_URLS": "http://localhost:3000/mcp, http://127.0.0.1:3000/mcp",
        "VLEI_REPLAY_DB": str(tmp_path / "state" / "replay.sqlite3"),
    })
    identity = settings.identity()
    assert identity.recipient.aid == world.le.pre
    assert identity.recipient.urls == ("http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp")
    assert type(identity._replay).__name__ == "SqliteReplayStore"


async def test_health_says_who_the_gateway_is_and_where_it_remembers(world, tmp_path):
    app = authz_app(world, tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://a") as c:
        health = (await c.get("/health")).json()
    assert health["signatureFormats"] == ["vlei-sig/0.3"]
    assert health["audience"] == {"aid": world.le.pre, "urls": [GATEWAY_URL]}
    assert health["replayStore"]["kind"] == "MemoryReplayStore"


async def test_no_decision_record_names_the_person(world, tmp_path):
    person = json.loads(world.ecr_credential.raw)["a"]["personLegalName"]
    app = authz_app(world, tmp_path)
    await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))
    await ask(app, rpc("adjust_insured_salary", {"person_ref": "EMP-0001", "salary_grade": 4},
                       signed_meta(world, "adjust_insured_salary",
                                   {"person_ref": "EMP-0001", "salary_grade": 4})))
    await ask(app, rpc("enroll_employee", ARGS,
                       signed_meta(world, audience=Audience("E" + "X" * 43, GATEWAY_URL))))
    world.le_registry.revoke(world.ecr_credential.said)
    await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))

    log = (tmp_path / "audit" / "decisions.jsonl").read_text(encoding="utf-8")
    assert len(log.splitlines()) == 4
    assert not name_leaked(log, person)


async def test_an_integer_beyond_ijson_is_digest_mismatch_with_the_reason(world, tmp_path):
    """A 17-digit numeric reference has no portable canonical form: refused, and the reason says so."""
    args = {**ARGS, "salary_grade": 12345678901234567}
    body = refused(await ask(authz_app(world, tmp_path),
                             rpc("enroll_employee", args, signed_meta(world, arguments=ARGS))),
                   "digest_mismatch")
    assert "I-JSON" in body["message"]


# ------------------------------------------------------------------------------------------- #
# Resilience: an internal failure is a named refusal, never an unlabelled 500 (or an unhandled
# gRPC error) — on either wire, and whether the body itself or the verifier underneath it is what
# failed.
# ------------------------------------------------------------------------------------------- #

class _BrokenReplayStore:
    """The shape an unreachable or corrupted SQLite file takes, without needing one: a store whose
    ``claim`` always raises. ``memory_since`` is a plain attribute, not a ``@property`` — the
    verifier only duck-types it."""

    def __init__(self) -> None:
        self.memory_since = LONG_AGO

    def claim(self, aid: str, nonce: str, expires_at: Any) -> bool:
        raise RuntimeError("the replay store is unavailable")


async def test_a_replay_store_that_cannot_claim_is_verifier_error_over_http(world, tmp_path):
    """The store itself failing is this gateway's own fault, not the caller's: named, not an
    unlabelled 500, and never the exception's own text."""
    app = authz_app(world, tmp_path, replay_store=_BrokenReplayStore())
    response = await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))

    assert response.status_code == 503, response.text
    body = response.json()
    assert body["layer"] == "verifier_error"
    assert "unavailable" not in body["message"]
    assert response.headers["x-vlei-failure"] == "verifier_error"
    assert len(app.state.audit.records) == 1
    record = app.state.audit.records[-1]
    assert record["decision"] == "deny" and record["layer"] == "verifier_error"
    assert "unavailable" not in json.dumps(record)


async def test_a_replay_store_that_cannot_claim_is_verifier_error_over_grpc(world, tmp_path):
    """The same internal failure, reached through the gRPC wire: a denied ``CheckResponse``, never
    a raised (and so unlabelled, UNKNOWN-to-agentgateway) exception."""
    import socket
    import sys

    import grpc
    from conftest import REGULATOR, identity_for, serve

    sys.path.insert(0, str(REGULATOR / "vlei-authz" / "envoy_authz"))
    import ext_authz_pb2 as pb  # noqa: E402
    import ext_authz_pb2_grpc as pb_grpc  # noqa: E402

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    app = authz.create_app(
        identity=identity_for(world, tmp_path, replay_store=_BrokenReplayStore()),
        policy=authz.load_policy(authz.HERE / "policy.json"),
        audit=authz.Audit(path=tmp_path / "audit" / "decisions.jsonl"),
        grpc_port=port,
    )
    request = pb.CheckRequest()
    request.attributes.request.http.raw_body = rpc("enroll_employee", ARGS, signed_meta(world))
    async with serve(app):
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            # If Check() ever raised instead of answering, this call would raise AioRpcError
            # (status UNKNOWN) rather than failing a plain assertion below.
            response = await pb_grpc.AuthorizationStub(channel).Check(request, timeout=20)

    assert response.status.code == 7  # google.rpc.Code.PERMISSION_DENIED
    assert response.status.message == "verifier_error"
    decoded = json.loads(response.denied_response.body)
    assert "verifier_error" in json.dumps(decoded)
    assert "unavailable" not in json.dumps(decoded)
    assert len(app.state.audit.records) == 1
    assert app.state.audit.records[-1]["layer"] == "verifier_error"


async def test_a_body_the_lenient_reparse_also_cannot_read_is_refused_not_500(world, tmp_path):
    """A repeated-member body is normally answered as ``digest_mismatch`` by re-reading it
    leniently to find the call to answer (see the repeated-member-name test above). A number with
    more digits than Python's own int-from-string conversion allows defeats *that* re-read too —
    there is no reading left to recover a call from, so it is simply unreadable, the same as any
    other body that is not JSON. Never an unhandled 500."""
    huge = "9" * 4301
    text = rpc("enroll_employee", ARGS, signed_meta(world)).decode()
    tampered = text.replace('"salary_grade": 3', f'"salary_grade": {huge}', 1)
    assert tampered != text
    app = authz_app(world, tmp_path)
    response = await ask(app, tampered.encode())

    assert response.status_code == 403, response.text
    body = response.json()
    assert body["layer"] is None
    assert "not JSON" in body["message"]
    assert app.state.audit.records[-1]["decision"] == "deny"
