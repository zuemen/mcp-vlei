"""The decision record carries the caller's signature, and re-verifies offline.

"When it goes wrong? A signed record names who is accountable": every record of a signed call
stores the statement the caller signed, the signature and the key state it was checked against, and
``scripts/verify-audit.py`` re-checks it with nothing but the record — after a key rotation too. A
record altered afterwards does not verify.
"""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout
from typing import Any

from conftest import ARGS, ROOT, answer_at, authz_app, labor, load, rpc, serve, signed_meta, stand_in_gateway

import gateway_client
from mcp_vlei import Signer
from mcp_vlei.audience import Audience
from mcp_vlei.signing import canonicalize, digest_params
from mcp_vlei.testing import LEI
from test_vlei_authz import ask, decode

verify_audit = load("verify_audit_script", ROOT / "scripts" / "verify-audit.py")


def records(tmp_path) -> list[dict[str, Any]]:
    log = tmp_path / "audit" / "decisions.jsonl"
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def run(path) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out):
        code = verify_audit.main([str(path)])
    return code, out.getvalue()


async def accepted(world, tmp_path) -> dict[str, Any]:
    app = authz_app(world, tmp_path)
    response = await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))
    assert response.status_code == 200, response.text
    return records(tmp_path)[-1]


async def test_an_accepted_record_stores_the_signed_statement_signature_and_key_state(world, tmp_path):
    record = await accepted(world, tmp_path)
    signed = record["signedRequest"]
    stmt = signed["statement"]

    assert set(stmt) == {"aid", "aud", "cred", "digest", "exp", "method", "nonce", "ts", "v"}
    assert stmt["v"] == "vlei-sig/0.3" and stmt["method"] == "tools/call"
    assert stmt["aid"] == world.agent.pre == record["delegateAid"]
    assert stmt["cred"] == world.ecr_credential.said == record["credentialSaid"]
    assert stmt["aud"]["aid"] == world.le.pre
    assert stmt["digest"] == signed["receivedDigest"] == digest_params(
        {"name": "enroll_employee", "arguments": ARGS})
    assert signed["sig"].startswith("0B")
    state = signed["keyState"]
    assert state["aid"] == world.agent.pre and state["sn"] == world.agent.sn
    assert state["eventSaid"] == world.agent.events[-1].said
    assert state["keys"] == [k.qb64 for k in world.agent.keys]
    # The old fields are untouched, and argument values are still never written.
    assert record["decision"] == "allow" and record["lei"] == LEI
    assert record["argumentNames"] == sorted(ARGS)
    assert "EMP-0001" not in json.dumps(signed)


async def test_verify_audit_holds_for_the_log_and_names_who_signed(world, tmp_path):
    await accepted(world, tmp_path)
    code, out = run(tmp_path / "audit" / "decisions.jsonl")
    assert code == 0, out
    assert "HOLDS" in out and f"LEI={LEI}" in out
    assert f"signed by {world.agent.pre}" in out and f"holder={world.holder.pre}" in out
    assert "1 hold, 0 fail" in out


async def test_a_record_altered_afterwards_fails(world, tmp_path):
    record = await accepted(world, tmp_path)
    assert verify_audit.verify_record(record)["holds"] is True

    def altered(change) -> dict[str, Any]:
        copied = copy.deepcopy(record)
        change(copied)
        return verify_audit.verify_record(copied)

    other = digest_params({"name": "enroll_employee", "arguments": {**ARGS, "salary_grade": 30}})
    # Both digests rewritten to another filing: the signature no longer covers the statement.
    both = altered(lambda r: r["signedRequest"]["statement"].update(digest=other)
                   or r["signedRequest"].update(receivedDigest=other))
    assert both["holds"] is False and both["signatureVerifies"] is False
    # Only what arrived rewritten: the signature holds, but it was not over these arguments.
    received = altered(lambda r: r["signedRequest"].update(receivedDigest=other))
    assert received["holds"] is False and received["signatureVerifies"] is True
    assert any("digest" in p for p in received["problems"])
    sig = record["signedRequest"]["sig"]
    flipped = altered(lambda r: r["signedRequest"].update(sig=sig[:10] + ("A" if sig[10] != "A" else "B") + sig[11:]))
    assert flipped["holds"] is False
    # Someone else's key put in the record: not the signer's key state.
    swapped = altered(lambda r: r["signedRequest"]["keyState"].update(keys=[world.holder.keys[0].qb64]))
    assert swapped["holds"] is False
    # Blame moved to another holder.
    blamed = altered(lambda r: r.update(delegateAid=world.holder.pre))
    assert blamed["holds"] is False
    # The signature stripped from an accepted call.
    stripped = altered(lambda r: r.pop("signedRequest"))
    assert stripped["holds"] is False

    tampered = tmp_path / "tampered.jsonl"
    bad = copy.deepcopy(record)
    bad["signedRequest"]["statement"]["digest"] = other
    tampered.write_text(json.dumps(record) + "\n" + json.dumps(bad) + "\n", encoding="utf-8")
    code, out = run(tampered)
    assert code == 1 and "1 hold, 1 fail" in out


async def test_it_still_verifies_after_the_signer_rotates(world, tmp_path):
    app = authz_app(world, tmp_path)
    assert (await ask(app, rpc("enroll_employee", ARGS, signed_meta(world)))).status_code == 200
    before = records(tmp_path)[-1]["signedRequest"]["keyState"]

    world.agent.rotate()
    after_args = {**ARGS, "person_ref": "EMP-0002"}
    assert (await ask(app, rpc("enroll_employee", after_args,
                               signed_meta(world, arguments=after_args)))).status_code == 200
    after = records(tmp_path)[-1]["signedRequest"]["keyState"]
    assert after["sn"] == before["sn"] + 1 and after["keys"] != before["keys"]

    code, out = run(tmp_path / "audit" / "decisions.jsonl")
    assert code == 0 and "2 hold, 0 fail" in out, out


async def test_a_refused_call_keeps_what_was_signed_and_is_consistent(world, tmp_path):
    app = authz_app(world, tmp_path)
    meta = signed_meta(world)  # signed for ARGS, sent with other arguments
    response = await ask(app, rpc("enroll_employee", {**ARGS, "salary_grade": 30}, meta))
    assert response.status_code == 403 and response.json()["layer"] == "digest_mismatch"
    record = records(tmp_path)[-1]
    signed = record["signedRequest"]
    assert signed["statement"]["digest"] != signed["receivedDigest"]
    assert signed["keyState"] is None  # refused before any witness was asked
    verdict = verify_audit.verify_record(record)
    assert verdict["holds"] is True and verdict["decision"] == "refused"
    assert verdict["signer"] == world.agent.pre


async def test_the_receipt_carries_the_signed_request_and_verifies(world, tmp_path):
    labor.INSURED.clear()
    authz = authz_app(world, tmp_path)
    async with serve(labor.create_app()) as upstream:
        async with serve(stand_in_gateway(authz, upstream)) as base:
            url = f"{base}/mcp"
            answer_at(authz, url)
            meta = gateway_client.signed_meta(
                credential=world.ecr_stream,
                signer=Signer.from_seed(world.agent.pre, world.agent.seed),
                tool="enroll_employee", arguments=ARGS, audience=Audience(world.le.pre, url),
                delegated_aid=world.agent.pre, credential_said=world.ecr_credential.said,
            )
            out = await gateway_client.call_through_gateway(url, "enroll_employee", ARGS, meta)
    labor.INSURED.clear()
    assert out["allowed"] is True, out["text"]
    receipt = json.loads(out["text"][out["text"].index("{"):])
    assert receipt["signedRequest"] == records(tmp_path)[-1]["signedRequest"]
    verdict = verify_audit.verify_record(receipt)
    assert verdict["holds"] is True and verdict["receipt"] is True
    assert verdict["lei"] == LEI and verdict["agentAid"] == world.agent.pre
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    assert run(path)[0] == 0


def test_the_statement_stored_is_exactly_what_was_signed(world):
    """No gateway: sign, store, rebuild — the bytes verified are JCS of the stored statement."""
    from mcp_vlei.signing import sign_request, statement

    signer = Signer.from_seed(world.agent.pre, world.agent.seed)
    params = {"name": "enroll_employee", "arguments": ARGS}
    sig = sign_request(signer, "tools/call", params, audience=Audience(world.le.pre, "http://x/mcp"),
                       credential_said=world.ecr_credential.said)
    stmt = statement(aid=sig["aid"], aud=sig["aud"], cred=world.ecr_credential.said,
                     digest=sig["digest"], ts=sig["ts"], exp=sig["exp"], nonce=sig["nonce"])
    signed = {"statement": json.loads(canonicalize(stmt)), "sig": sig["sig"], "alg": "Ed25519",
              "receivedDigest": digest_params(params),
              "keyState": {"aid": world.agent.pre, "sn": world.agent.sn,
                           "keys": [k.qb64 for k in world.agent.keys]}}
    assert verify_audit.signature_verifies(signed)[0] is True
