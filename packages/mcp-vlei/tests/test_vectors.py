"""The published test vectors in spec/examples/digest-vectors.json, held against this package.

A second implementer needs to know exactly which bytes the digest covers — the skill-generated
server had to guess (examples/skill-server/REPORT.md, gap 11). The vectors settle it, and this test
keeps the package and the vectors from drifting apart.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_vlei import Signer
from mcp_vlei.errors import InvalidSignature
from mcp_vlei.namespace import DEFAULT, keys
from mcp_vlei.signing import (
    arguments_satisfied,
    canonicalize,
    digest_params,
    signed_payload,
    verify_request,
)

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "examples" / "digest-vectors.json"
pytestmark = pytest.mark.skipif(not VECTORS.is_file(), reason="needs the repository's spec/")


def vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", vectors()["digests"] if VECTORS.is_file() else [],
                         ids=lambda v: v["note"][:40])
def test_digest_vectors(vector):
    params = vector["params"]
    without_meta = {k: v for k, v in params.items() if k != "_meta"}
    assert canonicalize(without_meta).decode("utf-8") == vector["canonical"]
    assert digest_params(params) == vector["digest"]


def test_signature_vector():
    v = vectors()["signature"]
    signer = Signer.from_seed("E" + "A" * 43, bytes.fromhex(v["seedHex"]))

    assert signer.verkey == v["verkey"]
    assert signed_payload(v["method"], v["ts"], v["digest"]).decode("utf-8") == v["payload"]
    assert signer.sign(v["payload"].encode("utf-8")) == v["sig"]  # Ed25519 is deterministic
    params = vectors()["digests"][0]["params"]
    signature = {"aid": signer.aid, "ts": v["ts"], "digest": v["digest"], "sig": v["sig"]}
    verify_request(signature, v["method"], params, v["verkey"], freshness_seconds=10**9)


def example(name: str) -> dict:
    return json.loads((VECTORS.parent / name).read_text(encoding="utf-8"))


def test_the_tools_call_example_is_a_labour_insurance_enrolment_that_verifies():
    """`tools-call-request.json` calls the tool `tool-with-requirement.json` defines, with arguments
    that tool accepts, a digest this package computes, and a signature that verifies against the
    published test key above — so anyone can check it. The credential, its SAID and the delegated
    AID are illustrative: no key event log stands behind them, and the example does not claim one.
    """
    call = example("tools-call-request.json")
    tools = {t["name"]: t for t in example("tool-with-requirement.json")["result"]["tools"]}
    k = keys(DEFAULT)  # the examples use the provisional default namespace
    params = call["params"]
    assert call["method"] == "tools/call" and params["name"] == "enroll_employee"

    schema = tools["enroll_employee"]["inputSchema"]
    arguments = params["arguments"]
    assert set(arguments) == set(schema["required"])
    assert re.fullmatch(schema["properties"]["person_ref"]["pattern"], arguments["person_ref"])
    date.fromisoformat(arguments["start_date"])
    assert isinstance(arguments["salary_grade"], int) and arguments["salary_grade"] >= 1

    meta = params["_meta"]
    signature = meta[k.signature]
    assert signature["aid"] == meta[k.delegated_aid]
    assert signature["digest"] == digest_params(params)
    verify_request(signature, call["method"], params, vectors()["signature"]["verkey"],
                   freshness_seconds=10**9)
    # ...and only against that key: it is the published test key, not a key of the illustrative AID.
    other = Signer.from_seed(signature["aid"], bytes(range(1, 33))).verkey
    with pytest.raises(InvalidSignature):
        verify_request(signature, call["method"], params, other, freshness_seconds=10**9)

    # The tool's argument rule holds on the day the call was signed, counted as the
    # demonstration's gateway counts days (+08:00).
    rules = tools["enroll_employee"]["_meta"][k.requires]["arguments"]
    signed = datetime.fromisoformat(signature["ts"].replace("Z", "+00:00"))
    ok, reason = arguments_satisfied(
        rules, arguments, today=signed.astimezone(timezone(timedelta(hours=8))).date())
    assert ok, reason
