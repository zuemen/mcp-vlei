"""The published test vectors in spec/examples/digest-vectors.json, held against this package.

A second implementer needs to know exactly which bytes the digest and the signature cover — the
skill-generated server had to guess (examples/skill-server/REPORT.md, gap 11). The vectors settle
it, and this test keeps the package and the vectors from drifting apart.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_vlei import Signer
from mcp_vlei.audience import Recipient
from mcp_vlei.errors import InvalidSignature
from mcp_vlei.namespace import DEFAULT, keys
from mcp_vlei.signing import (
    arguments_satisfied,
    canonicalize,
    digest_params,
    statement,
    verify_request,
)

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "examples" / "digest-vectors.json"
pytestmark = pytest.mark.skipif(not VECTORS.is_file(), reason="needs the repository's spec/")


def vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _at(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@pytest.mark.parametrize("vector", vectors()["digests"] if VECTORS.is_file() else [],
                         ids=lambda v: v["note"][:40])
def test_digest_vectors(vector):
    params = vector["params"]
    without_meta = {k: v for k, v in params.items() if k != "_meta"}
    assert canonicalize(without_meta).decode("utf-8") == vector["canonical"]
    assert digest_params(params) == vector["digest"]


def test_signature_vector():
    v = vectors()["signature"]
    st = v["statement"]
    signer = Signer.from_seed(st["aid"], bytes.fromhex(v["seedHex"]))

    assert signer.verkey == v["verkey"]
    rebuilt = statement(aid=st["aid"], aud=st["aud"], cred=st["cred"], digest=st["digest"],
                        ts=st["ts"], exp=st["exp"], nonce=st["nonce"], method=st["method"])
    assert rebuilt == st
    assert canonicalize(st).decode("ascii") == v["canonical"]
    assert signer.sign(v["canonical"].encode("ascii")) == v["sig"]  # Ed25519 is deterministic

    params = vectors()["digests"][0]["params"]
    assert digest_params(params) == st["digest"]
    signature = {"v": st["v"], "aid": st["aid"], "aud": st["aud"], "ts": st["ts"],
                 "exp": st["exp"], "nonce": st["nonce"], "digest": st["digest"], "sig": v["sig"]}
    verify_request(signature, st["method"], params, v["verkey"],
                   recipient=Recipient(st["aud"]["aid"], (st["aud"]["url"],)),
                   credential_said=st["cred"], now=_at(st["ts"]))


def example(name: str) -> dict:
    return json.loads((VECTORS.parent / name).read_text(encoding="utf-8"))


def test_the_tools_call_example_is_a_labour_insurance_enrolment_that_verifies():
    """`tools-call-request.json` calls the tool `tool-with-requirement.json` defines, with arguments
    that tool accepts, a digest this package computes, and a v0.3 signature that verifies against
    the published test key above — so anyone can check it. The credential, its SAID, the delegated
    AID and the recipient AID are illustrative: no key event log stands behind them.
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
    assert signature["v"] == "vlei-sig/0.3"
    assert signature["aid"] == meta[k.delegated_aid]
    assert signature["digest"] == digest_params(params)
    recipient = Recipient(signature["aud"]["aid"], (signature["aud"]["url"],))
    verify_request(signature, call["method"], params, vectors()["signature"]["verkey"],
                   recipient=recipient, credential_said=meta[k.credential_said],
                   now=_at(signature["ts"]))
    # ...and only against that key: it is the published test key, not a key of the illustrative AID.
    other = Signer.from_seed(signature["aid"], bytes(range(1, 33))).verkey
    with pytest.raises(InvalidSignature):
        verify_request(signature, call["method"], params, other, recipient=recipient,
                       credential_said=meta[k.credential_said], now=_at(signature["ts"]))

    # The tool's argument rule holds on the day the call was signed, counted as the
    # demonstration's gateway counts days (+08:00).
    rules = tools["enroll_employee"]["_meta"][k.requires]["arguments"]
    signed = _at(signature["ts"])
    ok, reason = arguments_satisfied(
        rules, arguments, today=signed.astimezone(timezone(timedelta(hours=8))).date())
    assert ok, reason


def test_the_pop_example_verifies_under_the_published_test_key():
    """`pop-exchange.json`: the answer is signed over the JCS statement, under the test key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from mcp_vlei.pop import pop_statement
    from mcp_vlei.signing import cesr_decode_signature, cesr_decode_verkey

    exchange = example("pop-exchange.json")
    sent, answer = exchange["request"]["body"], exchange["response"]["body"]
    assert (answer["nonce"], answer["url"], answer["v"]) == (sent["nonce"], sent["url"], "vlei-pop/0.3")
    statement = pop_statement(aid=answer["aid"], nonce=answer["nonce"], url=answer["url"],
                              ts=answer["ts"], exp=answer["exp"])
    key = Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(vectors()["signature"]["verkey"]))
    key.verify(cesr_decode_signature(answer["sig"]), canonicalize(statement))  # raises if not
    assert exchange["refusedForAnotherUrl"]["body"]["layer"] == "audience_mismatch"


def test_the_error_examples_name_every_layer_in_check_order():
    from mcp_vlei.errors import FailureLayer

    layers = [entry["layer"] for entry in example("error-responses.json")["layers"]]
    assert sorted(layers) == sorted(layer.value for layer in FailureLayer)
    assert layers.index("unsupported_version") < layers.index("stale_signature")         < layers.index("audience_mismatch") < layers.index("digest_mismatch")


def test_the_discover_example_declares_the_format_and_the_proof():
    capability = example("discover-response.json")["result"]["capabilities"]["extensions"][
        "org.gleif.vlei/identity"]
    assert capability["signatureFormats"] == ["vlei-sig/0.3"]
    assert capability["pop"] == "/.well-known/vlei/pop"
