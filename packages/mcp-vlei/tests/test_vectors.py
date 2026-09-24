"""The published test vectors in spec/examples/digest-vectors.json, held against this package.

A second implementer needs to know exactly which bytes the digest covers — the skill-generated
server had to guess (examples/skill-server/REPORT.md, gap 11). The vectors settle it, and this test
keeps the package and the vectors from drifting apart.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_vlei import Signer
from mcp_vlei.signing import canonicalize, digest_params, signed_payload, verify_request

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
