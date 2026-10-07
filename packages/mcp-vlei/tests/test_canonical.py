"""The canonical form a v0.3 signature covers: RFC 8785 over I-JSON, exactly.

A digest is only as good as the agreement on what was hashed. v0.2 wrote `1e21` where RFC 8785
writes `1e+21`, so a JavaScript client and this package computed different digests for the same
call; a repeated key or an integer beyond 2**53 let two parsers read one body two ways.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from mcp_vlei.signing import MAX_SAFE_INTEGER, canonicalize, digest_params, loads_strict

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "examples" / "jcs-number-vectors.json"


def _numbers() -> list[dict]:
    if not VECTORS.is_file():
        return []
    return json.loads(VECTORS.read_text(encoding="utf-8"))["numbers"]


@pytest.mark.skipif(not VECTORS.is_file(), reason="needs the repository's spec/")
@pytest.mark.parametrize("vector", _numbers(), ids=lambda v: v["text"])
def test_numbers_are_written_as_ecmascript_writes_them(vector):
    value = struct.unpack(">d", bytes.fromhex(vector["hex"]))[0]
    assert canonicalize(value).decode("ascii") == vector["text"]


@pytest.mark.parametrize("value, text", [
    (1e21, "1e+21"), (1e-7, "1e-7"), (1.5e-7, "1.5e-7"), (-0.0, "0"), (100.0, "100"),
    (3, "3"), (-(2**53 - 1), "-9007199254740991"),
])
def test_the_forms_v02_got_wrong(value, text):
    assert canonicalize(value) == text.encode("ascii")


def test_an_integer_beyond_ijson_is_refused_not_rounded():
    """Rounded, 2**60 and 2**60 + 1 would share one digest."""
    with pytest.raises(ValueError, match="I-JSON"):
        canonicalize(MAX_SAFE_INTEGER + 1)
    with pytest.raises(ValueError, match="I-JSON"):
        digest_params({"name": "t", "arguments": {"n": 2**60}})


def test_a_lone_surrogate_has_no_canonical_form():
    with pytest.raises(ValueError):
        digest_params({"name": "t", "arguments": {"s": "\ud800"}})


def test_a_repeated_member_name_is_refused():
    with pytest.raises(ValueError, match="duplicate member name 'salary_grade'"):
        loads_strict('{"arguments": {"salary_grade": 3, "salary_grade": 30}}')


def test_nan_and_infinity_are_not_json():
    for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
        with pytest.raises(ValueError, match="is not JSON"):
            loads_strict(text)


def test_strict_loading_reads_ordinary_json_as_json_does():
    text = '{"b": [1, 2.5, "臺"], "a": {"x": null, "y": true}}'
    assert loads_strict(text) == json.loads(text)
    assert loads_strict(text.encode("utf-8")) == json.loads(text)
