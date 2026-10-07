"""The two failure layers v0.3 adds. Named exactly, because the skill keys its recovery off them."""

from __future__ import annotations

import mcp_vlei
from mcp_vlei.errors import AudienceMismatch, FailureLayer, UnsupportedVersion


def test_the_new_layers_are_named_on_the_wire():
    assert FailureLayer.AUDIENCE_MISMATCH.value == "audience_mismatch"
    assert FailureLayer.UNSUPPORTED_VERSION.value == "unsupported_version"


def test_neither_is_worth_retrying():
    """A call for another recipient stays for another recipient; an old client stays old."""
    assert not FailureLayer.AUDIENCE_MISMATCH.retryable
    assert not FailureLayer.UNSUPPORTED_VERSION.retryable


def test_each_raises_with_its_layer_first_in_the_text():
    exc = AudienceMismatch("signed for http://elsewhere/mcp", aid="E" + "A" * 43)
    assert exc.to_text() == "audience_mismatch: signed for http://elsewhere/mcp"
    assert exc.to_detail() == {"layer": "audience_mismatch", "message": "signed for http://elsewhere/mcp",
                               "aid": "E" + "A" * 43}
    assert UnsupportedVersion("v0.2").layer is FailureLayer.UNSUPPORTED_VERSION


def test_the_package_exports_them():
    assert mcp_vlei.AudienceMismatch is AudienceMismatch
    assert mcp_vlei.UnsupportedVersion is UnsupportedVersion
