"""Who a v0.3 call is for, and how a verifier tells it was not for them."""

from __future__ import annotations

import pytest

from mcp_vlei.audience import Audience, Recipient, normalise_endpoint
from mcp_vlei.errors import AudienceMismatch

AID = "E" + "R" * 43
OTHER = "E" + "X" * 43


@pytest.mark.parametrize("given, normal", [
    ("http://localhost:3000/mcp", "http://localhost:3000/mcp"),
    ("HTTP://LocalHost:3000/mcp", "http://localhost:3000/mcp"),
    ("https://gw.example:443/mcp", "https://gw.example/mcp"),
    ("http://gw.example:80/mcp", "http://gw.example/mcp"),
    ("http://gw.example", "http://gw.example/"),
    ("  http://gw.example/mcp  ", "http://gw.example/mcp"),
    ("http://[::1]:3000/mcp", "http://[::1]:3000/mcp"),
    ("https://bücher.example/mcp", "https://xn--bcher-kva.example/mcp"),
    ("http://gw.example/a%20b", "http://gw.example/a%20b"),
    ("http://gw.example/a%2fb", "http://gw.example/a%2Fb"),
    ("http://gw.example/%e4%b8%ad/mcp", "http://gw.example/%E4%B8%AD/mcp"),
])
def test_one_spelling_per_endpoint(given, normal):
    assert normalise_endpoint(given) == normal


@pytest.mark.parametrize("bad", [
    "", "gw.example/mcp", "ftp://gw.example/mcp", "http://user:pw@gw.example/mcp",
    "http://gw.example/mcp?x=1", "http://gw.example/mcp?", "http://gw.example/mcp#top",
    "http:///mcp", "http://gw.example:99999/mcp", "http://gw.example/臺",
])
def test_anything_more_than_a_place_is_refused(bad):
    with pytest.raises(ValueError):
        normalise_endpoint(bad)


def test_an_audience_is_normalised_and_checked():
    assert Audience(AID, "HTTP://LOCALHOST:3000/mcp").to_wire() == {
        "aid": AID, "url": "http://localhost:3000/mcp"}
    with pytest.raises(ValueError, match="CESR"):
        Audience("not-an-aid", "http://localhost:3000/mcp")


def test_a_recipient_needs_an_endpoint():
    with pytest.raises(ValueError, match="at least one endpoint"):
        Recipient(AID, ())


def test_a_recipient_accepts_its_own_name_at_any_of_its_urls():
    me = Recipient(AID, ("http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp"))
    assert me.check({"aid": AID, "url": "http://127.0.0.1:3000/mcp"}) == "http://127.0.0.1:3000/mcp"
    assert me.check({"aid": AID, "url": "HTTP://localhost:3000/mcp"}) == "http://localhost:3000/mcp"


def test_percent_encodings_that_differ_only_in_case_are_one_endpoint():
    """RFC 3986 §6.2.2.1: ``%2f`` and ``%2F`` are the same octet. A client that spelled it one
    way and a verifier configured the other must not refuse each other as audience_mismatch."""
    me = Recipient(AID, ("http://gw.example/a%2Fb/mcp",))
    assert me.check({"aid": AID, "url": "http://gw.example/a%2fb/mcp"}) == "http://gw.example/a%2Fb/mcp"
    assert Audience(AID, "http://gw.example/a%2fb/mcp").url == "http://gw.example/a%2Fb/mcp"


def test_a_wrong_url_is_named_without_listing_this_servers_urls():
    """The caller is not verified yet: telling it every URL this server is reached at (loopback,
    tunnel and internal addresses among them) would map the deployment for anyone who asks."""
    me = Recipient(AID, ("http://localhost:3000/mcp", "https://tunnel.example/mcp"))
    with pytest.raises(AudienceMismatch) as exc:
        me.check({"aid": AID, "url": "http://localhost:3001/mcp"}, signer=OTHER)
    assert "http://localhost:3001/mcp" in exc.value.message
    assert "localhost:3000" not in exc.value.message and "tunnel.example" not in exc.value.message


@pytest.mark.parametrize("aud, says", [
    ({"aid": OTHER, "url": "http://localhost:3000/mcp"}, "not for this server"),
    ({"aid": AID, "url": "http://localhost:3001/mcp"},
     "signed for http://localhost:3001/mcp, which is not this server's endpoint"),
    ({"aid": AID, "url": "http://localhost:3000/other"}, "which is not this server's endpoint"),
    ({"aid": AID, "url": "not a url"}, "unusable URL"),
    ({"aid": AID}, "not {aid, url}"),
    ({"aid": AID, "url": "http://localhost:3000/mcp", "extra": "x"}, "not {aid, url}"),
    ("http://localhost:3000/mcp", "not {aid, url}"),
])
def test_a_call_for_anyone_else_is_audience_mismatch(aud, says):
    me = Recipient(AID, ("http://localhost:3000/mcp",))
    with pytest.raises(AudienceMismatch, match=says) as exc:
        me.check(aud, signer=OTHER)
    assert exc.value.layer.value == "audience_mismatch"
