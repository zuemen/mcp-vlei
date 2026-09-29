"""`VleiVerifier`: an adapter over a running vlei-verifier, used for revocation.

Its question is "what did the holder of this AID present?". The answer is about *a* credential; it
has to be the one being presented, and a cached answer about one must not stand in for another.
"""

from __future__ import annotations

import httpx
import pytest

from mcp_vlei import VleiVerifier
from mcp_vlei.errors import ChainInvalid

AID = "E" + "h" * 43
ROOT = "E" + "r" * 43
ONE, OTHER = "E" + "1" * 43, "E" + "2" * 43


def verifier_answering_about(said: str) -> tuple[VleiVerifier, list[str]]:
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return httpx.Response(200, json={
            "aid": AID, "said": said, "lei": "984500ABCDEF12345678", "role": "r",
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return VleiVerifier("http://verifier", accepted_roots=[ROOT], client=client), asked


async def test_an_answer_about_another_credential_is_not_an_answer():
    verifier, _ = verifier_answering_about(ONE)
    with pytest.raises(ChainInvalid, match="not the presented"):
        await verifier.verify("cesr", said=OTHER, aid=AID)


async def test_a_cached_answer_is_only_about_the_credential_it_was_about():
    verifier, asked = verifier_answering_about(ONE)
    assert (await verifier.verify("cesr", said=ONE, aid=AID)).lei
    with pytest.raises(ChainInvalid):
        await verifier.verify("cesr", said=OTHER, aid=AID)
    assert len(asked) == 2
