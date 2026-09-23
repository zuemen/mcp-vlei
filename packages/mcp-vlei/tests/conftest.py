"""Shared fixtures.

The tests use a stub verifier rather than a live ``vlei-verifier``: what is under test here is the
package's own decision logic — which layer fires, in what order, and what the caller is told. The
live verifier is exercised end to end by ``scripts/bootstrap-credentials.sh`` checks 3-6 and by
``examples/association-server/tests/``.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_vlei import Signer  # noqa: E402
from mcp_vlei.errors import Revoked  # noqa: E402
from mcp_vlei.verifier import VerificationResult  # noqa: E402

ROOT_AID = "EHJ2kA8vQZ4Yd3mRr7TcN1sWpLxFbGuV9oKqDzXnA5eM"
HOLDER_AID = "EDq8WnPrK3xLm5ZvTcYbJi1RoUa9HgNsEf7QdMwXy2Vt"
AGENT_AID = "EFn3RtYqXmLdW5oJbP2TvNcUiSpRyEg7ZhKa4QsMxVwB"
CRED_SAID = "EBcd7TqLmN4pR2wXyZ1vHsJk8QgUeA3nCfDoI6t0PyWr"
LEI = "984500ABCDEF12345678"


@pytest.fixture
def seed() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def signer(seed: bytes) -> Signer:
    return Signer.from_seed(AGENT_AID, seed)


@pytest.fixture
def key_store(tmp_path: Path, seed: bytes) -> Path:
    (tmp_path / f"{AGENT_AID}.key").write_bytes(seed)
    return tmp_path


@pytest.fixture
def credential_file(tmp_path: Path) -> Path:
    path = tmp_path / "ecr.cesr"
    path.write_text('{"v":"ACDC10JSON","d":"' + CRED_SAID + '","a":{"LEI":"' + LEI + '"}}')
    return path


class StubVerifier:
    """Stands in for ``VleiVerifier``, with the knobs each scenario needs."""

    def __init__(
        self,
        *,
        role: str | None = "member-registration",
        scope: dict[str, Any] | None = None,
        revoked: bool = False,
        root_aid: str | None = ROOT_AID,
        accepted_roots: list[str] | None = None,
    ) -> None:
        self.role = role
        self.scope = scope or {}
        self.revoked = revoked
        self.root_aid = root_aid
        self.accepted_roots = accepted_roots or [ROOT_AID]
        self.calls: list[str] = []

    async def verify(self, cesr, *, said, aid, expected_role=None, source="presented"):
        self.calls.append(aid)
        if self.revoked:
            raise Revoked("the credential has been revoked", aid=aid, credential_said=said)
        from mcp_vlei.errors import UnknownRoot

        if self.root_aid and self.root_aid not in self.accepted_roots:
            raise UnknownRoot(
                f"chain terminates at {self.root_aid}, which is not an accepted root",
                aid=aid,
                credential_said=said,
            )
        return VerificationResult(
            aid=aid,
            lei=LEI,
            role=self.role,
            credential_said=said or CRED_SAID,
            holder_aid=HOLDER_AID,
            scope=self.scope,
            root_aid=self.root_aid,
            source=source,
        )

    def invalidate(self, aid: str) -> None:
        self.calls.append(f"invalidate:{aid}")


class Ctx:
    """Minimal stand-in for the SDK's tool-call context."""

    def __init__(self, tool_name: str, arguments: dict[str, Any], meta: dict[str, Any], *, requires=None, verkey=None):
        self.tool_name = tool_name
        self.tool = {"name": tool_name, "_meta": {"org.gleif.vlei/requires": requires} if requires else {}}
        self.method = "tools/call"
        self.params = {"name": tool_name, "arguments": arguments}
        self.meta = meta
        self.caller_verkey = verkey
        self.vlei = None


@pytest.fixture
def stub_verifier() -> StubVerifier:
    return StubVerifier()


@pytest.fixture
def le_credential(tmp_path: Path) -> Path:
    path = tmp_path / "le.cesr"
    path.write_text('{"v":"ACDC10JSON","d":"' + CRED_SAID + '","a":{"LEI":"' + LEI + '"}}')
    return path
