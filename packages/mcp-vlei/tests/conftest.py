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

ROOT_AID = "EM-uSa3-ZH6ynbMtqUE0aOce0memXiuXHDOVNQia8x6n"
QVI_AID = "EDFRI3MOLPx4mOQNKlHOS1O_JLWMGRFiaiwO1FSxheW0"
LE_AID = "EKPdng_ffec4VInvOsswAeIoe0C0LtDDBbk-5YbDHDMe"
QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
ECR_SCHEMA = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"
REGISTRY = "EHsH7DfMGlfOsAVjTw1EZMhbHQJovsqmBYXHFYDgiz2K"
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


def mint(schema: str, issuer: str, issuee: str, attributes: dict, edge=None) -> str:
    """Serialize a credential and fill in the SAID its contents imply.

    Real chains, not placeholder JSON: the extension now walks and re-hashes what it is given, so a
    fixture that was not a valid chain would only prove the checks were skipped.
    """
    import base64
    import json

    import blake3

    body: dict = {
        "v": "ACDC10JSON000000_",
        "d": "#" * 44,
        "i": issuer,
        "ri": REGISTRY,
        "s": schema,
        "a": {"i": issuee, "dt": "2026-09-23T00:00:00.000000+00:00", **attributes},
    }
    if edge:
        label, target = edge
        body["e"] = {"d": "E" + "A" * 43, label: {"n": target, "s": schema}}

    text = json.dumps(body, separators=(",", ":"))
    digest = blake3.blake3(text.encode("utf-8")).digest(length=32)
    said = "E" + base64.urlsafe_b64encode(b"\x00" + digest).decode("ascii")[1:]
    return text.replace('"d":"' + "#" * 44 + '"', f'"d":"{said}"', 1)


def build_chain(role: str = "member-registration", root: str = ROOT_AID) -> tuple[str, str]:
    """A full root -> QVI -> LE -> ECR chain, and the ECR's SAID."""
    import json

    qvi = mint(QVI_SCHEMA, root, QVI_AID, {"LEI": LEI})
    le = mint(LE_SCHEMA, QVI_AID, LE_AID, {"LEI": LEI}, edge=("qvi", json.loads(qvi)["d"]))
    ecr = mint(
        ECR_SCHEMA, LE_AID, HOLDER_AID,
        {"LEI": LEI, "personLegalName": "Chen Wei-Ting", "engagementContextRole": role},
        edge=("le", json.loads(le)["d"]),
    )
    return qvi + le + ecr, json.loads(ecr)["d"]


@pytest.fixture
def credential_file(tmp_path: Path) -> Path:
    stream, said = build_chain()
    path = tmp_path / "ecr.cesr"
    path.write_text(stream, encoding="utf-8")
    return path


@pytest.fixture
def credential_said() -> str:
    """The ECR's SAID. `build_chain` is deterministic, so this matches `credential_file`."""
    return build_chain()[1]


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
        ttl_ms: int = 30_000,
    ) -> None:
        # Part of the verifier contract the extension relies on: it advertises the TTL so a
        # counterparty knows how long a verification result may be cached.
        self.ttl_ms = ttl_ms
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


def make_params(tool: str, arguments: dict[str, Any], meta: dict[str, Any] | None = None):
    """A real ``CallToolRequestParams``, so the tests exercise the SDK's own validation."""
    from mcp.types import CallToolRequestParams

    payload: dict[str, Any] = {"name": tool, "arguments": arguments}
    if meta:
        payload["_meta"] = meta
    return CallToolRequestParams.model_validate(payload)


class Ctx:
    """Stand-in for ``ServerRequestContext``.

    The extension only reads ``params`` and passes ``ctx`` to ``call_next``, so a placeholder is
    enough here; the SDK's own context is exercised by the end-to-end tests in ``examples/``.
    """

    def __init__(self) -> None:
        self.method = "tools/call"


@pytest.fixture
def stub_verifier() -> StubVerifier:
    return StubVerifier()


@pytest.fixture
def le_credential(tmp_path: Path) -> Path:
    stream, _ = build_chain()
    path = tmp_path / "le.cesr"
    path.write_text(stream, encoding="utf-8")
    return path
