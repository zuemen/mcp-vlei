"""A signer that never holds the private key.

The agent's key lives in the KERI keystore inside the `keri-cli` container and is signed with
there, through `kli sign`. keripy's `Manager` exposes no way to export a private seed, which is
correct: a key you can copy is a key that can be taken.

This is the same arrangement Signify provides in production — the holder's device keeps the key and
returns signatures — reached through a local command instead of a KERIA agent. Swapping one for the
other changes this file and nothing else, which is the point of `mcp_vlei` taking any object with
`.aid`, `.verkey` and `.sign()`.

Note what is being signed with: the **agent's delegated AID**, not the person's. If this signer
were compromised, the delegation is revoked and the ECR holder's credential is untouched.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from mcp_vlei.signing import CommandSigner

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = os.environ.get("VLEI_COMPOSE", str(ROOT / "scripts" / "docker-compose.yml"))


def _run(args: list[str]) -> str:
    env = dict(os.environ, MSYS_NO_PATHCONV="1")  # Git Bash rewrites container paths otherwise
    result = subprocess.run(
        ["docker", "compose", "-f", COMPOSE, "exec", "-T", "keri-cli", *args],
        capture_output=True, text=True, env=env, timeout=120,
        # `kli status` prints a check mark for an anchored delegation, which the console codepage
        # on Windows cannot decode; without this the capture thread dies and the output is lost.
        encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()[-300:]}")
    return result.stdout


def keystore_signer(keystore: str, alias: str) -> CommandSigner:
    """A `CommandSigner` backed by `kli sign` in the given keystore."""
    aid = _run(["kli", "aid", "--name", keystore, "--alias", alias]).strip().splitlines()[-1]
    verkey = _verkey(keystore, alias)
    return CommandSigner(
        aid=aid,
        verkey=verkey,
        command=lambda text: _run(
            ["kli", "sign", "--name", keystore, "--alias", alias, "--text", text]
        ),
    )


def _verkey(keystore: str, alias: str) -> str:
    """The AID's current public key, which the counterparty verifies the signature against.

    Read from the live key state rather than derived from the AID: the current key is whatever the
    latest rotation made it, so deriving it would be right only until the first rotation and then
    quietly wrong.
    """
    out = _run(["kli", "status", "--name", keystore, "--alias", alias, "--verbose"])
    lines = [line.strip() for line in out.splitlines()]
    for index, line in enumerate(lines):
        if line.startswith("Public Keys"):
            for candidate in lines[index + 1 : index + 4]:
                key = candidate.split(". ")[-1].strip()
                if len(key) == 44 and key[0] in "DB":
                    return key
    raise RuntimeError(f"no current public key in key state for {alias!r}: {out[:200]}")


def agent_signer() -> CommandSigner:
    """The agent's signer: its delegated AID when one exists, the ECR holder's otherwise.

    The fallback is the documented one from `spec/SPEC.md`: `delegatedAid` is optional, and a
    deployment without it keeps every property except the second revocation switch.
    """
    env_path = ROOT / "credentials" / "env.json"
    env = json.loads(env_path.read_text()) if env_path.exists() else {}
    if env.get("agentAid"):
        return keystore_signer("agent", "agent")
    return keystore_signer("ecr", "ecr")
