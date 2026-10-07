"""VLEI_CREDENTIALS_DIR: the console must never sign with another stack's credentials against a
default (live) port.

Task 24c: `scripts/demo-parallel.sh` points a second console (its own port, :38800) at the parallel
v0.3 stack's `.v03/credentials` instead of `credentials/`. Nothing else may change by accident when
it does: this console must refuse to start unless the compose command that signs for those
credentials, and the gateway/before/witness it is for, are all given explicitly too — so a copy of
this stack can never default onto the live stack's keri-cli or ports while holding another stack's
credentials.

No containers, no network: these checks only ever reach the guard at the top of
`examples/console/app.py`, which runs before `Environment()` — before anything is read from disk
or dialled over the network.

    PYTHONPATH=packages/mcp-vlei/src python -m pytest examples/console/tests/test_parallel_credentials.py -q
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "examples" / "console"
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))

#: What demo-parallel.sh sets, besides VLEI_CREDENTIALS_DIR — kept in one place so each test only
#: has to say which one it leaves out.
OTHERS = {
    "VLEI_COMPOSE_CMD": "docker compose -p mcp-vlei-v03p -f scripts/docker-compose.yml",
    "VLEI_GATEWAY_URL": "http://localhost:33000/mcp",
    "VLEI_BEFORE_URL": "http://127.0.0.1:38090",
    "VLEI_WITNESS_URL": "http://localhost:35642",
}
#: Every variable the guard touches, cleared before each test so one test's os.environ never
#: leaks into the next — module-level code runs once per import, and each test imports afresh.
ALL_GUARDED = ("VLEI_CREDENTIALS_DIR", *OTHERS)


def _clear() -> None:
    for name in ALL_GUARDED:
        os.environ.pop(name, None)
    os.environ.pop("VLEI_CONSOLE_TARGET", None)


def _load(tmp_path: Path, *, credentials_dir: bool, missing: str | None, module_name: str):
    """Import a fresh copy of the console with the given environment, module-level code and all.

    `missing`, when given, is the one variable from OTHERS this call leaves unset; every other
    one of OTHERS is set, so a refusal can be attributed to exactly that variable and no other.
    """
    _clear()
    os.environ["VLEI_CONSOLE_MINTED"] = "1"  # never live, so Environment() dials nothing either way
    if credentials_dir:
        os.environ["VLEI_CREDENTIALS_DIR"] = str(tmp_path)
        for name, value in OTHERS.items():
            if name != missing:
                os.environ[name] = value
    sys.argv = ["console"]
    spec = importlib.util.spec_from_file_location(module_name, CONSOLE / "app.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        _clear()
    return module


@pytest.mark.parametrize("missing", sorted(OTHERS))
def test_credentials_dir_without_one_companion_var_refuses(tmp_path, missing):
    with pytest.raises(SystemExit) as excinfo:
        _load(tmp_path, credentials_dir=True, missing=missing,
              module_name=f"console_app_parallel_missing_{missing}")
    message = str(excinfo.value)
    assert missing in message
    assert "VLEI_CREDENTIALS_DIR" in message
    for name in OTHERS:
        if name != missing:
            assert name not in message, f"{name} was not the missing one but is named in: {message}"


def test_credentials_dir_with_every_companion_var_set_does_not_refuse(tmp_path):
    module = _load(tmp_path, credentials_dir=True, missing=None,
                   module_name="console_app_parallel_complete")
    assert module.CREDENTIALS == tmp_path


def test_credentials_dir_unset_is_unchanged_default():
    module = _load(Path("unused"), credentials_dir=False, missing=None,
                   module_name="console_app_parallel_unset")
    assert module.CREDENTIALS == module.ROOT / "credentials"
