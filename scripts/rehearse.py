"""Rehearse the recording, unattended, and say whether every scene ends where the script says.

Drives the console the way the presenter does — keys 0-4, the REVOKE button, `I` to re-issue —
in a real browser at 1920x1080, and checks each scene against what it should end on: the
outcome, the failure layer, that the evidence line says issued credentials,
keystore signing and a witness, and that no readiness warning is on screen when a scene should
allow. Run it after `scripts/reset-demo.sh`; it leaves the environment as it found it (scene 4's
revocation is followed by a re-issue, exactly as between takes).

    python scripts/rehearse.py                  # scenes 1-4, the recording; exits 0 only if right
    python scripts/rehearse.py --scenes 0-4     # the console's every scene, the impersonation too
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8800")

#: What the talk records: the labour-insurance scenes. Scene 0 is still in the console.
RECORDED = "1-4"

#: (step, key or action, expected status, expected layer)
SCRIPT = [
    ("scene 0", "0", "self-asserted", None),
    ("scene 1", "1", "allowed", None),
    ("scene 2", "2", "refused", "role_mismatch"),
    ("scene 3", "3", "refused", "scope_exceeded"),
    ("scene 4", "4", "allowed", None),
    ("scene 4 · REVOKE", "revoke", "refused", "revoked"),
    ("re-issue (I)", "i", None, None),
]


def state() -> dict:
    with urllib.request.urlopen(f"{CONSOLE}/state", timeout=30) as response:
        return json.load(response)


def scenes_in(text: str) -> set[int]:
    """`1-4` or `0,2,4` -> the scene numbers."""
    wanted: set[int] = set()
    for part in text.split(","):
        low, _, high = part.strip().partition("-")
        wanted.update(range(int(low), int(high or low) + 1))
    return wanted


def _scene_of(step: str) -> int:
    """`scene 4 · REVOKE` -> 4. The re-issue belongs to scene 4, whose revocation it undoes."""
    return int(step.split()[1]) if step.startswith("scene ") else 4


def steps_for(wanted: set[int]) -> list[tuple]:
    """The script's steps for those scenes, in order."""
    return [step for step in SCRIPT if _scene_of(step[0]) in wanted]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the Windows console is cp950
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenes", default=RECORDED,
                        help=f"which scenes, e.g. 1-4 or 0-4 (default {RECORDED}, the recording)")
    wanted = scenes_in(parser.parse_args().scenes)
    rows: list[tuple[str, str, str, float]] = []
    failures = 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(f"{CONSOLE}/?chrome=off")
        page.wait_for_selector("#checks li")

        for step, action, status, layer in steps_for(wanted):
            started = time.monotonic()
            if action == "revoke":
                page.click("#revoke")
                page.wait_for_function(
                    "document.getElementById('outcome').className.includes('refused')",
                    timeout=120_000,
                )
            elif action == "i":
                before = state()["verification"]["outcome"]
                page.keyboard.press("i")
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline and state().get("readiness") is None and \
                        state()["verification"]["outcome"] == before:
                    time.sleep(1)
                # The re-issue ends by reloading the current scene; wait until it has.
                while time.monotonic() < deadline and state()["identities"]["agent"]["status"] != "valid":
                    time.sleep(1)
            else:
                page.keyboard.press(action)
                page.wait_for_function(
                    """n => document.getElementById('scene-n').textContent === n
                           && document.getElementById('outcome').className.split(' ').length > 1""",
                    arg=action,
                    timeout=120_000,
                )
            elapsed = time.monotonic() - started
            now = state()
            outcome = now["verification"]["outcome"]
            evidence = now.get("evidence", {})
            problems = []
            if status is not None and outcome["status"] != status:
                problems.append(f"expected {status}, got {outcome['status']}")
            if layer is not None and outcome.get("layer") != layer:
                problems.append(f"expected layer {layer}, got {outcome.get('layer')}")
            if status == "allowed" and now.get("readiness"):
                problems.append(f"readiness warning on screen: {now['readiness']}")
            if evidence.get("credentials") != "issued" or "kli" not in evidence.get("signing", ""):
                problems.append(f"not the issued environment: {evidence}")
            shown = outcome["status"] + (f" · {outcome['layer']}" if outcome.get("layer") else "")
            rows.append((step, shown, "; ".join(problems) or "ok", elapsed))
            failures += bool(problems)

        browser.close()

    print(f"\n  {'step':<18} {'on screen':<30} {'seconds':>8}  result")
    for step, shown, verdict, elapsed in rows:
        print(f"  {step:<18} {shown:<30} {elapsed:8.1f}  {verdict}")
    print(f"\n  {'READY TO RECORD' if not failures else f'{failures} STEP(S) WRONG'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
