"""Rehearse the recording, unattended, and say whether every scene ends where the script says.

Drives the console the way the presenter does — keys 0-5, the REVOKE button, `I` to re-issue —
in a real browser at 1920x1080, and checks each scene against the recording script in
`docs/DEMO.md`: the outcome, the failure layer, that the evidence line says issued credentials,
keystore signing and a witness, and that no readiness warning is on screen when a scene should
allow. Run it after `scripts/reset-demo.sh`; it leaves the environment as it found it (scene 3's
revocation is followed by a re-issue, exactly as between takes).

    python scripts/rehearse.py            # exits 0 only if every scene is right
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8800")

#: (step, key or action, expected status, expected layer)
SCRIPT = [
    ("scene 0", "0", "self-asserted", None),
    ("scene 1", "1", "allowed", None),
    ("scene 2", "2", "refused", "missing_credential"),
    ("scene 3", "3", "allowed", None),
    ("scene 3 · REVOKE", "revoke", "refused", "revoked"),
    ("re-issue (I)", "i", None, None),
    ("scene 4", "4", "allowed", None),
    ("scene 5", "5", "allowed", None),
]


def state() -> dict:
    with urllib.request.urlopen(f"{CONSOLE}/state", timeout=30) as response:
        return json.load(response)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the Windows console is cp950
    rows: list[tuple[str, str, str, float]] = []
    failures = 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(f"{CONSOLE}/?chrome=off")
        page.wait_for_selector("#checks li")

        for step, action, status, layer in SCRIPT:
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
