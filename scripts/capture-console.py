"""Screenshot the Trust Console's six scenes, for the deck.

The screenshots are taken from the running console, driven the way the recording drives it —
nothing is drawn, mocked or composed. Scene 3 is captured after a real revocation (`kli vc revoke`,
read back from the witness), and the credential is re-issued afterwards so scenes 4 and 5 have one
to present, exactly as between takes.

    python scripts/capture-console.py            # -> docs/slides/shots/scene-0.png … scene-5.png
    python scripts/capture-console.py 0 1        # only those scenes (3 revokes, then re-issues)

Needs the console on :8800 (or CONSOLE_URL) and, for scenes 4 and 5, the gateway and the
skill-generated server running — `scripts/record-check.sh` says whether they are. A scene whose
server is down is captured anyway, showing NOT RUNNING, and the script says so: a screenshot of a
refusal to pretend is still true, but it is not the one the deck wants.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "slides" / "shots"
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8800")

#: What each scene is expected to end on. Anything else is reported, not hidden.
EXPECTED = {0: "self-asserted", 1: "allowed", 2: "refused", 3: "refused", 4: "allowed", 5: "allowed"}


def post(path: str, timeout: float = 600) -> dict:
    request = urllib.request.Request(CONSOLE + path, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # Rendered at 2x: the full frame is saved at 1920x1080, and the verification column —
        # the part a slide shows at reading size — at twice that.
        page = browser.new_page(viewport={"width": 1920, "height": 1080}, device_scale_factor=2)
        page.goto(f"{CONSOLE}/?chrome=off")
        page.wait_for_selector("#checks li")

        wanted = [int(a) for a in sys.argv[1:]] or list(range(6))
        for n in wanted:
            if n == 3:
                post("/scene/3")
                post("/revoke")  # verifies the same call again once the witness has the `rev`
            else:
                post(f"/scene/{n}")
            status = EXPECTED[n]
            # The column reveals one row at a time; the banner is set when the reveal ends.
            page.wait_for_function(
                """([n, status]) =>
                     document.getElementById('scene-n').textContent === String(n)
                     && document.getElementById('outcome').className.split(' ').length > 1""",
                arg=[n, status],
                timeout=60_000,
            )
            page.wait_for_timeout(600)  # let the last row's transition settle
            shown = page.eval_on_selector("#outcome", "e => e.className.replace('outcome', '').trim()")
            if shown != status:
                problems.append(f"scene {n}: expected {status}, the console shows {shown}")
            path = OUT / f"scene-{n}.png"
            page.screenshot(path=str(path), scale="css")
            # The verification column, from its heading to just under the banner.
            clip = page.evaluate(
                """() => {
                     const pane = document.querySelectorAll('section.pane')[2].getBoundingClientRect();
                     const out = document.getElementById('outcome').getBoundingClientRect();
                     return {x: pane.x, y: pane.y, width: pane.width,
                             height: out.bottom - pane.y + 28};
                   }"""
            )
            column = OUT / f"scene-{n}-verification.png"
            page.screenshot(path=str(column), clip=clip, scale="device")
            print(f"  scene {n}: {shown:<14} -> {path.relative_to(ROOT)}, {column.name}")

            if n == 3:
                post("/reissue")  # the between-takes step; scenes 4 and 5 need a live credential

        browser.close()

    for problem in problems:
        print(f"  ! {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
