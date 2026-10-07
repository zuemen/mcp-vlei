"""Record a draft of the demo video from the running console — unattended, frame-exact.

A draft, not the take: it drives the console the way the presenter does (keys, the REVOKE button),
so the checks, the revocation and the gateway call on screen are all real, but it cannot pace itself
to a live narration the way a person does. It exists so the deck can be rehearsed against a real
recording, and so the timing of each scene can be judged before anyone records.

Frames come from Chrome's screencast (full-resolution JPEG at quality 100, with timestamps), not from Playwright's
built-in recorder, whose 1 Mbit/s VP8 blurs text at 1080p. Each scene is its own segment; scene 4
revokes the ECR for real, and it is re-issued once the recording ends, off camera, exactly as
between takes. Segments are encoded to H.264 and joined.

    python scripts/record-demo.py                                   # the talk's four scenes, 2:05
    python scripts/record-demo.py --scenes 0:45,1:30,2:25,3:25,4:45  # scene 0 as well
    python scripts/record-demo.py --lang en                         # no Chinese on screen

The page is English but for the employer's 統一編號; --lang en names it in English as well.

Needs everything `scripts/reset-demo.sh` starts, and ffmpeg (on PATH, or imageio-ffmpeg).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8800")
#: The recording script of the talk: scene -> seconds. Scenes 1-4, the labour-insurance filing;
#: the impersonation (scene 0) is shown in the talk as the observatory's records instead.
SCRIPT = "1:30,2:25,3:25,4:45"
#: The scene in which the presenter clicks REVOKE, and when — after narrating the valid call.
REVOCATION_SCENE = 4
REVOKE_AT = 15.0


def ffmpeg() -> str:
    found = shutil.which("ffmpeg")
    if found:
        return found
    import imageio_ffmpeg

    return imageio_ffmpeg.get_ffmpeg_exe()


def post(path: str, timeout: float = 600) -> dict:
    request = urllib.request.Request(CONSOLE + path, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def record_scene(page, cdp, scene: int, seconds: float, workdir: Path) -> list[tuple[Path, float]]:
    """Frames of one scene, as (file, timestamp)."""
    frames: list[tuple[Path, float]] = []

    def on_frame(event):
        index = len(frames)
        path = workdir / f"s{scene}-{index:05d}.jpg"
        path.write_bytes(base64.b64decode(event["data"]))
        frames.append((path, event["metadata"]["timestamp"]))
        cdp.send("Page.screencastFrameAck", {"sessionId": event["sessionId"]})

    cdp.on("Page.screencastFrame", on_frame)
    # JPEG at quality 100: at 92 a lossy frame, encoded again as 4:2:0 video, blurred small coloured
    # text twice; PNG is lossless but Chrome sends it too slowly to catch the checks lighting up.
    cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 100,
                                      "maxWidth": 1920, "maxHeight": 1080})
    # The scene starts when its own call is on screen. Until the backend has made it, the page still
    # shows the scene before — on a freshly opened page, the one the console was last on, replaying —
    # and a clip that starts at the key press opens on the wrong scene's result.
    before = page.inner_text("#req-json")
    page.keyboard.press(str(scene))
    page.wait_for_function("(before) => document.querySelector('#req-json').textContent !== before",
                           arg=before, timeout=120_000)
    started = time.time()
    revoked = False
    while time.time() - started < seconds:
        if scene == REVOCATION_SCENE and not revoked and time.time() - started >= REVOKE_AT:
            page.click("#revoke")
            page.mouse.move(960, 1070)  # off the button, or it stays in its hover colour
            revoked = True
        page.wait_for_timeout(100)  # keeps the event loop turning so frames arrive
    end = time.time()
    cdp.send("Page.stopScreencast")
    cdp.remove_listener("Page.screencastFrame", on_frame)
    # The scene's own window. Chrome sends a frame only when the page changes, so the first frame
    # after the key press can arrive a second later (scenes 1-4 wait for the gateway); show it from the
    # key press, and hold the last frame to the end.
    during = [f for f in frames if f[1] >= started]
    frames = [(during[0][0] if during else frames[-1][0], started)] + during[1:]
    frames.append((frames[-1][0], end))
    return frames


def encode(frames: list[tuple[Path, float]], out: Path, fps: int = 30) -> None:
    """A constant-rate H.264 segment: at each tick, the newest frame Chrome had sent by then.

    Written to ffmpeg frame by frame rather than as a concat list with durations: the concat
    demuxer stretched image durations here (a 4-second scene came out at 7.7 seconds)."""
    start, end = frames[0][1], frames[-1][1]
    command = [ffmpeg(), "-loglevel", "error", "-y", "-f", "image2pipe", "-framerate", str(fps),
               "-c:v", "mjpeg", "-i", "-",
               # Screen frames are full-range; players, PowerPoint among them, expect TV range.
               "-vf", "scale=out_range=tv,format=yuv420p", "-color_range", "tv",
               "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-movflags", "+faststart",
               str(out)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    index, current, data = 0, None, b""
    for tick in range(max(1, round((end - start) * fps))):
        at = start + tick / fps
        while index + 1 < len(frames) and frames[index + 1][1] <= at:
            index += 1
        if frames[index][0] != current:
            current = frames[index][0]
            data = current.read_bytes()
        process.stdin.write(data)
    process.stdin.close()
    if process.wait() != 0:
        raise RuntimeError(f"ffmpeg failed encoding {out.name}")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the Windows console is cp950
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenes", default=SCRIPT, help="scene:seconds,… (default: the script)")
    parser.add_argument("--out", type=Path, default=ROOT / "recordings" / "demo-draft.mp4")
    parser.add_argument("--lang", choices=["zh", "en"], default="zh",
                        help="en: the employer's 統一編號 named in English too (the rest is English)")
    args = parser.parse_args()
    plan = [(int(n), float(s)) for n, s in (item.split(":") for item in args.scenes.split(","))]

    workdir = Path(tempfile.mkdtemp(prefix="demo-"))
    segments: list[Path] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        cdp = page.context.new_cdp_session(page)
        page.goto(f"{CONSOLE}/?chrome=off" + ("&lang=en" if args.lang == "en" else ""))
        page.wait_for_selector("#checks li")
        for scene, seconds in plan:
            frames = record_scene(page, cdp, scene, seconds, workdir)
            segment = workdir / f"scene-{scene}.mp4"
            encode(frames, segment)
            segments.append(segment)
            print(f"  scene {scene}: {seconds:.0f}s, {len(frames)} frames")
        browser.close()
    if any(n == REVOCATION_SCENE for n, _ in plan):
        # As between takes: the revocation scene revoked the ECR for real. A failed re-issue must
        # not cost the recording, and must not go unnoticed: the next take would show `revoked`.
        try:
            reissued = post("/reissue").get("ok")
        except OSError:  # urllib's HTTPError and URLError
            reissued = False
        print("  ECR re-issued" if reissued else
              "  the ECR was NOT re-issued: run bash scripts/bootstrap-credentials.sh --reissue")

    listing = workdir / "segments.txt"
    listing.write_text("".join(f"file '{s.as_posix()}'\n" for s in segments), encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([ffmpeg(), "-loglevel", "error", "-y", "-f", "concat", "-safe", "0",
                    "-i", str(listing), "-c", "copy", "-movflags", "+faststart", str(args.out)],
                   check=True)
    total = sum(s for _, s in plan)
    print(f"  -> {args.out} ({int(total // 60)}:{int(total % 60):02d}, "
          f"{args.out.stat().st_size / 1e6:.1f} MB)")
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
