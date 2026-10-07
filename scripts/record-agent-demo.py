"""Record the story page while a real Claude agent files, before and after — no hands needed.

    python scripts/record-agent-demo.py --out agent-demo.mp4 [--lang zh|en] [--headed] [--stills DIR]
                                        [--brisk] [--max-seconds 100]

Needs the stack from reset-demo.sh, the console on :8800, and the claude CLI (examples/console/
agent.py starts it). The page's own buttons do the work: each starts Claude Code with one MCP
connection — labor-today, then labor-vlei — and Claude decides what to call. The fifth step presses
the replay button: the console signs one call as Bob's agent and sends the same bytes twice. The
captions are laid over the page for the recording only, with a line under them that stays the whole
way (fictional identities, a simulated system, a self-hosted trust root); each scene holds with its
key rows scrolled clear of them, and the video starts on the opening caption, the page already in
the take's language. Every wait for Claude and for the replay is timed; if the take runs over
--max-seconds, only those waits are sped up — one factor for all of them, each sped-up stretch
labelled on screen — and captions and results keep their real speed. Restart the two simulators
first for a clean take:

    docker restart mcp-vlei-regulator-labor-insurance-sim-1 mcp-vlei-regulator-labor-insurance-before-1
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeout

#: VLEI_CONSOLE_URL: a second console recorded on its own port (e.g. scripts/demo-parallel.sh's
#: :38800), so a parallel take can never overwrite a recording made against the live one.
CONSOLE = os.environ.get("VLEI_CONSOLE_URL", "http://localhost:8800")
SIZE = {"width": 1920, "height": 1080}
CLAUDE_WAIT_MS = 240_000
REPLAY_WAIT_MS = 60_000
#: How long each moment is held, in ms. --brisk is for a short talk: the same steps, shorter pauses.
HOLDS = {"intro": 3500, "caption": 2600, "after": 5000, "settle": 2500, "impostor": 6000, "replay": 6000,
         "final": 6000}
BRISK = {"intro": 2000, "caption": 2000, "after": 3200, "settle": 2000, "impostor": 4000, "replay": 4000,
         "final": 4000}

CAPTIONS = {
    "zh": [
        "同一個真的 Claude 代理、同一句話，走兩種 MCP",
        "① 改善前：Claude 透過今天的 MCP 加保——系統只知道它自稱的名字",
        "② 改善後：同一句話走 MCP × vLEI——系統知道是哪個法人、什麼角色，而且驗證過",
        "③ 冒名者：一支腳本冒用同一個名字。改善前照收；改善後在閘道擋下",
        "④ 權限不符：調薪需要 payroll 角色，閘道拒絕，Claude 自己說明原因",
        "⑤ 重送：Bob 的代理簽好的呼叫被原封不動再送一次——原始呼叫受理，副本在閘道被拒絕",
        "MCP 只認得自稱的名字；MCP × vLEI 認得法人、角色與授權",
    ],
    "en": [
        "One real Claude agent, one sentence, two kinds of MCP",
        "① Before: Claude files through MCP as it is today — the system knows only a self-given name",
        "② After: the same sentence through MCP × vLEI — the legal entity and role, verified",
        "③ An impostor script gives the same name. Before: accepted. After: refused at the gateway",
        "④ Wrong role: a salary change needs the payroll role; refused, and Claude says why",
        "⑤ A replay: a copy of Bob's agent's signed call, sent again unchanged — the original accepted, the copy refused",
        "MCP knows a self-given name; MCP × vLEI knows the entity, the role and the authority",
    ],
}

#: Under every caption, on every frame: what in the demo is real and what is not.
HONESTY = {
    "zh": "身分皆為虛構・勞保系統為模擬・信任根自建",
    "en": "Fictional identities · simulated labour-insurance system · self-hosted trust root",
}
#: The label on a sped-up wait, by what is being waited for ("▶▶" is drawn before it).
BADGE = {
    "zh": {"claude": "×{n} — 等待 Claude", "replay": "×{n} — 等待閘道"},
    "en": {"claude": "×{n} — waiting for Claude", "replay": "×{n} — waiting for the gateway"},
}
#: A wait is sped up only from EDGE s after it starts to EDGE s before it ends (the click and the
#: result stay at real speed), and only if what is left is at least SHORTEST s long — a blink of
#: fast-forward with a badge reads as a glitch. One factor for every wait, at most MOST.
EDGE, SHORTEST, MOST = 0.4, 3.0, 12
#: Aim this many seconds under --max-seconds: the video's clock and the script's differ slightly.
SLACK = 2.0
FPS = 25

#: The caption bar: ``text`` fades in; the honesty line under it is set at once and never fades.
#: ``text`` null sets up the bar (and the honesty line) only.
OVERLAY = """
([text, honesty]) => {
  let bar = document.getElementById('rec-caption');
  if (!bar) {
    const font = '"Noto Sans TC","Microsoft JhengHei",sans-serif';
    bar = document.createElement('div');
    bar.id = 'rec-caption';
    bar.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:9999;padding:14px 40px 12px;' +
      'background:rgba(16,32,58,0.94);color:#fff;text-align:center';
    const line = document.createElement('div');
    line.id = 'rec-caption-text';
    line.style.cssText = 'font:700 30px/1.35 ' + font + ';min-height:40px;transition:opacity .3s';
    const note = document.createElement('div');
    note.id = 'rec-honesty';
    note.style.cssText = 'margin-top:6px;font:600 20px/1.3 ' + font + ';color:#D5DEEC;letter-spacing:.02em';
    bar.append(line, note);
    document.body.appendChild(bar);
  }
  if (honesty) bar.querySelector('#rec-honesty').textContent = honesty;
  if (text === null) return;
  const line = bar.querySelector('#rec-caption-text');
  line.style.opacity = 0;
  setTimeout(() => { line.textContent = text; line.style.opacity = 1; }, 250);
}
"""


def overlay_on_load(honesty: str) -> str:
    """An init script: the bar, with its honesty line, is on the page from its first paint."""
    return (f"document.addEventListener('DOMContentLoaded', () => ({OVERLAY.strip()})"
            f"([null, {json.dumps(honesty)}]));")


class Waits:
    """Seconds since the page (and so its video) started, and every wait for Claude or the replay."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.spans: list[tuple[str, str, float, float]] = []

    def now(self) -> float:
        return time.monotonic() - self.t0

    @contextlib.contextmanager
    def timing(self, kind: str, label: str):
        start = self.now()
        try:
            yield
        finally:
            end = self.now()
            self.spans.append((kind, label, start, end))
            print(f"wait {kind} ({label}): {start:.2f}-{end:.2f} s, {end - start:.2f} s", file=sys.stderr)


def _timing(waits: Waits | None, kind: str, label: str):
    return waits.timing(kind, label) if waits is not None else contextlib.nullcontext()


PRESS = """
(sel) => {
  const el = document.querySelector(sel);
  el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  el.style.outline = '5px solid #E0A800'; el.style.outlineOffset = '3px';
  setTimeout(() => { el.style.outline = ''; }, 1400);
}
"""


#: Scroll as little as needed for the given elements to sit fully above the caption bar (the last
#: one wins when they do not all fit: it is the scene's key row). The body gets room at its foot,
#: so even the page's last element can rise above the bar.
REVEAL = """
([sels, margin]) => {
  const bar = document.getElementById('rec-caption');
  const barH = bar ? bar.getBoundingClientRect().height : 0;
  if ((parseFloat(document.body.style.paddingBottom) || 0) < barH + margin) {
    document.body.style.paddingBottom = (barH + margin) + 'px';
  }
  const rects = sels.map((s) => document.querySelector(s)).filter(Boolean).map((e) => e.getBoundingClientRect());
  if (!rects.length) return 0;
  const top = Math.min(...rects.map((r) => r.top)), bottom = Math.max(...rects.map((r) => r.bottom));
  const lo = margin, hi = innerHeight - barH - margin;
  let delta = 0;
  if (bottom - top <= hi - lo) { if (bottom > hi) delta = bottom - hi; else if (top < lo) delta = top - lo; }
  else delta = rects[rects.length - 1].bottom - hi;
  if (Math.abs(delta) >= 1) window.scrollBy({ top: delta, behavior: 'smooth' });
  return delta;
}
"""
#: Which of the given elements are missing, or not wholly between the top and the caption bar.
HIDDEN = """
(sels) => {
  const bar = document.getElementById('rec-caption');
  const hi = innerHeight - (bar ? bar.getBoundingClientRect().height : 0);
  return sels.filter((s) => { const e = document.querySelector(s); if (!e) return true;
    const r = e.getBoundingClientRect(); return r.top < 0 || r.bottom > hi + 0.5; });
}
"""
#: Resolves once the page has stopped scrolling (a smooth scroll ends), or after 2.5 s.
SETTLE = """
() => new Promise((done) => {
  const t0 = performance.now(); let last = null, still = 0;
  const tick = () => {
    const y = scrollY; still = y === last ? still + 1 : 0; last = y;
    const t = performance.now() - t0;
    if ((still >= 8 && t > 250) || t > 2500) done(y); else requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})
"""
#: The first (newest) row of a feed, as text: a new row is a different first row.
FIRST_ROW = "(sel) => { const li = document.querySelector(sel + ' li.entry'); return li ? li.textContent : ''; }"


def reveal(page: Page, selectors: list[str]) -> None:
    """Bring a scene's key rows fully above the caption bar, and say so if one stays hidden."""
    page.evaluate(SETTLE)            # measure after any scroll still under way, not during it
    page.evaluate(REVEAL, [selectors, 24])
    page.evaluate(SETTLE)
    hidden = page.evaluate(HIDDEN, selectors)
    if hidden:
        print(f"warning: still missing or under the caption bar: {', '.join(hidden)}", file=sys.stderr)


def wait_for(page: Page, script: str, arg: Any, what: str, timeout_ms: int = 6000) -> None:
    """Wait for the page's next refresh (every 2 s) to show ``what``; a warning, not a failure."""
    try:
        page.wait_for_function(script, arg=arg, timeout=timeout_ms)
    except PlaywrightTimeout:
        print(f"warning: {what} did not appear within {timeout_ms / 1000:g} s", file=sys.stderr)


def caption(page: Page, text: str, hold_ms: int | None = None, honesty: str | None = None) -> None:
    page.evaluate(OVERLAY, [text, honesty])
    page.wait_for_timeout(HOLDS["caption"] if hold_ms is None else hold_ms)


def press(page: Page, selector: str) -> None:
    page.evaluate(PRESS, selector)
    page.wait_for_timeout(1100)
    page.click(selector)


def ask_claude(page: Page, side: str, ask: str, waits: Waits | None = None, feed: str | None = None) -> None:
    """Ask Claude; hold on its conversation and — with ``feed`` — the row that call adds to that
    board (the system's or the gateway's record), both clear of the caption bar."""
    chat = f"#chat-{side}"
    # The previous run's finished conversation is still on the page until the new one renders:
    # wait for a different run, finished — not for any finished-looking conversation.
    before = page.evaluate("(sel) => document.querySelector(sel).dataset.run || ''", chat)
    first = page.evaluate(FIRST_ROW, feed) if feed else ""
    press(page, f'.btn.ask[data-side="{side}"][data-ask="{ask}"]')
    with _timing(waits, "claude", f"{side}/{ask}"):
        page.wait_for_function(
            "([sel, before]) => { const box = document.querySelector(sel);"
            " return box.dataset.run && box.dataset.run !== before && box.querySelector('.ag-meta, .ag-err'); }",
            arg=[chat, before], timeout=CLAUDE_WAIT_MS)
    page.evaluate("(sel) => document.querySelector(sel).scrollIntoView({block: 'center', behavior: 'smooth'})", chat)
    keep = [chat]
    if feed:
        wait_for(page, f"([sel, first]) => {{ const f = ({FIRST_ROW})(sel); return f && f !== first; }}",
                 [feed, first], f"this call's row in {feed}")
        keep.append(f"{feed} li.entry")
    reveal(page, keep)
    page.wait_for_timeout(HOLDS["after"])


def replay_scene(page: Page, waits: Waits | None = None) -> None:
    """Press the replay button and wait for this press's result. The previous take's result stays
    on the page until the new one renders, so wait for a different run id — not for any result."""
    out = "#replay-out"
    before = page.evaluate("(sel) => document.querySelector(sel).dataset.run || ''", out)
    press(page, "#replay")
    with _timing(waits, "replay", "replay"):
        page.wait_for_function(
            "([sel, before]) => { const box = document.querySelector(sel);"
            " return box.dataset.run && box.dataset.run !== before; }",
            arg=[out, before], timeout=REPLAY_WAIT_MS)
    ended = page.evaluate("(sel) => [...document.querySelectorAll(sel + ' li[data-delivery]')]"
                          ".map((li) => li.dataset.status)", out)
    if ended != ["allowed", "refused"]:
        # The caption says the original was accepted and the copy refused; the page shows what the
        # gateway answered. When they disagree, the take is wrong — say so rather than ship it.
        print(f"warning: the replay scene ended {ended}, not as its caption says; re-take it",
              file=sys.stderr)
    page.evaluate("(sel) => document.querySelector(sel).scrollIntoView({block: 'center', behavior: 'smooth'})", out)
    reveal(page, [out])   # both deliveries and the note under them
    page.wait_for_timeout(HOLDS["replay"])


def record(out: Path, lang: str, headed: bool, stills: Path | None = None,
           max_seconds: float = 0.0) -> Path:
    lines = CAPTIONS[lang]
    honesty = HONESTY[lang]
    if stills:
        stills.mkdir(parents=True, exist_ok=True)

    def still(page: Page, step: int) -> None:
        """Each step as it ends, at full size: the PDF's fallback for a projector without video."""
        if stills:
            page.screenshot(path=str(stills / f"step-{step}-{lang}.png"))

    def say(page: Page, text: str, hold_ms: int | None = None) -> None:
        caption(page, text, hold_ms, honesty)

    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headed)
        context = browser.new_context(viewport=SIZE, record_video_dir=tmp, record_video_size=SIZE,
                                      locale="zh-TW" if lang == "zh" else "en-GB")
        context.add_init_script(overlay_on_load(honesty))
        page = context.new_page()
        waits = Waits()                     # the page's video starts with the page
        # ?lang=: the page renders in the take's language from its first paint (story.js reads it).
        page.goto(f"{CONSOLE}/story?mode=live&lang={lang}")
        page.wait_for_selector(".btn.ask:not([disabled])", timeout=30_000)
        if lang == "en":
            page.click('[data-lang="en"]')
        page.click("#fresh-start")
        caption(page, lines[0], 600, honesty)   # its 250 ms delay and 300 ms fade-in
        # The video starts here, on the opening caption: not on the blank tab, the page loading or
        # the fresh start before it.
        shown = waits.now()
        page.wait_for_timeout(HOLDS["intro"])

        say(page, lines[1])
        ask_claude(page, "before", "enrol", waits, feed="#before-feed")
        still(page, 1)

        say(page, lines[2])
        ask_claude(page, "after", "enrol", waits, feed="#after-feed")
        still(page, 2)

        say(page, lines[3])
        press(page, "#impersonate")
        page.wait_for_function("() => { const m = document.querySelector('#imp-msg'); "
                               "return m && m.textContent && m.textContent !== '…'; }", timeout=60_000)
        page.wait_for_timeout(HOLDS["settle"])   # the next refresh brings both filings onto the boards
        wait_for(page, "() => document.querySelector('#before-feed li.impostor')"
                       " && document.querySelector('#after-feed li.impostor')", None, "both impostor rows")
        page.evaluate("() => document.querySelector('.imp').scrollIntoView({block: 'end', behavior: 'smooth'})")
        # Both boards' impostor rows (the refusal last: the key row) and the line saying what happened.
        reveal(page, ["#imp-msg", "#before-feed li.impostor", "#after-feed li.impostor"])
        page.wait_for_timeout(HOLDS["impostor"])
        still(page, 3)

        say(page, lines[4])
        ask_claude(page, "after", "adjust", waits, feed="#after-feed")
        still(page, 4)

        say(page, lines[5])
        replay_scene(page, waits)
        still(page, 5)

        page.evaluate("() => document.querySelector('.cmp').scrollIntoView({block: 'center', behavior: 'smooth'})")
        reveal(page, [".cmp"])
        say(page, lines[6], HOLDS["final"])

        video = page.video.path()
        closed = waits.now()
        print(f"page closed at {closed:.2f} s", file=sys.stderr)
        context.close()
        browser.close()
        webm = Path(tmp) / "take.webm"
        shutil.move(video, webm)
        return to_mp4(webm, out, lang=lang, start=shown, spans=waits.spans, max_seconds=max_seconds,
                      closed=closed)


def plan(total: float, spans: list[tuple[str, str, float, float]], limit: float,
         start: float = 0.0) -> tuple[int, list[tuple[str, float, float]]]:
    """Which waits to speed up, and by one factor for all, for the video (``start``..``total`` s of
    the take) to fit in ``limit`` s. ``(1, [])``: it fits as it is, or there is nothing to speed up."""
    stretches = [(kind, max(a + EDGE, start), min(b - EDGE, total)) for kind, _, a, b in spans]
    stretches = [(kind, a, b) for kind, a, b in stretches if b - a >= SHORTEST]
    aim = limit - SLACK
    if not limit or total - start <= aim or not stretches:
        return 1, []
    waited = sum(b - a for _, a, b in stretches)
    rest = total - start - waited
    factor = MOST if rest >= aim else min(MOST, max(2, math.ceil(waited / (aim - rest))))
    return factor, stretches


def squeeze(t: float, start: float, factor: int, stretches: list[tuple[str, float, float]]) -> float:
    """Where the take's second ``t`` lands in the video."""
    return t - start - (1 - 1 / factor) * sum(min(max(t - a, 0.0), b - a) for _, a, b in stretches)


def _font(lang: str, size: int):
    from PIL import ImageFont

    fonts = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "Fonts"
    names = ["msjhbd.ttc", "msjh.ttc"] if lang == "zh" else ["segoeuib.ttf", "arialbd.ttf"]
    for candidate in [*(str(fonts / name) for name in names), "NotoSansCJK-Bold.ttc", "DejaVuSans-Bold.ttf"]:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def badge(text: str, lang: str, path: Path) -> Path:
    """The fast-forward label: "▶▶" (drawn, not a glyph) and ``text``, on an amber pill."""
    from PIL import Image, ImageDraw

    font = _font(lang, 40)
    left, top, right, bottom = ImageDraw.Draw(Image.new("RGBA", (1, 1))).textbbox((0, 0), text, font=font)
    tri_w, tri_h, gap, space, pad_x, pad_y = 24, 30, 3, 18, 30, 16
    height = max(tri_h, bottom - top) + 2 * pad_y
    width = pad_x + 2 * tri_w + gap + space + (right - left) + pad_x
    image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    ink = (16, 32, 58, 255)
    draw.rounded_rectangle((0, 0, width - 1, height - 1), radius=height // 2,
                           fill=(224, 168, 0, 250), outline=ink, width=3)
    middle, x = height / 2, pad_x
    for _ in range(2):
        draw.polygon([(x, middle - tri_h / 2), (x + tri_w, middle), (x, middle + tri_h / 2)], fill=ink)
        x += tri_w + gap
    draw.text((x - gap + space - left, middle - (bottom - top) / 2 - top), text, font=font, fill=ink)
    image.save(path)
    return path


def to_mp4(webm: Path, out: Path, lang: str = "zh", start: float = 0.0,
           spans: list[tuple[str, str, float, float]] | tuple = (), max_seconds: float = 0.0,
           closed: float | None = None) -> Path:
    """The take from ``start`` s, as h264. If it runs over ``max_seconds``, the waits in ``spans``
    are sped up — only they, by one factor — and each sped-up stretch carries the badge.

    ``start`` and ``spans`` are on the script's clock, which starts when the page opens; the video's
    starts at its first frame, which can come a second or more later. Both end when the page closes
    (``closed`` on the script's clock), so the script's clock runs ahead by ``closed`` minus the
    video's length, and every time is moved back by that before it is used."""
    import imageio_ffmpeg

    out.parent.mkdir(parents=True, exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    _, total = imageio_ffmpeg.count_frames_and_secs(str(webm))
    lag = max(0.0, closed - total) if closed else 0.0
    print(f"the script's clock is {lag:.2f} s ahead of the video's", file=sys.stderr)
    start = max(0.0, start - lag)
    spans = [(kind, label, a - lag, b - lag) for kind, label, a, b in spans]
    factor, stretches = plan(total, list(spans), max_seconds, start)
    shift = "+".join(f"clip(T-{a:.3f},0,{b - a:.3f})" for _, a, b in stretches) or "0"
    graph = [f"[0:v]trim=start={start:.3f},"
             f"setpts='(T-{start:.3f}-{1 - 1 / factor:.6f}*({shift}))/TB',fps={FPS}[v0]"]
    inputs, last = ["-i", str(webm)], "v0"
    with tempfile.TemporaryDirectory() as tmp:
        for n, kind in enumerate(sorted({kind for kind, _, _ in stretches}), start=1):
            png = badge(BADGE[lang][kind].format(n=factor), lang, Path(tmp) / f"badge-{kind}.png")
            when = "+".join(f"between(t,{squeeze(a, start, factor, stretches):.3f},"
                            f"{squeeze(b, start, factor, stretches):.3f})"
                            for k, a, b in stretches if k == kind)
            inputs += ["-i", str(png)]
            graph.append(f"[{last}][{n}:v]overlay=x=main_w-overlay_w-40:y=40:enable='{when}'[v{n}]")
            last = f"v{n}"
        subprocess.run([ffmpeg, "-y", "-loglevel", "error", *inputs, "-filter_complex", ";".join(graph),
                        "-map", f"[{last}]", "-c:v", "libx264", "-preset", "slow", "-crf", "18",
                        "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(out)], check=True)
    length = squeeze(total, start, factor, stretches)
    print(f"take {total:.2f} s; video from {start:.2f} s", file=sys.stderr)
    if factor == 1:
        print(f"no speed-up; video {length:.2f} s", file=sys.stderr)
    else:
        for kind, a, b in stretches:
            print(f"sped up x{factor} ({kind}): take {a:.2f}-{b:.2f} s -> video "
                  f"{squeeze(a, start, factor, stretches):.2f}-{squeeze(b, start, factor, stretches):.2f} s",
                  file=sys.stderr)
        print(f"video {length:.2f} s", file=sys.stderr)
    if max_seconds and length > max_seconds:
        print(f"warning: the video is {length:.1f} s, over --max-seconds {max_seconds:g}", file=sys.stderr)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=Path("agent-demo.mp4"))
    parser.add_argument("--lang", choices=["zh", "en"], default="zh")
    parser.add_argument("--headed", action="store_true", help="show the browser while recording")
    parser.add_argument("--brisk", action="store_true", help="shorter pauses, for a short talk")
    parser.add_argument("--stills", type=Path, help="also save each step as it ends, as step-N-<lang>.png")
    parser.add_argument("--max-seconds", type=float, default=100.0,
                        help="if the take runs longer, speed up only the waits for Claude and the replay "
                             "(labelled on screen) so that it fits; 0 keeps real time throughout")
    args = parser.parse_args()
    if args.brisk:
        HOLDS.update(BRISK)
    if args.out.exists():
        print(f"{args.out} exists; choose another --out", file=sys.stderr)
        return 2
    print(record(args.out, args.lang, args.headed, args.stills, args.max_seconds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
