"""Test counts, from pytest itself — so no document states a number nobody re-counted.

    python scripts/count-tests.py            # rewrite every count listed in TARGETS
    python scripts/count-tests.py --check    # exit 1, naming each stale count (CI)

Each count is `pytest --collect-only -q` over one suite, the same suites CI runs. The places that
state a count are TARGETS below; a slide deck built from this repository can ask this file at build time
instead of carrying one. A number anywhere else is handwritten — historical records such as
`examples/skill-server/REPORT.md` are left as they were written.
"""

from __future__ import annotations

import re
import subprocess
import sys
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SUITES = {
    "package": "packages/mcp-vlei/tests",
    "console": "examples/console/tests",
    "regulator": "examples/regulator/tests",
    "skill-server": "examples/skill-server/tests",
    "observatory": "examples/observatory/tests",
}

#: (file, pattern whose one group is the count, suite)
TARGETS = [
    ("README.md", r"`packages/mcp-vlei/` — (\d+) tests", "package"),
    ("packages/mcp-vlei/README.md", r"^(\d+) tests, no containers required", "package"),
    ("docs/CONFORMANCE.md", r"pytest packages/mcp-vlei/tests +# (\d+) tests", "package"),
    ("examples/README.md", r"`regulator/tests/` — (\d+) tests", "regulator"),
    ("examples/README.md", r"`skill-server/tests/` — (\d+) tests", "skill-server"),
    ("examples/README.md", r"`console/tests/` — (\d+) tests", "console"),
    ("examples/README.md", r"`observatory/tests/` — (\d+) tests", "observatory"),
    ("examples/skill-server/README.md", r"`tests/test_server.py` — (\d+) tests", "skill-server"),
]


@cache
def count(suite: str) -> int:
    """How many tests pytest collects in one suite."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", SUITES[suite]],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    found = re.search(r"^(\d+) tests? collected", result.stdout, re.M)
    if result.returncode != 0 or not found:
        tail = "\n".join((result.stdout + result.stderr).splitlines()[-5:])
        raise SystemExit(f"could not collect {SUITES[suite]}:\n{tail}")
    return int(found.group(1))


def main() -> int:
    check = "--check" in sys.argv[1:]
    stale: list[str] = []
    for relative, pattern, suite in TARGETS:
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        match = re.search(pattern, text, re.M)
        if not match:
            stale.append(f"{relative}: no count matching {pattern!r} — the sentence moved; update TARGETS")
            continue
        actual = count(suite)
        if int(match.group(1)) == actual:
            continue
        if check:
            stale.append(f"{relative}: says {match.group(1)} {suite} tests, pytest collects {actual}")
        else:
            text = text[:match.start(1)] + str(actual) + text[match.end(1):]
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"  {relative}: {match.group(1)} -> {actual} ({suite})")
    for line in stale:
        print(f"  ! {line}")
    if check and not stale:
        print("  every stated test count matches pytest")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
