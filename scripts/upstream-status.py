"""Is the vlei-verifier issue's status stated consistently?

    python scripts/upstream-status.py                 # status.json on its own
    python scripts/upstream-status.py path/to/talk.md # and a talk that states the status

`docs/upstream/status.json` is the one place the status is written. On its own it must be
consistent: once `filed` is true it names the issue. Given a talk, the talk must say the `say`
phrase and, while `filed` is false, none of `never_say_until_filed` — "we reported it", when
nothing has been reported, is the mistake this exists to stop.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "docs" / "upstream" / "status.json"


def problems(talk: Path | None = None) -> list[str]:
    status = json.loads(STATUS.read_text(encoding="utf-8"))
    found = []
    if status.get("filed") and not status.get("issue"):
        found.append(f"{STATUS.name} says filed but gives no issue link")
    if talk is None:
        return found
    text = " ".join(talk.read_text(encoding="utf-8").replace(">", " ").split()).lower()
    if status["say"].lower() not in text:
        found.append(f"{talk.name} never says {status['say']!r}, which is the status in {STATUS.name}")
    if not status["filed"]:
        for phrase in status["never_say_until_filed"]:
            if phrase.lower() in text:
                found.append(f"{talk.name} says {phrase!r}, but {STATUS.name} says the issue is not filed")
    return found


if __name__ == "__main__":
    wrong = problems(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
    for line in wrong:
        print(f"  ! {line}")
    if not wrong:
        print("  the upstream issue's status is stated consistently")
    sys.exit(1 if wrong else 0)
