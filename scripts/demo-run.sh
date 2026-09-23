#!/usr/bin/env bash
#
# demo-run.sh — drive the console through the scenes, at the pace of whoever is recording.
#
#   bash scripts/demo-run.sh             # all scenes, pausing between each
#   bash scripts/demo-run.sh --scene 3   # one scene
#
# Prints each scene's title before it runs and its verification report after, so the terminal is a
# usable second screen. The console itself is driven over HTTP, so the keyboard shortcuts still
# work — use whichever suits the take.

set -uo pipefail

CONSOLE="${CONSOLE_URL:-http://localhost:8800}"

TITLES=(
  "0  Impersonation — quota granted on a name the caller chose"
  "1  A verified call — eight checks, ALLOWED"
  "2  A client without the extension — additive"
  "3  Revocation — six still true, one no longer"
  "4  Through the gateway — the agent does not change"
  "5  A server written from the skill"
)

c_reset=$'\033[0m'; c_hi=$'\033[36m'; c_dim=$'\033[90m'

report() {
  curl -fsS "${CONSOLE}/state" | python -c "
import json, sys
state = json.load(sys.stdin)
verification = state.get('verification', {})
marks = {'pass': '+', 'fail': 'x', 'skipped': '-', 'pending': '.'}
for check in verification.get('checks', []):
    tail = check['layer'] or (f\"{check['ms']:6.1f} ms\" if check.get('ms') is not None else '')
    print(f\"    {marks.get(check['status'], '?')} {check['label']:<44} {tail}\")
    if check['status'] == 'fail' and check.get('detail'):
        print(f\"      {check['detail']}\")
outcome = verification.get('outcome', {})
verdict = outcome.get('status', '?').upper()
if outcome.get('layer'):
    verdict += f\" · {outcome['layer']}\"
print(f'  {verdict}')
if state.get('readiness'):
    print(f\"  ! {state['readiness']}\")
"
}

run_scene() {
  local n="$1"
  printf '\n%s==> %b%s\n\n' "$c_hi" "${TITLES[$n]}" "$c_reset"
  curl -fsS -X POST "${CONSOLE}/scene/${n}" >/dev/null || {
    printf '  could not reach the console at %s\n' "$CONSOLE"
    exit 1
  }
  sleep 3                      # let the reveal finish before reading the state back
  report
}

if ! curl -fsS "${CONSOLE}/state" >/dev/null 2>&1; then
  printf '\n  The console is not answering on %s\n  Start it: bash scripts/reset-demo.sh\n\n' "$CONSOLE"
  exit 1
fi

if [[ "${1:-}" == "--scene" && -n "${2:-}" ]]; then
  run_scene "$2"
  printf '\n'
  exit 0
fi

for n in 0 1 2 3 4 5; do
  run_scene "$n"
  if [[ $n -lt 5 ]]; then
    printf '\n%s  press enter for the next scene%s' "$c_dim" "$c_reset"
    read -r
  fi
done
printf '\n%s  done%s\n\n' "$c_dim" "$c_reset"
