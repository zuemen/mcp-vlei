#!/usr/bin/env bash
#
# live-guard.sh — evidence that the live demonstration stack was not touched.
#
#   bash scripts/live-guard.sh snapshot <file>      # name, image ID, start time, status of every live container
#   bash scripts/live-guard.sh check <file>         # exit 1, naming what changed, if anything differs
#   bash scripts/live-guard.sh check-base <file>    # the same, ignoring mcp-vlei-regulator-* (the switch
#                                                   # recreates those; nothing else may change)
#   bash scripts/live-guard.sh check-images <file>  # names and image IDs only (after a rollback)
#
# Read-only: `docker ps` and `docker inspect`, nothing else. Run `snapshot` before and `check`
# after every task that runs Docker, until the v0.3 switch (scripts/v03-switch.sh) — the one task
# allowed to change the live stack, which takes its own snapshot first.
#
# Live: mcp-vlei-regulator-*, mcp-vlei-{witness,verifier,cli,schema}, ragflow-*. The parallel v0.3
# stack (mcp-vlei-v03p*) is not live and is not recorded.
#
# Docker unreachable and "no live containers" must never look like anything other than what they
# are: both exit non-zero naming the problem, never as "unchanged" and never as "THE LIVE STACK
# CHANGED" — a dead Docker daemon is not evidence that someone touched the containers. A failure
# inside a pipeline or a process substitution does not reach the caller's `set -e`, so every
# `docker` call here is captured into a variable first and its exit status tested explicitly,
# before that output is ever handed to `diff` or written to a file.
set -euo pipefail

LIVE='^(mcp-vlei-regulator-.*|mcp-vlei-(witness|verifier|cli|schema)|ragflow-.*)$'

# Prints one line per live container (name, image, start time, status) on stdout.
#   returns 2, naming docker on stderr, if `docker ps` or `docker inspect` could not be reached.
#   returns 3, on stderr, if docker answered but nothing matched $LIVE.
# Either way stdout is not to be trusted by the caller: "could not read" must never be mistaken
# for "zero containers is the true state".
snapshot() {
  local raw
  if ! raw="$(docker ps -a --format '{{.Names}}' 2>&1)"; then
    echo "live-guard: docker is not reachable (docker ps failed): ${raw}" >&2
    return 2
  fi

  local matched
  matched="$(printf '%s\n' "$raw" | grep -E "$LIVE" | sort || true)"
  if [[ -z "$matched" ]]; then
    echo "live-guard: docker answered but no live container matched the live set — refusing an empty baseline" >&2
    return 3
  fi

  local name line
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if ! line="$(docker inspect -f '{{.Name}} {{.Image}} {{.State.StartedAt}} {{.State.Status}}' "$name" 2>&1)"; then
      echo "live-guard: docker is not reachable (docker inspect ${name} failed): ${line}" >&2
      return 2
    fi
    printf '%s\n' "$line"
  done <<< "$matched"
}

compare() {  # $1 snapshot file, $2 filter applied to both sides
  local before="$1" filter="$2"
  [[ -f "$before" && -s "$before" ]] \
    || { echo "live-guard: no usable baseline at $before (missing or empty)" >&2; exit 2; }

  local current status=0
  current="$(snapshot)" || status=$?
  if [[ "$status" -ne 0 ]]; then
    # snapshot() already named the problem on stderr. Stop with its status here — never fall
    # through to the diff below and report an untrustworthy read as "changed" or "unchanged".
    exit "$status"
  fi

  # The filter is eval'd under `set -o pipefail`: a filter like `grep -v ...` that legitimately
  # matches nothing (e.g. check-base when every container is a regulator one) exits 1 on its own,
  # which must not be confused with a real failure — the filter strings below are kept total
  # (`|| true`) for that known case. Any other filter failure is still caught here and named,
  # rather than let `set -e` kill the script silently with a bare exit 1 that looks exactly like
  # "THE LIVE STACK CHANGED" never printed its message.
  local now_filtered then_filtered
  now_filtered="$(printf '%s\n' "$current" | eval "$filter")" || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "live-guard: could not filter the snapshot" >&2
    exit 2
  fi
  then_filtered="$(eval "$filter" < "$before")" || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "live-guard: could not filter the snapshot" >&2
    exit 2
  fi

  if diff <(printf '%s\n' "$now_filtered") <(printf '%s\n' "$then_filtered") >/dev/null; then
    echo "live-guard: unchanged ($(printf '%s\n' "$then_filtered" | wc -l | tr -d ' ') containers compared)"
  else
    echo "live-guard: THE LIVE STACK CHANGED — now (<) against the snapshot (>):" >&2
    diff <(printf '%s\n' "$now_filtered") <(printf '%s\n' "$then_filtered") >&2 || true
    exit 1
  fi
}

case "${1:-}" in
  snapshot)
    out="${2:?usage: live-guard.sh snapshot <file>}"
    status=0
    content="$(snapshot)" || status=$?
    if [[ "$status" -ne 0 ]]; then
      # snapshot() already named the problem on stderr (docker unreachable, or nothing matched).
      # $out is never touched — no partial or empty file is left behind on failure.
      echo "live-guard: no snapshot written" >&2
      exit "$status"
    fi
    mkdir -p "$(dirname "$out")"
    printf '%s\n' "$content" > "$out"
    echo "live-guard: $(printf '%s\n' "$content" | wc -l | tr -d ' ') live containers recorded in $out"
    ;;
  check)        compare "${2:?usage: live-guard.sh check <file>}" "cat" ;;
  check-base)   compare "${2:?usage: live-guard.sh check-base <file>}" "{ grep -v '^/mcp-vlei-regulator-' || true; }" ;;
  check-images) compare "${2:?usage: live-guard.sh check-images <file>}" "cut -d' ' -f1,2" ;;
  *)
    echo "usage: bash scripts/live-guard.sh snapshot|check|check-base|check-images <file>" >&2
    exit 2
    ;;
esac
