#!/usr/bin/env bash
#
# demo-parallel.sh — a second console, from this worktree, against the PARALLEL v0.3 stack.
#
#   bash scripts/demo-parallel.sh
#
# For recording the talk's new demo video without ever touching the live stack: this console
# answers on :38800 (not :8800), signs through the parallel stack's keri-cli
# (VLEI_COMPOSE_CMD, from `scripts/v03-stack.sh env`) and reads .v03/credentials (not
# credentials/). examples/console/app.py refuses to start with VLEI_CREDENTIALS_DIR set unless
# VLEI_COMPOSE_CMD, VLEI_GATEWAY_URL, VLEI_BEFORE_URL and VLEI_WITNESS_URL are also set,
# explicitly — this script sets every one of them, every time, so that guard never has reason to
# fire here. Record against it with VLEI_CONSOLE_URL=http://localhost:38800 and your own --out
# (scripts/record-agent-demo.py), never the defaults — a parallel take must never overwrite the
# existing videos.
#
# Prints nothing secret: every value below is a URL or a local path — the same ones
# `scripts/v03-stack.sh env` itself prints for the other tasks that drive this stack.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

PORT=38800
REGULATOR_CONTAINER="mcp-vlei-v03p-regulator-agentgateway-1"

if netstat -ano 2>/dev/null | grep ":${PORT} " | grep -q LISTENING; then
  echo "demo-parallel: something is already listening on :${PORT} — stop it first" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${REGULATOR_CONTAINER}"; then
  echo "demo-parallel: ${REGULATOR_CONTAINER} is not running. Bring the parallel stack up first:" >&2
  echo "  bash scripts/v03-stack.sh up" >&2
  echo "  bash scripts/v03-stack.sh bootstrap" >&2
  echo "  bash scripts/v03-stack.sh gateway" >&2
  exit 1
fi

# `v03-stack.sh env` prints only URLs and local paths (no secret): VLEI_CREDENTIALS_DIR,
# VLEI_COMPOSE_CMD (the parallel base stack's compose command, exactly as it builds it),
# VLEI_WITNESS_URL / VLEI_WITNESS_URLS, and more this console does not need.
eval "$(bash "${HERE}/v03-stack.sh" env)"

# Pinned here rather than trusted to v03-stack.sh's own export of the first: the gateway and
# before URLs this console must use are this task's exact values, not whatever another task's
# script happens to compute today.
export VLEI_GATEWAY_URL="http://localhost:33000/mcp"
export VLEI_BEFORE_URL="http://127.0.0.1:38090"
export PORT="${PORT}"

echo "demo-parallel: console on http://localhost:${PORT} (parallel stack: VLEI_CREDENTIALS_DIR=${VLEI_CREDENTIALS_DIR})"
cd "${ROOT}"
PYTHONPATH="packages/mcp-vlei/src" exec python examples/console/app.py
