#!/usr/bin/env bash
#
# reset-demo.sh — back to a clean state, ready to record.
#
#   bash scripts/reset-demo.sh                    # full: containers, credentials, services
#   bash scripts/reset-demo.sh --keep-credentials # faster: only the verifier and console state
#
# Ends with READY, or with the reason it did not. Between takes the fast path is usually enough;
# the full path is for the start of a session, or after anything has been changed.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) NATIVE_HERE="$(cygpath -m "$HERE")" ;;
  *)                    NATIVE_HERE="$HERE" ;;
esac
COMPOSE="docker compose -f ${NATIVE_HERE}/docker-compose.yml"
CONSOLE="${CONSOLE_URL:-http://localhost:8800}"

KEEP_CREDENTIALS=0
[[ "${1:-}" == "--keep-credentials" ]] && KEEP_CREDENTIALS=1

c_reset=$'\033[0m'; c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_hi=$'\033[36m'
step() { printf '\n%s==> %s%s\n' "$c_hi" "$*" "$c_reset"; }
ok()   { printf '%s  ok%s  %s\n' "$c_ok" "$c_reset" "$*"; }
die()  { printf '\n%s  NOT READY%s  %s\n\n' "$c_bad" "$c_reset" "$*"; exit 1; }

# --------------------------------------------------------------------------------------------- #

step "Stopping the console"
PID="$(netstat -ano 2>/dev/null | grep ':8800' | grep LISTENING | awk '{print $5}' | head -1)"
if [[ -n "${PID:-}" ]]; then
  taskkill //PID "$PID" //F >/dev/null 2>&1 || kill "$PID" 2>/dev/null
  ok "console stopped"
else
  ok "console was not running"
fi

if (( KEEP_CREDENTIALS )); then
  step "Resetting the verifier only (--keep-credentials)"
  # The verifier keeps its decisions in-container, so recreating it is the reset. Credentials and
  # the witness network are left alone, which is what makes this the fast path.
  $COMPOSE up -d --force-recreate vlei-verifier >/dev/null 2>&1 \
    || die "could not recreate the verifier"
  ok "verifier recreated with an empty database"
else
  step "Recreating every container"
  # `docker compose down -v` has been observed to leave containers behind on this setup, which
  # produces a stale verifier database and a confusing run. Remove them by name first.
  docker rm -f mcp-vlei-cli mcp-vlei-verifier mcp-vlei-witness mcp-vlei-schema >/dev/null 2>&1
  $COMPOSE up -d >/dev/null 2>&1 || die "containers did not start"
  ok "containers recreated"

  step "Waiting for services"
  for i in $(seq 1 60); do
    curl -fsS http://localhost:5642/oobi >/dev/null 2>&1 && break
    sleep 2
    [[ $i -eq 60 ]] && die "the witness network did not come up"
  done
  ok "witnesses up"
  for i in $(seq 1 60); do
    curl -fsS http://localhost:7676/health >/dev/null 2>&1 && break
    sleep 2
    [[ $i -eq 60 ]] && die "the verifier did not come up"
  done
  ok "verifier up"

  step "Issuing credentials (this is the slow part)"
  rm -rf "${ROOT}/credentials"
  DELEGATION_TRIES=20 bash "${HERE}/bootstrap-credentials.sh" > "${ROOT}/reset.log" 2>&1 \
    || die "bootstrap failed; see reset.log"
  ok "chain issued, six acceptance checks passed, credential re-issued at the end"
fi

step "Starting the console"
( cd "$ROOT" && PYTHONPATH="packages/mcp-vlei/src" \
  python examples/console/app.py > "${ROOT}/console.log" 2>&1 & )
for i in $(seq 1 30); do
  curl -fsS "${CONSOLE}/state" >/dev/null 2>&1 && break
  sleep 1
  [[ $i -eq 30 ]] && die "the console did not start; see console.log"
done
ok "console on ${CONSOLE}"

step "Checking recording preconditions"
bash "${HERE}/record-check.sh" || die "preconditions not met (see above)"

printf '\n%s  READY%s\n\n' "$c_ok" "$c_reset"
