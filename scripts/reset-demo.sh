#!/usr/bin/env bash
#
# reset-demo.sh — back to a clean state, ready to record.
#
#   bash scripts/reset-demo.sh                    # full: containers, credentials, services
#   bash scripts/reset-demo.sh --keep-credentials # faster: only the verifier and console state
#
# Everything the six scenes need comes up: the witness network and verifier, the credential chain,
# the gateway (scene 4, pointed at the chain's root), the server written from the skill (scene 5)
# and the console. Ends with READY, or with the reason it did not. Between takes the fast path is usually enough;
# the full path is for the start of a session, or after anything has been changed.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Machine-local overrides (gitignored), e.g. witness host ports when Windows has reserved 5642-5644.
# `docker compose` reads the same file, so the scripts and the containers agree on the ports.
[[ -f "${HERE}/.env" ]] && { set -a; . "${HERE}/.env"; set +a; }
WITNESS_URL="${VLEI_WITNESS_URL:-http://localhost:5642}"
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

stop_port() {  # stop whatever listens on a local port: $1 port, $2 what it is
  local pid
  pid="$(netstat -ano 2>/dev/null | grep ":$1 " | grep LISTENING | awk '{print $5}' | head -1)"
  if [[ -n "${pid:-}" ]]; then
    taskkill //PID "$pid" //F >/dev/null 2>&1 || kill "$pid" 2>/dev/null
    ok "$2 stopped"
  else
    ok "$2 was not running"
  fi
}

step "Stopping the console and the skill-generated server"
stop_port 8800 "console"
stop_port 8082 "skill-generated server"

if (( KEEP_CREDENTIALS )); then
  step "Resetting the verifier only (--keep-credentials)"
  # The verifier keeps its decisions in-container, so recreating it is the reset. Credentials and
  # the witness network are left alone, which is what makes this the fast path.
  $COMPOSE up -d --force-recreate vlei-verifier >/dev/null 2>&1 \
    || die "could not recreate the verifier"
  ok "verifier recreated with an empty database"
  for i in $(seq 1 60); do
    curl -fsS http://localhost:7676/health >/dev/null 2>&1 && break
    sleep 2
    [[ $i -eq 60 ]] && die "the verifier did not come up"
  done
  # An empty database trusts no root, so the first presentation after this (the re-issue between
  # takes) would be rejected. Install the root the credentials were issued under.
  bash "${HERE}/bootstrap-credentials.sh" --install-root > "${ROOT}/reset.log" 2>&1     || die "could not install the root of trust; see reset.log"
  ok "root of trust installed in the new verifier"
else
  step "Recreating every container"
  # `docker compose down -v` has been observed to leave containers behind on this setup, which
  # produces a stale verifier database and a confusing run. Remove them by name first.
  docker rm -f mcp-vlei-cli mcp-vlei-verifier mcp-vlei-witness mcp-vlei-schema >/dev/null 2>&1
  $COMPOSE up -d >/dev/null 2>&1 || die "containers did not start"
  ok "containers recreated"

  step "Waiting for services"
  for i in $(seq 1 60); do
    curl -fsS "${WITNESS_URL}/oobi" >/dev/null 2>&1 && break
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

# Relative, from the repository: on Windows, Python cannot open a Git Bash path like /c/Users/….
ROOT_AID="$(cd "$ROOT" && python -c "import json;print(json.load(open('credentials/env.json'))['acceptedRoots'][0])" 2>/dev/null)"
[[ -n "$ROOT_AID" ]] || die "credentials/env.json has no accepted root; run without --keep-credentials"

# Background services are started with the subshell's own output detached as well: on Git Bash a
# stub process stays alive beside each native one, and if it held this script's stdout, anything
# reading it (`| tee reset.log`) would wait for the console to exit.

step "Starting the gateway (scene 4)"
# Recreated, because the root it trusts is the one the chain was just issued under.
( cd "$ROOT" && VLEI_ACCEPTED_ROOTS="$ROOT_AID" \
  docker compose -f deploy/agentgateway/docker-compose.yml up -d --build --force-recreate \
  > "${ROOT}/gateway.log" 2>&1 ) || die "the gateway did not start; see gateway.log"
for i in $(seq 1 60); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://localhost:3000/mcp)" != "000" ]] && break
  sleep 2
  [[ $i -eq 60 ]] && die "the gateway did not answer on :3000; see gateway.log"
done
ok "gateway on http://localhost:3000/mcp, trusting ${ROOT_AID}"

step "Starting the server written from the skill (scene 5)"
( cd "$ROOT" && PYTHONPATH="packages/mcp-vlei/src" VLEI_LE_CREDENTIAL=credentials/le.cesr \
  VLEI_ACCEPTED_ROOTS="$ROOT_AID" VLEI_WITNESS_URL="$WITNESS_URL" PORT=8082 \
  python examples/skill-server/server.py > "${ROOT}/skill-server.log" 2>&1 & ) </dev/null >/dev/null 2>&1
for i in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8082/.well-known/vlei >/dev/null 2>&1 && break
  sleep 1
  [[ $i -eq 30 ]] && die "the skill-generated server did not start; see skill-server.log"
done
ok "skill-generated server on http://127.0.0.1:8082/mcp"

step "Starting the console"
( cd "$ROOT" && PYTHONPATH="packages/mcp-vlei/src" \
  python examples/console/app.py > "${ROOT}/console.log" 2>&1 & ) </dev/null >/dev/null 2>&1
for i in $(seq 1 30); do
  curl -fsS "${CONSOLE}/state" >/dev/null 2>&1 && break
  sleep 1
  [[ $i -eq 30 ]] && die "the console did not start; see console.log"
done
ok "console on ${CONSOLE}"

step "Checking recording preconditions"
bash "${HERE}/record-check.sh" || die "preconditions not met (see above)"

printf '\n%s  READY%s\n\n' "$c_ok" "$c_reset"
