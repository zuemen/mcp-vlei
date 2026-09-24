#!/usr/bin/env bash
#
# record-check.sh — everything that has to be true before a take.
#
#   bash scripts/record-check.sh
#
# Exits non-zero if any check fails, so it can gate `demo-run.sh` or a CI job. Each line says what
# was checked and what to do about it, because the point is to fix problems before the camera is
# running rather than to discover them during a take.
#
# The expensive one is the credential: the acceptance suite revokes it, so a console started after
# a test run shows `revoked` in scene 1. That is the console being right, and it is also a reshoot.

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
VERIFIER="${VLEI_VERIFIER_URL:-http://localhost:7676}"
WITNESS="${VLEI_WITNESS_URL:-http://localhost:5642}"
MIN_FREE_GB="${MIN_FREE_GB:-10}"

c_reset=$'\033[0m'; c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_dim=$'\033[90m'
FAILED=0

ok()   { printf '%s  ok  %s%s\n' "$c_ok" "$c_reset" "$1"; }
bad()  { printf '%s fail %s%s\n' "$c_bad" "$c_reset" "$1"; printf '%s       %s%s\n' "$c_dim" "$2" "$c_reset"; FAILED=1; }
note() { printf '%s       %s%s\n' "$c_dim" "$1" "$c_reset"; }

printf '\n  Recording preconditions\n\n'

# --------------------------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------------------------- #

if curl -fsS "${WITNESS}/oobi" >/dev/null 2>&1; then
  ok "witness network answering on ${WITNESS}"
else
  bad "witness network is not answering on ${WITNESS}" \
      "run: docker compose -f scripts/docker-compose.yml up -d"
fi

if curl -fsS "${VERIFIER}/health" >/dev/null 2>&1; then
  ok "verifier answering on ${VERIFIER}"
else
  note "verifier is not answering on ${VERIFIER}"
  note "not fatal: revocation is read from the witness by default (revocation_source=\"tel\")"
fi

# --------------------------------------------------------------------------------------------- #
# Credentials — the one that bites
# --------------------------------------------------------------------------------------------- #

ENV_FILE="${ROOT}/credentials/env.json"
if [[ -f "$ENV_FILE" ]]; then
  ok "credentials/env.json present"

  SAID="$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['ecrSaid'])" "$ENV_FILE" 2>/dev/null)"
  if [[ -z "$SAID" ]]; then
    bad "could not read ecrSaid from credentials/env.json" "re-run: bash scripts/bootstrap-credentials.sh"
  elif curl -fsS "${WITNESS}/query?typ=tel&vcid=${SAID}" 2>/dev/null | grep -q '"t":"rev"'; then
    bad "the agent's credential is REVOKED" \
        "scene 1 will refuse. Re-issue: bash scripts/bootstrap-credentials.sh"
  else
    ok "the agent's credential is live (no rev event in the issuer's log)"
  fi
else
  bad "no credentials/env.json" "run: bash scripts/bootstrap-credentials.sh"
fi

# --------------------------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------------------------- #

if curl -fsS "${CONSOLE}/state" >/dev/null 2>&1; then
  ok "console answering on ${CONSOLE}"

  READINESS="$(curl -fsS "${CONSOLE}/state" | python -c "
import json,sys
print(json.load(sys.stdin).get('readiness') or '')" 2>/dev/null)"
  if [[ -n "$READINESS" ]]; then
    bad "the console reports it is not ready" "$READINESS"
  else
    ok "console reports no readiness problem"
  fi

  # The reveal is driven by SSE; a console that cannot stream shows a frozen column on camera.
  # An event stream never ends, so curl always stops on --max-time with a non-zero status; under
  # `pipefail` that failed the whole pipeline and this check could never pass. Capture, then look.
  EVENTS="$(curl -sS --max-time 5 -H 'Accept: text/event-stream' "${CONSOLE}/events" 2>/dev/null \
            | head -c 200 || true)"
  if grep -q '"scene"' <<<"$EVENTS"; then
    ok "console event stream delivering state"
  else
    bad "console /events did not deliver a state within 5s" \
        "restart it: python examples/console/app.py"
  fi
else
  bad "console is not answering on ${CONSOLE}" \
      "run: python examples/console/app.py"
fi

# --------------------------------------------------------------------------------------------- #
# Scenes 4 and 5: real servers. The console will not stand in for them — it shows NOT RUNNING.
# --------------------------------------------------------------------------------------------- #

GATEWAY="${VLEI_GATEWAY_URL:-http://localhost:3000/mcp}"
SKILL="${VLEI_SKILL_SERVER_URL:-http://127.0.0.1:8082/mcp}"
if curl -sS -o /dev/null --max-time 5 "${GATEWAY}" 2>/dev/null; then
  ok "scene 4: gateway answering on ${GATEWAY}"
else
  bad "scene 4: nothing on ${GATEWAY}" \
      "VLEI_ACCEPTED_ROOTS=<root from credentials/env.json> docker compose -f deploy/agentgateway/docker-compose.yml up -d"
fi
if curl -fsS -o /dev/null --max-time 5 "${SKILL%/mcp}/.well-known/vlei" 2>/dev/null; then
  ok "scene 5: skill-generated server answering on ${SKILL}"
else
  bad "scene 5: nothing on ${SKILL}" \
      "see examples/skill-server/README.md — VLEI_LE_CREDENTIAL, VLEI_ACCEPTED_ROOTS, VLEI_WITNESS_URL"
fi

# --------------------------------------------------------------------------------------------- #
# Scene 0's server
# --------------------------------------------------------------------------------------------- #

# Imported rather than started: a stdio server started here would sit waiting for a client, and
# the question is only whether it loads. The path stays relative so Windows backslashes never
# reach the Python source.
if (cd "$ROOT" && timeout 60 python -c "
import importlib.util
spec = importlib.util.spec_from_file_location('vendor', 'examples/impersonation/vendor_server.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
" >/dev/null 2>&1); then
  ok "examples/impersonation server imports"
else
  bad "examples/impersonation/vendor_server.py does not import" \
      "check: pip install -e packages/mcp-vlei"
fi

# --------------------------------------------------------------------------------------------- #
# Disk
# --------------------------------------------------------------------------------------------- #

FREE_GB="$(df -P -BG "${ROOT}" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
if [[ -n "$FREE_GB" ]] && (( FREE_GB >= MIN_FREE_GB )); then
  ok "${FREE_GB}GB free (need ${MIN_FREE_GB}GB)"
else
  bad "only ${FREE_GB:-?}GB free, want ${MIN_FREE_GB}GB" \
      "1080p30 at 10 Mbps is roughly 75MB per minute, plus takes you will discard"
fi

# --------------------------------------------------------------------------------------------- #

printf '\n'
if (( FAILED )); then
  printf '%s  NOT READY%s — fix the lines marked fail, then run this again.\n\n' "$c_bad" "$c_reset"
  exit 1
fi
printf '%s  READY%s\n' "$c_ok" "$c_reset"
note "browser at 1920x1080, zoom 100%, open ${CONSOLE}/?chrome=off"
note "notifications off, bookmarks bar hidden"
printf '\n'
