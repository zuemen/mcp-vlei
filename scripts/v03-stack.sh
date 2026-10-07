#!/usr/bin/env bash
#
# v03-stack.sh — the parallel v0.3 stack, beside the live one and never instead of it.
#
#   bash scripts/v03-stack.sh up         # witnesses, schema server, verifier, keri-cli (project mcp-vlei-v03p)
#   bash scripts/v03-stack.sh bootstrap  # the chain, the operator's LE and a forged chain, into .v03/credentials
#   bash scripts/v03-stack.sh gateway    # build and start the v0.3 gateway; delegate its signing AID
#   bash scripts/v03-stack.sh env        # `export …` lines a client needs to use this stack (eval them)
#   bash scripts/v03-stack.sh status
#   bash scripts/v03-stack.sh down       # stop both projects; volumes (keystores, replay store) are kept
#
# Its own project names (mcp-vlei-v03p, mcp-vlei-v03p-regulator), container names, host ports
# (+30000: witnesses 35642-35644, schema 37723, verifier 37676, gateway 33000, before 38090),
# network (mcp-vlei-v03p_default), keystores (a volume) and credentials (.v03/credentials,
# gitignored). The overlays are deploy/v03/parallel.{base,regulator}.yml.
#
# Nothing here reads scripts/.env, and the agent running it never prints or opens anything under
# .v03/credentials — the scripts write there, as they write credentials/ for the live stack.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) NROOT="$(cygpath -m "$ROOT")" ;;
  *)                    NROOT="$ROOT" ;;
esac

PROJECT=mcp-vlei-v03p
BASE="docker compose -p ${PROJECT} -f ${NROOT}/scripts/docker-compose.yml -f ${NROOT}/deploy/v03/parallel.base.yml"
REG="docker compose -p ${PROJECT}-regulator -f ${NROOT}/deploy/agentgateway/docker-compose.yml -f ${NROOT}/deploy/v03/parallel.regulator.yml"
CREDS="${NROOT}/.v03/credentials"
GATEWAY="http://localhost:33000"
AUDIENCE="${GATEWAY}/mcp,http://127.0.0.1:33000/mcp"

# What bootstrap-*.sh, the proxy and kli_signer read to address this stack instead of the live one.
export VLEI_CREDENTIALS_DIR="$CREDS"
export VLEI_BOOTSTRAP_COMPOSE="$BASE" VLEI_BOOTSTRAP_CREDENTIALS="$CREDS" VLEI_BOOTSTRAP_DOTENV=/dev/null
export VLEI_BOOTSTRAP_VERIFIER_URL=http://localhost:37676 VLEI_BOOTSTRAP_SCHEMA_URL=http://localhost:37723
export VLEI_WITNESS_URL=http://localhost:35642

say() { printf '\n==> %s\n' "$*"; }
roots() {
  python -c "import json,sys;print(','.join(json.load(open(sys.argv[1]))['acceptedRoots']))" \
    "${CREDS}/env.json"
}
wait_for() {  # $1 url, $2 what
  local i
  for i in $(seq 1 60); do
    curl -fsS -o /dev/null --max-time 3 "$1" 2>/dev/null && return 0
    sleep 2
  done
  echo "v03-stack: $2 did not answer at $1" >&2
  return 1
}

case "${1:-}" in
  up)
    mkdir -p "${ROOT}/.v03/credentials"
    say "parallel witnesses, schema server, verifier, keri-cli"
    $BASE up -d
    wait_for http://localhost:35642/oobi "the parallel witness"
    ;;
  bootstrap)
    say "credentials into .v03/credentials (parallel keri-cli)"
    DELEGATION_TRIES="${DELEGATION_TRIES:-20}" bash "${HERE}/bootstrap-credentials.sh"
    bash "${HERE}/bootstrap-regulator.sh"
    bash "${HERE}/bootstrap-forged.sh"
    ;;
  gateway)
    export VLEI_ACCEPTED_ROOTS="$(roots)"
    export VLEI_LE_CREDENTIAL_FILE="${CREDS}/regulator/le.cesr"
    export VLEI_AUDIENCE_URLS="$AUDIENCE"
    say "build the v0.3 gateway images"
    $REG build
    say "vlei-pop first, then its signing AID"
    $REG up -d --no-deps vlei-pop
    VLEI_BOOTSTRAP_POP_COMPOSE="$REG" DELEGATION_TRIES="${DELEGATION_TRIES:-20}" \
      bash "${HERE}/bootstrap-gateway-signer.sh"
    say "the rest of the gateway"
    $REG up -d
    wait_for "${GATEWAY}/.well-known/vlei" "the parallel gateway"
    ;;
  env)
    cat <<EOF
export VLEI_GATEWAY_URL=${GATEWAY}/mcp
export VLEI_PLAIN_URL=http://127.0.0.1:38090/mcp
export VLEI_CREDENTIALS_DIR='${CREDS}'
export VLEI_COMPOSE_CMD='${BASE}'
export VLEI_WITNESS_URL=http://localhost:35642
export VLEI_WITNESS_URLS=http://localhost:35642,http://localhost:35643,http://localhost:35644
export VLEI_ACCEPTED_ROOTS=$(roots)
export VLEI_BOOTSTRAP_COMPOSE='${BASE}'
export VLEI_BOOTSTRAP_CREDENTIALS='${CREDS}'
export VLEI_BOOTSTRAP_DOTENV=/dev/null
export VLEI_BOOTSTRAP_VERIFIER_URL=http://localhost:37676
export VLEI_BOOTSTRAP_SCHEMA_URL=http://localhost:37723
EOF
    ;;
  status)
    $BASE ps
    $REG ps
    curl -fsS --max-time 5 "${GATEWAY}/.well-known/vlei" \
      | python -c "import json,sys;d=json.load(sys.stdin);print('well-known:',d.get('signatureFormats'),d.get('pop'),d.get('ttlMs'))" \
      || echo "well-known: no answer"
    ;;
  down)
    $REG down
    $BASE down
    ;;
  *)
    echo "usage: bash scripts/v03-stack.sh up|bootstrap|gateway|env|status|down" >&2
    exit 2
    ;;
esac
