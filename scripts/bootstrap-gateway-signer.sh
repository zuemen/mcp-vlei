#!/usr/bin/env bash
#
# bootstrap-gateway-signer.sh — the gateway's signing AID, delegated by its operator's LE.
#
#   VLEI_BOOTSTRAP_COMPOSE="docker compose -p <base project> -f … [-f …]" \
#   VLEI_BOOTSTRAP_POP_COMPOSE="docker compose -p <regulator project> -f … [-f …]" \
#     bash scripts/bootstrap-gateway-signer.sh          # re-runnable: an existing AID is kept
#
# Both are required, and neither has a default. VLEI_BOOTSTRAP_COMPOSE names the keri-cli whose
# `regulator` keystore approves the delegation; bootstrap-credentials.sh, sourced below, would
# otherwise fall back to scripts/docker-compose.yml — the live project — so this script refuses to
# run without it. scripts/v03-stack.sh exports it for the parallel stack; the live switch
# (scripts/v03-switch.sh) must pass it explicitly too.
#
# vlei-pop proves that the gateway holds its operator's key by signing a client's challenge
# (mcp_vlei.pop). It signs as `gateway`: an AID in vlei-pop's own KERI keystore, whose delegated
# inception the operator's AID (`regulator`, in keri-cli — scripts/bootstrap-regulator.sh)
# approves. The operator's own LE key never sits in an online service, and the operator can stop
# the gateway's proofs without touching its LE.
#
# The approval appends one interaction event to the operator's key event log. No v0.2 check reads
# that log, so the event is harmless to a v0.2 stack — and it cannot be undone, which is why on the
# live stack this runs only inside the v0.3 switch (scripts/v03-switch.sh).
#
# Writes <credentials>/regulator/gateway.aid. The vlei-pop container must be running.
set -euo pipefail
# First, before anything is sourced or run: no compose command, no Docker call.
: "${VLEI_BOOTSTRAP_COMPOSE:?set VLEI_BOOTSTRAP_COMPOSE to the docker compose command of the stack whose regulator keystore approves the delegation}"
POP_COMPOSE="${VLEI_BOOTSTRAP_POP_COMPOSE:?set it to the docker compose command of the gateway project}"

GATEWAY_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bootstrap-credentials.sh
source "${GATEWAY_HERE}/bootstrap-credentials.sh" --library

kli_pop() { MSYS_NO_PATHCONV=1 $POP_COMPOSE exec -T vlei-pop kli "$@"; }
# Whether keystore $1 in vlei-pop is initialised — not whether its directory exists: any kli call
# naming a keystore that was never initialised (this script's own `kli_pop status`, vlei-pop's
# `kli aid` at runtime) leaves an empty ks/<name> behind before refusing with "Keystore must
# already exist".
# `kli list` refuses such a directory (exit 255) and accepts an initialised keystore, with or
# without AIDs; `kli init` completes the empty directory. Tested on keripy 1.2.14 (Task 22 report).
pop_keystore_initialised() { kli_pop list --name "$1" >/dev/null 2>&1; }

R=regulator
G=gateway

gateway_main() {
  step "Preflight"
  kli status --name "$R" --alias "$R" >/dev/null 2>&1 \
    || fail "no ${R} keystore in keri-cli: run scripts/bootstrap-regulator.sh first"
  local operator; operator="$(kli aid --name "$R" --alias "$R" | tr -d '\r\n')"
  ok "operator ${operator}"
  $POP_COMPOSE ps --status running --services 2>/dev/null | grep -qx vlei-pop \
    || fail "vlei-pop is not running: start it before this script"

  if kli_pop status --name "$G" --alias "$G" >/dev/null 2>&1; then
    note "${G} already exists in vlei-pop's keystore: kept"
  else
    step "The gateway AID's keystore, inside vlei-pop"
    # A first run stopped after `init` leaves an initialised keystore without the AID: keep it.
    if pop_keystore_initialised "$G"; then
      note "${G}'s keystore is already initialised in vlei-pop: kept, not initialised again"
    else
      kli_pop init --name "$G" --nopasscode \
        --config-dir /keri-config --config-file bootstrap-config >/dev/null \
        || fail "could not create the ${G} keystore inside vlei-pop"
    fi
    local w port aid
    for w in "${WITNESSES[@]}"; do
      port="${w%%:*}"; aid="${w##*:}"
      kli_pop oobi resolve --name "$G" --oobi-alias "wit${port}" \
        --oobi "http://witness-demo:${port}/oobi/${aid}/controller" >/dev/null
    done
    local operator_oobi
    operator_oobi="$(kli oobi generate --name "$R" --alias "$R" --role witness | head -1 | tr -d '\r\n')"
    [[ -n "$operator_oobi" ]] || fail "could not generate a witness OOBI for ${R}"
    kli_pop oobi resolve --name "$G" --oobi-alias "$R" --oobi "$operator_oobi" >/dev/null
    # A delegated AID cannot deliver its own request (bootstrap-credentials.sh, delegated_incept).
    # Kept if a stopped first run already made it, as delegated_incept does.
    if ! kli_pop status --name "$G" --alias "${G}-proxy" >/dev/null 2>&1; then
      kli_pop incept --name "$G" --alias "${G}-proxy" --file /keri-config/incept-witnesses.json >/dev/null \
        || fail "could not incept ${G}-proxy, which carries ${G}'s delegation request"
    fi

    step "Delegated inception of ${G} under ${R}: proposed in vlei-pop, approved in keri-cli"
    kli_pop incept --name "$G" --alias "$G" --file /keri-config/incept-witnesses.json \
      --delpre "$operator" --proxy "${G}-proxy" >/dev/null 2>&1 &
    local proposer=$!
    sleep 4
    local tries=0
    while kill -0 "$proposer" 2>/dev/null && [[ $tries -lt ${DELEGATION_TRIES:-10} ]]; do
      tries=$((tries+1))
      timeout 15 bash -c "$(declare -f kli); COMPOSE='$COMPOSE'; \
        kli delegate confirm --name $R --alias $R --interact --auto" >/dev/null 2>&1 || true
      sleep 2
    done
    if kill -0 "$proposer" 2>/dev/null; then
      kill "$proposer" 2>/dev/null || true
      fail "the delegated inception of ${G} did not complete after ${tries} approvals; raise DELEGATION_TRIES"
    fi
    wait "$proposer" || fail "the delegated inception of ${G} failed"
  fi

  local gateway_aid; gateway_aid="$(kli_pop aid --name "$G" --alias "$G" | tr -d '\r\n')"
  [[ -n "$gateway_aid" ]] || fail "vlei-pop's keystore holds no ${G} AID"
  mkdir -p "${OUT}/regulator"
  printf '%s\n' "$gateway_aid" > "${OUT}/regulator/gateway.aid"
  ok "${G} = ${gateway_aid}, delegated by ${R}"
}

gateway_main "$@"
