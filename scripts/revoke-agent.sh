#!/usr/bin/env bash
#
# revoke-agent.sh — withdraw one agent's delegation; the holder's ECR and every other agent stay.
#
#   bash scripts/revoke-agent.sh agent2       # by keystore name (as given to scripts/issue-agent.sh)
#   bash scripts/revoke-agent.sh E…           # or by AID
#
# Deck p9 "Cancel it any time", p13 "Cancel it when the role changes". The ECR holder anchors, in an
# interaction event of its own key event log,
#
#   {"i": <agent AID>, "d": <agent dip SAID>, "withdrawn": true}
#
# and check 7 (revocation) refuses the agent's next call as `revoked`, reading the holder's log
# from the witnesses (spec/SPEC.md "Withdrawing an agent's delegation"). A proposal: KERI has no
# standard for a delegator withdrawing a delegation on its own. The seal deliberately has no `s` —
# `{i, s, d}` is how the holder approves the agent's inception and rotations.
#
# IRREVERSIBLE. The event cannot be removed from the holder's log, and nothing restores the agent;
# re-authorising is a new AID (scripts/issue-agent.sh). The demo's own agent (`agent`, the AID in
# <credentials>/_work/agent.aid) is refused unless VLEI_REVOKE_DEMO_AGENT=yes.
set -euo pipefail

REVOKE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bootstrap-credentials.sh
source "${REVOKE_HERE}/bootstrap-credentials.sh" --library

TARGET="${1:-}"
case "$TARGET" in
  ""|-h|--help)
    echo "usage: bash scripts/revoke-agent.sh <keystore name | agent AID>" >&2
    exit 2 ;;
esac

revoke_main() {
  step "Preflight"
  $COMPOSE exec -T keri-cli true >/dev/null 2>&1 || fail "the keri-cli container is not running"
  [[ -s "${WORK}/ecr.aid" ]] || fail "${WORK}/ecr.aid not found: run scripts/bootstrap-credentials.sh first"
  local holder; holder="$(cat "${WORK}/ecr.aid")"

  local aid
  if [[ "$TARGET" =~ ^E[A-Za-z0-9_-]{43}$ ]]; then
    aid="$TARGET"
  else
    [[ "$TARGET" =~ ^[A-Za-z0-9_-]+$ ]] || fail "not a keystore name or an AID: ${TARGET}"
    aid="$(kli aid --name "$TARGET" --alias "$TARGET" 2>/dev/null | tr -d '\r\n')"
    [[ -n "$aid" ]] || fail "no keystore ${TARGET} with an AID of that alias"
  fi
  [[ "$aid" != "$holder" ]] || fail "${aid} is the ECR holder itself; revoke the ECR instead"

  local demo; demo="$(cat "${WORK}/agent.aid" 2>/dev/null | tr -d '\r\n' || true)"
  if [[ -n "$demo" && "$aid" == "$demo" && "${VLEI_REVOKE_DEMO_AGENT:-}" != "yes" ]]; then
    fail "${aid} is the demo agent (_work/agent.aid). Withdrawal is irreversible; set VLEI_REVOKE_DEMO_AGENT=yes to mean it."
  fi

  # Only an agent this holder delegated: the seal would otherwise sit in the holder's log for ever
  # and mean nothing.
  local kel; kel="$(curl -fsS "${WITNESS_URL}/query?typ=kel&pre=${holder}" 2>/dev/null || true)"
  [[ -n "$kel" ]] || fail "the holder's key event log could not be read from ${WITNESS_URL}"
  grep -q "\"i\":\"${aid}\",\"s\":\"0\"" <<<"$kel" \
    || fail "the holder ${holder} never approved ${aid}: it is not this holder's agent"
  if grep -q "\"i\":\"${aid}\",\"d\":\"${aid}\",\"withdrawn\":true" <<<"$kel"; then
    note "${aid} is already withdrawn; nothing to do"
    return 0
  fi
  ok "agent ${aid}, delegated by ${holder}"

  step "Anchoring the withdrawal in the holder's key event log"
  # For a self-addressing AID the dip SAID is the AID itself, so `d` repeats `i`.
  local seal="{\"i\":\"${aid}\",\"d\":\"${aid}\",\"withdrawn\":true}"
  kli interact --name ecr --alias ecr --data "$seal" >/dev/null

  local tries=0
  until curl -fsS "${WITNESS_URL}/query?typ=kel&pre=${holder}" 2>/dev/null \
        | grep -q "\"i\":\"${aid}\",\"d\":\"${aid}\",\"withdrawn\":true"; do
    tries=$((tries+1)); [[ $tries -gt 15 ]] && fail "the witness at ${WITNESS_URL} does not show the withdrawal"
    sleep 2
  done
  ok "withdrawn: ${seal}"
  note "the agent's next call is refused at check 7 (revocation) as 'revoked'; the ECR is untouched"
}

revoke_main
