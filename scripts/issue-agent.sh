#!/usr/bin/env bash
#
# issue-agent.sh — one more agent, with a key of its own, delegated by the ECR holder.
#
#   bash scripts/issue-agent.sh agent2        # keystore and alias "agent2"; re-runnable: kept if it exists
#
# The handler's one step (deck p13: "issue the agent its own key"): a new AID in its own keystore,
# incepted as a delegated identifier (`dip`) whose inception the ECR holder's key event log
# approves (`kli delegate confirm --interact` anchors `{i: agent, s: "0", d: dip SAID}`). Nothing
# is issued to the agent — it presents the holder's ECR and signs with its own key, exactly like
# the `agent` the bootstrap creates (spec/SPEC.md "Delegation").
#
# The pair of this script is scripts/revoke-agent.sh, which withdraws one agent's delegation without
# touching the ECR. A withdrawn agent cannot be restored: authorising again means running this
# script for a new name, which is a new AID.
#
# The approval appends one interaction event to the ECR holder's key event log. It cannot be undone.
# On a stack recorded for a demo, that changes the holder's event count the console shows; use the
# parallel stack (VLEI_BOOTSTRAP_COMPOSE — scripts/v03-stack.sh env) when that matters.
#
# Writes <credentials>/_work/<name>.aid. The keri-cli container and the witnesses must be running,
# and the main chain bootstrapped (<credentials>/_work/ecr.aid).
set -euo pipefail

ISSUE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The main bootstrap's functions — kli, delegated_incept, resolve_witnesses — without running it.
# shellcheck source=bootstrap-credentials.sh
source "${ISSUE_HERE}/bootstrap-credentials.sh" --library

NAME="${1:-}"
case "$NAME" in
  ""|-h|--help)
    echo "usage: bash scripts/issue-agent.sh <name>   (a new keystore and alias, e.g. agent2)" >&2
    exit 2 ;;
esac
[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || fail "name must be letters, digits, '-' or '_': ${NAME}"
case "$NAME" in
  root|qvi|le|ecr|regulator|gateway|forged-*|*-proxy)
    fail "${NAME} is a keystore the chain itself uses; choose another name" ;;
esac

issue_main() {
  step "Preflight"
  $COMPOSE exec -T keri-cli true >/dev/null 2>&1 || fail "the keri-cli container is not running"
  curl -fsS "${WITNESS_URL}/oobi" >/dev/null 2>&1 \
    || fail "no witness on ${WITNESS_URL}: start the stack first"
  [[ -s "${WORK}/ecr.aid" ]] || fail "${WORK}/ecr.aid not found: run scripts/bootstrap-credentials.sh first"
  local holder; holder="$(cat "${WORK}/ecr.aid")"
  ok "ECR holder ${holder}"

  if kli status --name "$NAME" --alias "$NAME" >/dev/null 2>&1; then
    note "${NAME} already exists: kept (a withdrawn agent stays withdrawn — pick a new name to re-authorise)"
  else
    step "Delegated inception of ${NAME} under the ECR holder"
    delegated_incept "$NAME" ecr \
      || fail "the delegation of ${NAME} did not complete. Raise DELEGATION_TRIES and re-run."
  fi

  local aid; aid="$(kli aid --name "$NAME" --alias "$NAME" | tr -d '\r\n')"
  [[ -n "$aid" ]] || fail "no AID for ${NAME}"

  # The approval must be on the witnesses, where a verifier reads it — not only in the keystore.
  local kel; kel="$(curl -fsS "${WITNESS_URL}/query?typ=kel&pre=${holder}" 2>/dev/null || true)"
  grep -q "\"i\":\"${aid}\",\"s\":\"0\"" <<<"$kel" \
    || fail "the witness at ${WITNESS_URL} does not show the holder approving ${aid}"
  printf '%s\n' "$aid" > "${WORK}/${NAME}.aid"
  ok "${NAME} (delegated by ${holder}) = ${aid}"
  note "sign as it with examples/my-agent/kli_signer.py: keystore_signer('${NAME}', '${NAME}')"
  note "withdraw it with: bash scripts/revoke-agent.sh ${NAME}"
}

issue_main
