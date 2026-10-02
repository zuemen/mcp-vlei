#!/usr/bin/env bash
#
# bootstrap-forged.sh — a second, self-made credential chain that the gateway was never told to trust.
#
#   bash scripts/bootstrap-forged.sh           # create it (re-runnable: existing keystores are reused)
#   bash scripts/bootstrap-forged.sh --check   # present it to the gateway; expect unknown_root
#
# It is as real as the main chain. KERI inception happens on the same witnesses, with a QVI
# delegated from its root, ACDC issuance under the published vLEI schemas, an ECR with the same
# role (labor-insurance-filing), and an agent AID delegated by the ECR holder.
#
# Exactly one thing differs: this root is not in the gateway's acceptedRoots. So the signature
# verifies, the delegation verifies, and every issuance is anchored in its issuer's key event log.
# Check 6, chain, still refuses with unknown_root.
#
# That is the attack it shows. Anyone can run keripy and issue credentials that look exactly like
# vLEI credentials. What they cannot do is end the chain at a root the verifier accepts.
#
# Every identity here is fictional:
#   - legal entity: 某大型半導體公司（虛構）/ Large Semiconductor Corp. (fictional)
#   - LEI: 984500LARGESEMI00061 (valid ISO 17442 check digits, not in GLEIF's index)
#   - handler: Zhang San (fictional)
# The LE credential carries only the LEI; the name is recorded in env.json.
#
# Writes credentials/forged/{le.cesr,ecr.cesr,env.json} and keystores named forged-*. It never
# touches credentials/env.json, the main chain's keystores, or the verifier's root of trust.
#
set -euo pipefail

FORGED_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The main bootstrap's functions — kli, issue, delegated_incept, introduce, rules_for — without
# running it. The argument keeps its top-level `--down` branch from seeing this script's arguments.
# shellcheck source=bootstrap-credentials.sh
source "${FORGED_HERE}/bootstrap-credentials.sh" --library

# Where the main chain's acceptedRoots are read from, before OUT is pointed elsewhere.
MAIN_ENV="${OUT}/env.json"

OUT="${ROOT_DIR}/credentials/forged"
WORK="${OUT}/_work"
CWORK="/credentials/forged/_work"   # the same directory, as the keri-cli container sees it

LE_NAME="${FORGED_LE_NAME:-Large Semiconductor Corp. (fictional)}"
LE_NAME_ZH="${FORGED_LE_NAME_ZH:-某大型半導體公司（虛構）}"
LE_LEI="${FORGED_LE_LEI:-984500LARGESEMI00061}"
ECR_PERSON="${FORGED_ECR_PERSON:-Zhang San (fictional)}"
ECR_ROLE="labor-insurance-filing"   # the same role as the real one: that is the point

F=forged
PARTIES=("${F}-root" "${F}-qvi" "${F}-le" "${F}-ecr")

preflight() {
  step "Preflight — the main environment must be up; this chain is added beside it"
  [[ -f "$MAIN_ENV" ]] || fail "${MAIN_ENV} not found: run scripts/bootstrap-credentials.sh first"
  curl -fsS "${WITNESS_URL}/oobi" >/dev/null 2>&1 \
    || fail "no witness on ${WITNESS_URL}: start the stack (scripts/reset-demo.sh) first"
  $COMPOSE exec -T keri-cli true >/dev/null 2>&1 || fail "the keri-cli container is not running"
  mkdir -p "$WORK"
  ok "witnesses up, keri-cli running, main chain present"
}

forged_parties() {
  step "Stage 2 — creating the forged controllers: ${PARTIES[*]}"
  local p
  for p in "${PARTIES[@]}"; do
    if kli status --name "$p" --alias "$p" >/dev/null 2>&1; then
      note "$p already exists, skipping inception"
    elif [[ "$p" == "${F}-qvi" ]]; then
      # Delegated from its root, as a real QVI is: the forgery is complete in every structural
      # respect, so the only thing left to refuse it on is the root.
      delegated_incept "$p" "${F}-root" || fail "delegated inception of ${p} failed.
      Raise DELEGATION_TRIES and re-run."
    else
      kli init --name "$p" --nopasscode \
        --config-dir /keri-config --config-file bootstrap-config >/dev/null
      resolve_witnesses "$p"
      kli incept --name "$p" --alias "$p" --file /keri-config/incept-witnesses.json >/dev/null
    fi
    local aid; aid="$(kli aid --name "$p" --alias "$p" | tr -d '\r\n')"
    printf '%s\n' "$aid" > "${WORK}/${p}.aid"
    ok "$p = $aid"
  done
}

forged_agent() {
  step "Stage 2b — the forged agent's AID, delegated by the forged ECR holder"
  local agent="${F}-agent"
  if kli status --name "$agent" --alias "$agent" >/dev/null 2>&1; then
    note "$agent already exists"
  elif ! delegated_incept "$agent" "${F}-ecr"; then
    # As in the main chain, not fatal: the holder's own AID signs, and the refusal is the same.
    note "the forged ECR holder's AID will sign directly"
    printf '%s\n' "" > "${WORK}/${agent}.aid"
    return 0
  fi
  kli aid --name "$agent" --alias "$agent" 2>/dev/null | tr -d '\r\n' > "${WORK}/${agent}.aid"
  ok "$agent (delegated) = $(cat "${WORK}/${agent}.aid")"
}

forged_registries() {
  step "Stage 4 — credential registries"
  local p
  for p in "${F}-root" "${F}-qvi" "${F}-le"; do
    if ! kli vc registry status --name "$p" --registry-name "${p}Registry" >/dev/null 2>&1; then
      kli vc registry incept --name "$p" --alias "$p" --registry-name "${p}Registry" >/dev/null
    fi
    ok "${p}Registry"
  done
}

forged_chain() {
  step "Stage 4b — issuing QVI -> LE (${LE_NAME}) -> ECR (${ECR_ROLE})"
  # Kept only while the holder still has it: after a full reset the keystores are new, and a SAID
  # left in _work would name a credential nobody holds.
  local held; held="$(cat "${WORK}/ecr.said" 2>/dev/null || true)"
  if [[ -n "$held" ]] && kli vc list --name "${F}-ecr" --alias "${F}-ecr" --said 2>/dev/null \
       | tr -d '\r' | grep -qxF "$held"; then
    note "already issued and held: ECR ${held} (delete ${WORK}/ecr.said to issue again)"
    return 0
  fi
  printf '{ "LEI": "%s" }\n' "$LE_LEI" > "${WORK}/qvi-data.json"
  printf '{ "LEI": "%s" }\n' "$LE_LEI" > "${WORK}/le-data.json"
  cat > "${WORK}/ecr-data.json" <<EOF
{
  "LEI": "${LE_LEI}",
  "personLegalName": "${ECR_PERSON}",
  "engagementContextRole": "${ECR_ROLE}"
}
EOF
  rules_for "$SCHEMA_QVI" "${WORK}/rules.json"
  rules_for "$SCHEMA_ECR" "${WORK}/ecr-rules.json"

  local qvi_said le_said ecr_said
  qvi_said="$(issue "${F}-root" "$(cat "${WORK}/${F}-qvi.aid")" "${F}-qvi" "$SCHEMA_QVI" \
              "${CWORK}/qvi-data.json" "" "${CWORK}/rules.json")"
  ok "QVI credential  $qvi_said"

  printf '{ "d": "", "qvi": { "n": "%s", "s": "%s" } }\n' "$qvi_said" "$SCHEMA_QVI" \
    > "${WORK}/le-edges.json"
  le_said="$(issue "${F}-qvi" "$(cat "${WORK}/${F}-le.aid")" "${F}-le" "$SCHEMA_LE" \
             "${CWORK}/le-data.json" "${CWORK}/le-edges.json" "${CWORK}/rules.json")"
  ok "LE credential   $le_said  (${LE_NAME}, LEI ${LE_LEI})"

  printf '{ "d": "", "le": { "n": "%s", "s": "%s" } }\n' "$le_said" "$SCHEMA_LE" \
    > "${WORK}/ecr-edges.json"
  ecr_said="$(issue "${F}-le" "$(cat "${WORK}/${F}-ecr.aid")" "${F}-ecr" "$SCHEMA_ECR" \
              "${CWORK}/ecr-data.json" "${CWORK}/ecr-edges.json" "${CWORK}/ecr-rules.json" private)"
  ok "ECR credential  $ecr_said  (role=${ECR_ROLE}, ${ECR_PERSON})"

  printf '%s' "$qvi_said" > "${WORK}/qvi.said"
  printf '%s' "$le_said"  > "${WORK}/le.said"
  printf '%s' "$ecr_said" > "${WORK}/ecr.said"
}

forged_export() {
  step "Stage 5 — exporting to credentials/forged/"
  local root; root="$(cat "${WORK}/${F}-root.aid")"
  # The whole demonstration rests on this: were the forged root ever accepted, the refusal would
  # prove nothing. Checked against the main chain's acceptedRoots, which the gateway is given.
  if python -c 'import json,sys; sys.exit(sys.argv[2] in json.load(open(sys.argv[1]))["acceptedRoots"])' \
       "$(cygpath -m "$MAIN_ENV" 2>/dev/null || echo "$MAIN_ENV")" "$root"; then
    ok "forged root ${root} is not an accepted root"
  else
    fail "the forged root ${root} is in ${MAIN_ENV} acceptedRoots — refusing to continue"
  fi

  kli vc export --name "${F}-le"  --alias "${F}-le"  --said "$(cat "${WORK}/le.said")"  --full \
    > "${OUT}/le.cesr"
  kli vc export --name "${F}-ecr" --alias "${F}-ecr" --said "$(cat "${WORK}/ecr.said")" --full \
    > "${OUT}/ecr.cesr"
  local agent; agent="$(cat "${WORK}/${F}-agent.aid" 2>/dev/null || true)"
  cat > "${OUT}/env.json" <<EOF
{
  "profile":       "forged",
  "rootAid":       "${root}",
  "qviAid":        "$(cat "${WORK}/${F}-qvi.aid")",
  "leAid":         "$(cat "${WORK}/${F}-le.aid")",
  "ecrAid":        "$(cat "${WORK}/${F}-ecr.aid")",
  "agentAid":      "${agent}",
  "agentKeystore": "$([[ -n "$agent" ]] && echo "${F}-agent" || echo "${F}-ecr")",
  "leSaid":        "$(cat "${WORK}/le.said")",
  "ecrSaid":       "$(cat "${WORK}/ecr.said")",
  "lei":           "${LE_LEI}",
  "leName":        "${LE_NAME}",
  "leNameZh":      "${LE_NAME_ZH}",
  "person":        "${ECR_PERSON}",
  "role":          "${ECR_ROLE}",
  "fictional":     "All identities are fictional. The root of trust is self-hosted for demonstration.",
  "acceptedRoots": [],
  "expected":      "unknown_root",
  "rootOfTrust":   "a second self-made root, deliberately absent from the gateway's acceptedRoots"
}
EOF
  ok "credentials/forged/le.cesr, credentials/forged/ecr.cesr, credentials/forged/env.json"
}

# Present the forged ECR to the running gateway, signed in the keri-cli keystore exactly as the
# real agent signs. Exit 0 only if the gateway refuses with unknown_root.
forged_check() {
  step "Check — enroll_employee through the gateway with the forged chain"
  local native_root; native_root="$(cygpath -m "$ROOT_DIR" 2>/dev/null || echo "$ROOT_DIR")"
  VLEI_POLICY_UTC_OFFSET="${VLEI_POLICY_UTC_OFFSET:-+08:00}" python - "$native_root" <<'PY'
import asyncio, json, sys
from pathlib import Path

root = Path(sys.argv[1])
for sub in ("packages/mcp-vlei/src", "examples/regulator", "examples/my-agent"):
    sys.path.insert(0, str(root / sub))
import gateway_client
from kli_signer import keystore_signer

env = json.loads((root / "credentials/forged/env.json").read_text(encoding="utf-8"))
keystore = env["agentKeystore"]
arguments = gateway_client.demo_arguments()
meta = gateway_client.signed_meta(
    credential=(root / "credentials/forged/ecr.cesr").read_text(encoding="utf-8").strip(),
    signer=keystore_signer(keystore, keystore), tool="enroll_employee", arguments=arguments,
    delegated_aid=env["agentAid"] or None, credential_said=env["ecrSaid"],
)
out = asyncio.run(gateway_client.call_through_gateway(
    gateway_client.DEFAULT_URL, "enroll_employee", arguments, meta))
checks = [(c["name"], c["passed"]) for c in (out.get("report") or {}).get("checks", [])]
print("  layer:", out["layer"])
print("  text: ", (out["text"] or "")[:200])
print("  checks:", ", ".join(f"{n}={'pass' if p else 'FAIL' if p is False else '-'}" for n, p in checks))
sys.exit(0 if out["allowed"] is False and out["layer"] == "unknown_root" else 1)
PY
  ok "refused at the root: unknown_root"
}

forged_main() {
  if [[ "${1:-}" == "--check" ]]; then
    forged_check
    return
  fi
  preflight
  forged_parties
  forged_agent
  PARTIES=("${F}-root" "${F}-qvi" "${F}-le" "${F}-ecr")
  introduce
  forged_registries
  forged_chain
  forged_export
  step "Done"
  note "Chain:  forged root -> QVI -> LE (${LE_NAME}) -> ECR (${ECR_ROLE}) -> delegated agent"
  note "Real KERI, real ACDC — and a root the gateway does not accept. Next:"
  note "  bash scripts/bootstrap-forged.sh --check     # expect unknown_root"
}

forged_main "$@"
