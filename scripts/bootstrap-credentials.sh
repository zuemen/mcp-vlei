#!/usr/bin/env bash
#
# bootstrap-credentials.sh — one command to stand up the mcp-vlei credential environment.
#
#   bash scripts/bootstrap-credentials.sh            # full run
#   bash scripts/bootstrap-credentials.sh --down     # tear everything down
#   bash scripts/bootstrap-credentials.sh --verify   # re-run acceptance checks only
#
# What is real and what is not:
#   REAL  — KERI inception and key events, witness receipts, ACDC issuance, chained edges,
#           TEL-based revocation, and verification by GLEIF-IT/vlei-verifier.
#   OURS  — the root of trust. In production the chain terminates at GLEIF's root; here it
#           terminates at an AID this script creates, installed into the verifier through its
#           documented POST /root_of_trust/{aid} endpoint.
#
# Chain:  self-configured root  ->  QVI  ->  LE  ->  ECR  ->  delegated agent AID
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${HERE}/.." && pwd)"

# Git Bash on Windows rewrites anything that looks like a POSIX path before handing it to a native
# binary. Docker needs a native path for -f, and the container paths passed to `kli` must be left
# alone entirely — hence the mixed-form path here and MSYS_NO_PATHCONV inside the kli helper.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) NATIVE_HERE="$(cygpath -m "$HERE")" ;;
  *)                    NATIVE_HERE="$HERE" ;;
esac
COMPOSE="docker compose -f ${NATIVE_HERE}/docker-compose.yml"
OUT="${ROOT_DIR}/credentials"
WORK="${OUT}/_work"

VERIFIER="http://localhost:7676"

# Published WebOfTrust/vLEI ACDC schema SAIDs, served by the vlei-server container.
# Override from the environment if you are pinning a different schema release.
SCHEMA_QVI="${SCHEMA_QVI:-EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao}"
SCHEMA_LE="${SCHEMA_LE:-ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VPxROE}"
SCHEMA_ECR="${SCHEMA_ECR:-EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw}"

# The legal entity this demo issues for. LEI is a test value: the association does not hold a
# real LEI, and every artifact says so.
LE_NAME="${LE_NAME:-Taiwan Blockchain Enthusiasts Association}"
LE_LEI="${LE_LEI:-984500ABCDEF12345678}"
ECR_ROLE="${ECR_ROLE:-regulatory-filing}"
ECR_PERSON="${ECR_PERSON:-Chen Wei-Ting}"

# Keystore names. Each is an independent controller with its own keystore, as separate parties
# would be in reality.
PARTIES=(root qvi le ecr)

c_reset=$'\033[0m'; c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_hi=$'\033[36m'; c_dim=$'\033[90m'
step()  { printf '\n%s==> %s%s\n' "$c_hi" "$*" "$c_reset"; }
ok()    { printf '%s  ok%s  %s\n' "$c_ok" "$c_reset" "$*"; }
fail()  { printf '%s fail%s %s\n' "$c_bad" "$c_reset" "$*"; exit 1; }
note()  { printf '%s      %s%s\n' "$c_dim" "$*" "$c_reset"; }

kli() { MSYS_NO_PATHCONV=1 $COMPOSE exec -T keri-cli kli "$@"; }

# ---------------------------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------------------------
if [[ "${1:-}" == "--down" ]]; then
  step "Tearing down"
  $COMPOSE down -v
  ok "containers and volumes removed"
  note "credentials/ left in place; remove it by hand if you want a clean slate"
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Stage 1 — bring up witnesses, schema server and verifier
# ---------------------------------------------------------------------------------------------
bring_up() {
  step "Stage 1 — starting witness network, schema server and verifier"
  mkdir -p "$WORK"
  $COMPOSE up -d

  local tries=0
  until curl -fsS "http://localhost:5642/oobi" >/dev/null 2>&1; do
    tries=$((tries+1)); [[ $tries -gt 40 ]] && fail "witness network did not come up on :5642"
    sleep 2
  done
  ok "witnesses wan/wil/wes up on 5642-5644"

  tries=0
  until curl -fsS "http://localhost:7723/oobi/${SCHEMA_QVI}" >/dev/null 2>&1; do
    tries=$((tries+1)); [[ $tries -gt 40 ]] && fail "vLEI schema server did not come up on :7723"
    sleep 2
  done
  ok "vLEI schema server up on 7723"

  tries=0
  until curl -fsS -o /dev/null "${VERIFIER}/health" 2>/dev/null \
     || curl -fsS -o /dev/null "${VERIFIER}/" 2>/dev/null; do
    tries=$((tries+1)); [[ $tries -gt 40 ]] && fail "vlei-verifier did not come up on :7676"
    sleep 2
  done
  ok "vlei-verifier up on 7676"
}

# ---------------------------------------------------------------------------------------------
# Stage 2 — create the four controllers
# ---------------------------------------------------------------------------------------------
make_parties() {
  step "Stage 2 — creating controllers: ${PARTIES[*]}"
  for p in "${PARTIES[@]}"; do
    if kli status --name "$p" --alias "$p" >/dev/null 2>&1; then
      note "$p already exists, skipping inception"
    else
      kli init --name "$p" --nopasscode \
        --config-dir /keri-config --config-file bootstrap-config >/dev/null
      kli incept --name "$p" --alias "$p" --file /keri-config/incept-witnesses.json >/dev/null
    fi
    local aid; aid="$(kli aid --name "$p" --alias "$p" | tr -d '\r\n')"
    printf '%s\n' "$aid" > "${WORK}/${p}.aid"
    ok "$p = $aid"
  done
}

# The agent's delegated AID, created under the ECR holder's KEL. Revoking the delegation stops the
# agent without touching the person's credential. Optional by design — see SPEC.md "Why a
# delegated AID for the agent"; if this stage is dropped, the ECR holder's AID signs directly.
make_delegate() {
  step "Stage 2b — creating the agent's delegated AID under the ECR holder's KEL"
  if kli status --name agent --alias agent >/dev/null 2>&1; then
    note "agent delegated AID already exists"
  else
    kli init --name agent --nopasscode \
      --config-dir /keri-config --config-file bootstrap-config >/dev/null
    local ecr_aid; ecr_aid="$(cat "${WORK}/ecr.aid")"

    # Delegated inception is a two-sided operation: the delegate proposes, the delegator confirms.
    kli incept --name agent --alias agent \
      --file /keri-config/incept-witnesses.json --delpre "$ecr_aid" >/dev/null 2>&1 &
    local proposer=$!
    sleep 3
    kli delegate confirm --name ecr --alias ecr --interact --auto >/dev/null 2>&1 || true
    wait $proposer || fail "delegated inception did not complete"
  fi
  local aid; aid="$(kli aid --name agent --alias agent | tr -d '\r\n')"
  printf '%s\n' "$aid" > "${WORK}/agent.aid"
  ok "agent (delegated) = $aid"
}

# ---------------------------------------------------------------------------------------------
# Stage 3 — mutual OOBI resolution
# ---------------------------------------------------------------------------------------------
introduce() {
  step "Stage 3 — resolving OOBIs between parties"
  for p in "${PARTIES[@]}"; do
    kli oobi generate --name "$p" --alias "$p" --role witness | head -1 | tr -d '\r\n' \
      > "${WORK}/${p}.oobi"
  done
  for a in "${PARTIES[@]}"; do
    for b in "${PARTIES[@]}"; do
      [[ "$a" == "$b" ]] && continue
      kli oobi resolve --name "$a" --oobi-alias "$b" --oobi "$(cat "${WORK}/${b}.oobi")" >/dev/null
    done
  done
  ok "all parties can resolve each other"
}

# ---------------------------------------------------------------------------------------------
# Stage 4 — credential registries and issuance
# ---------------------------------------------------------------------------------------------
registries() {
  step "Stage 4 — creating credential registries"
  for p in root qvi le; do
    if kli vc registry status --name "$p" --registry-name "${p}Registry" >/dev/null 2>&1; then
      note "${p}Registry already exists"
    else
      kli vc registry incept --name "$p" --alias "$p" --registry-name "${p}Registry" >/dev/null
    fi
    ok "${p}Registry"
  done
}

write_data() {
  local root_aid qvi_aid le_aid ecr_aid
  root_aid="$(cat "${WORK}/root.aid")"; qvi_aid="$(cat "${WORK}/qvi.aid")"
  le_aid="$(cat "${WORK}/le.aid")";     ecr_aid="$(cat "${WORK}/ecr.aid")"

  cat > "${WORK}/qvi-data.json" <<EOF
{ "LEI": "${LE_LEI}" }
EOF

  cat > "${WORK}/le-data.json" <<EOF
{ "LEI": "${LE_LEI}" }
EOF

  cat > "${WORK}/ecr-data.json" <<EOF
{
  "LEI": "${LE_LEI}",
  "personLegalName": "${ECR_PERSON}",
  "engagementContextRole": "${ECR_ROLE}"
}
EOF

  # The usage disclaimers carried by every vLEI credential.
  cat > "${WORK}/rules.json" <<'EOF'
{
  "d": "",
  "usageDisclaimer": {
    "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
  },
  "issuanceDisclaimer": {
    "l": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
  }
}
EOF
}

# Issue one credential and have the recipient admit it. Returns the credential SAID on stdout.
issue() {
  local issuer="$1" recipient_aid="$2" recipient="$3" schema="$4" data="$5" edges="${6:-}"
  local args=(vc create --name "$issuer" --alias "$issuer"
              --registry-name "${issuer}Registry"
              --schema "$schema" --recipient "$recipient_aid"
              --data "@${data}" --rules "@/credentials/_work/rules.json")
  [[ -n "$edges" ]] && args+=(--edges "@${edges}")
  kli "${args[@]}" >/dev/null

  local said
  said="$(kli vc list --name "$issuer" --alias "$issuer" --issued --said | tail -1 | tr -d '\r\n')"

  # IPEX grant / admit: the issuer offers, the recipient accepts into its own store.
  kli ipex grant --name "$issuer" --alias "$issuer" --said "$said" \
      --recipient "$recipient_aid" >/dev/null
  sleep 2
  local msg
  msg="$(kli ipex list --name "$recipient" --alias "$recipient" --poll --said | tail -1 | tr -d '\r\n')"
  kli ipex admit --name "$recipient" --alias "$recipient" --said "$msg" >/dev/null
  sleep 2
  printf '%s' "$said"
}

issue_chain() {
  step "Stage 4b — issuing the credential chain"
  write_data

  local root_aid qvi_aid le_aid ecr_aid
  root_aid="$(cat "${WORK}/root.aid")"; qvi_aid="$(cat "${WORK}/qvi.aid")"
  le_aid="$(cat "${WORK}/le.aid")";     ecr_aid="$(cat "${WORK}/ecr.aid")"

  # root -> QVI
  QVI_SAID="$(issue root "$qvi_aid" qvi "$SCHEMA_QVI" /credentials/_work/qvi-data.json)"
  ok "QVI credential  $QVI_SAID  (root -> qvi)"

  # QVI -> LE, with an edge back to the QVI credential
  cat > "${WORK}/le-edges.json" <<EOF
{ "d": "", "qvi": { "n": "${QVI_SAID}", "s": "${SCHEMA_QVI}" } }
EOF
  LE_SAID="$(issue qvi "$le_aid" le "$SCHEMA_LE" \
             /credentials/_work/le-data.json /credentials/_work/le-edges.json)"
  ok "LE credential   $LE_SAID  (qvi -> le, ${LE_NAME})"

  # LE -> ECR, with an edge back to the LE credential
  cat > "${WORK}/ecr-edges.json" <<EOF
{ "d": "", "le": { "n": "${LE_SAID}", "s": "${SCHEMA_LE}" } }
EOF
  ECR_SAID="$(issue le "$ecr_aid" ecr "$SCHEMA_ECR" \
              /credentials/_work/ecr-data.json /credentials/_work/ecr-edges.json)"
  ok "ECR credential  $ECR_SAID  (le -> ecr, role=${ECR_ROLE})"

  printf '%s' "$QVI_SAID" > "${WORK}/qvi.said"
  printf '%s' "$LE_SAID"  > "${WORK}/le.said"
  printf '%s' "$ECR_SAID" > "${WORK}/ecr.said"
}

# ---------------------------------------------------------------------------------------------
# Stage 5 — export CESR for the packages to consume
# ---------------------------------------------------------------------------------------------
export_creds() {
  step "Stage 5 — exporting CESR credentials to credentials/"
  kli vc export --name le  --alias le  --said "$(cat "${WORK}/le.said")"  --chain \
    > "${OUT}/le.cesr"
  kli vc export --name ecr --alias ecr --said "$(cat "${WORK}/ecr.said")" --chain \
    > "${OUT}/ecr.cesr"

  cat > "${OUT}/env.json" <<EOF
{
  "rootAid":     "$(cat "${WORK}/root.aid")",
  "qviAid":      "$(cat "${WORK}/qvi.aid")",
  "leAid":       "$(cat "${WORK}/le.aid")",
  "ecrAid":      "$(cat "${WORK}/ecr.aid")",
  "agentAid":    "$(cat "${WORK}/agent.aid" 2>/dev/null || echo "")",
  "leSaid":      "$(cat "${WORK}/le.said")",
  "ecrSaid":     "$(cat "${WORK}/ecr.said")",
  "lei":         "${LE_LEI}",
  "role":        "${ECR_ROLE}",
  "verifierUrl": "${VERIFIER}",
  "acceptedRoots": ["$(cat "${WORK}/root.aid")"],
  "rootOfTrust": "self-configured; in production this would be GLEIF's root"
}
EOF
  ok "credentials/le.cesr, credentials/ecr.cesr, credentials/env.json"
}

# ---------------------------------------------------------------------------------------------
# Stage 6 — install our root of trust into the verifier
# ---------------------------------------------------------------------------------------------
install_root() {
  step "Stage 6 — installing the self-configured root of trust into vlei-verifier"
  local root_aid; root_aid="$(cat "${WORK}/root.aid")"
  local oobi;     oobi="$(cat "${WORK}/root.oobi")"

  local code
  code="$(curl -sS -o "${WORK}/root_of_trust.out" -w '%{http_code}' \
    -X POST "${VERIFIER}/root_of_trust/${root_aid}" \
    -H 'Content-Type: application/json' \
    -d "{\"vlei\": \"$(sed 's/"/\\"/g' "${OUT}/le.cesr" | tr -d '\n')\", \"oobi\": \"${oobi}\"}")"

  case "$code" in
    200|201|202) ok "root of trust installed: ${root_aid} (HTTP ${code})" ;;
    *) fail "verifier rejected the root of trust (HTTP ${code}): $(cat "${WORK}/root_of_trust.out")" ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Acceptance checks — these are the deliverable, not decoration
# ---------------------------------------------------------------------------------------------
present() {
  local said="$1" file="$2"
  # GLEIF-IT/vlei-verifier accepts a presentation as CESR at /presentations/{said}. Released
  # versions have used both PUT and POST; try PUT first and fall back.
  local code
  code="$(curl -sS -o "${WORK}/present.out" -w '%{http_code}' \
    -X PUT "${VERIFIER}/presentations/${said}" \
    -H 'Content-Type: application/json+cesr' --data-binary "@${file}")"
  if [[ "$code" == "404" || "$code" == "405" ]]; then
    code="$(curl -sS -o "${WORK}/present.out" -w '%{http_code}' \
      -X POST "${VERIFIER}/presentations/${said}" \
      -H 'Content-Type: application/json+cesr' --data-binary "@${file}")"
  fi
  printf '%s' "$code"
}

authorized() {
  local aid="$1"
  curl -sS -o "${WORK}/authz.out" -w '%{http_code}' "${VERIFIER}/authorizations/${aid}"
}

verify_all() {
  local ecr_said ecr_aid
  ecr_said="$(cat "${WORK}/ecr.said")"; ecr_aid="$(cat "${WORK}/ecr.aid")"

  step "Check 3 — presenting the ECR credential"
  local code; code="$(present "$ecr_said" "${OUT}/ecr.cesr")"
  [[ "$code" == "202" || "$code" == "200" ]] \
    && ok "presentation accepted (HTTP ${code})" \
    || fail "presentation rejected (HTTP ${code}): $(cat "${WORK}/present.out")"

  step "Check 4 — the holder is authorized"
  sleep 2
  code="$(authorized "$ecr_aid")"
  [[ "$code" == "200" ]] \
    && ok "authorized (HTTP 200): $(cat "${WORK}/authz.out")" \
    || fail "expected 200, got ${code}: $(cat "${WORK}/authz.out")"

  step "Check 5 — revoking the ECR credential"
  kli vc revoke --name le --alias le --registry-name leRegistry --said "$ecr_said" \
      --send "$ecr_aid" >/dev/null
  sleep 3
  ok "revoked in the LE's TEL"

  step "Check 6 — the holder is no longer authorized"
  present "$ecr_said" "${OUT}/ecr.cesr" >/dev/null || true
  sleep 2
  code="$(authorized "$ecr_aid")"
  if [[ "$code" == "200" ]] && grep -qi '"\?revoked"\?' "${WORK}/authz.out"; then
    ok "reported revoked: $(cat "${WORK}/authz.out")"
  elif [[ "$code" != "200" ]]; then
    ok "no longer authorized (HTTP ${code})"
  else
    fail "still authorized after revocation — this check must fail loudly: $(cat "${WORK}/authz.out")"
  fi
}

# ---------------------------------------------------------------------------------------------
main() {
  if [[ "${1:-}" == "--verify" ]]; then
    verify_all
  else
    bring_up
    make_parties
    make_delegate
    introduce
    registries
    issue_chain
    export_creds
    install_root
    verify_all
  fi

  step "Done"
  note "Chain:  root -> QVI -> LE (${LE_NAME}) -> ECR (${ECR_ROLE}) -> delegated agent AID"
  note "Real KERI, real ACDC, real verifier. The root of trust is self-configured;"
  note "in production it would be GLEIF's."
}

main "$@"
