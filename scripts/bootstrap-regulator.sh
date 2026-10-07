#!/usr/bin/env bash
#
# bootstrap-regulator.sh — the gateway operator's own LE credential.
#
#   bash scripts/bootstrap-regulator.sh     # re-runnable: a credential that still chains is kept
#
# The gateway publishes who operates it at /.well-known/vlei. A careful client verifies that before
# presenting anything, and the credential proxy (examples/credential-proxy) refuses to expose a
# single tool until it has.
#
# Until this script, the gateway published the employer's LE — the only LE the demo had — so
# "who operates this gateway?" was answered with the employer. This issues the operator an LE of its
# own, from the same QVI, so the answer is the operator:
#
#   模擬勞保機關（虛構）/ Simulated Labour Insurance Office (fictional)
#   LEI 984500LABORSIM000054 — valid ISO 17442 check digits, not in GLEIF's index
#
# It is not the Bureau of Labor Insurance, does not speak for it, and nothing here is connected to it.
#
# Writes credentials/regulator/{le.cesr,env.json} and a keystore named `regulator`. The main chain's
# credentials are untouched; the QVI's key event log gains one issuance.
#
set -euo pipefail

REGULATOR_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bootstrap-credentials.sh
source "${REGULATOR_HERE}/bootstrap-credentials.sh" --library

MAIN_WORK="$WORK"
OUT="${VLEI_BOOTSTRAP_CREDENTIALS:-${ROOT_DIR}/credentials}/regulator"
WORK="${OUT}/_work"
CWORK="/credentials/regulator/_work"

LE_NAME="${REGULATOR_LE_NAME:-Simulated Labour Insurance Office (fictional)}"
LE_NAME_ZH="${REGULATOR_LE_NAME_ZH:-模擬勞保機關（虛構）}"
LE_LEI="${REGULATOR_LE_LEI:-984500LABORSIM000054}"
R=regulator

# Whether a keystore holds a credential — true only if both the keystore and the credential exist.
holds() {
  local keystore="$1" said="$2"
  [[ -n "$said" ]] || return 1
  kli vc list --name "$keystore" --alias "$keystore" --said 2>/dev/null | tr -d '\r' | grep -qxF "$said"
}

regulator_main() {
  step "Preflight — the main chain's QVI issues this credential"
  [[ -s "${MAIN_WORK}/qvi.said" && -s "${MAIN_WORK}/qvi.aid" ]] \
    || fail "no QVI in ${MAIN_WORK}: run scripts/bootstrap-credentials.sh first"
  kli status --name qvi --alias qvi >/dev/null 2>&1 || fail "the qvi keystore is missing"
  mkdir -p "$WORK"
  local qvi_said; qvi_said="$(cat "${MAIN_WORK}/qvi.said")"
  ok "QVI credential ${qvi_said}"

  step "The operator's controller"
  if kli status --name "$R" --alias "$R" >/dev/null 2>&1; then
    note "$R already exists"
  else
    kli init --name "$R" --nopasscode \
      --config-dir /keri-config --config-file bootstrap-config >/dev/null
    resolve_witnesses "$R"
    kli incept --name "$R" --alias "$R" --file /keri-config/incept-witnesses.json >/dev/null
  fi
  kli aid --name "$R" --alias "$R" | tr -d '\r\n' > "${WORK}/${R}.aid"
  ok "$R = $(cat "${WORK}/${R}.aid")"

  # Kept when it is still held and still chains to the QVI credential the main chain uses now. A
  # reset issues a new QVI, and an LE chained to the old one would reach a root nobody accepts.
  local said; said="$(cat "${WORK}/le.said" 2>/dev/null || true)"
  if holds "$R" "$said" && [[ "$(cat "${WORK}/qvi.said" 2>/dev/null || true)" == "$qvi_said" ]]; then
    note "LE ${said} still held and chained to the current QVI: kept"
  else
    step "Issuing the operator's LE (${LE_NAME}, LEI ${LE_LEI})"
    # The QVI and the operator must be able to resolve each other for the grant to arrive.
    kli oobi generate --name "$R" --alias "$R" --role witness | head -1 | tr -d '\r\n' \
      > "${WORK}/${R}.oobi"
    kli oobi generate --name qvi --alias qvi --role witness | head -1 | tr -d '\r\n' \
      > "${WORK}/qvi.oobi"
    kli oobi resolve --name qvi --oobi-alias "$R" --oobi "$(cat "${WORK}/${R}.oobi")" >/dev/null
    kli oobi resolve --name "$R" --oobi-alias qvi --oobi "$(cat "${WORK}/qvi.oobi")" >/dev/null

    printf '{ "LEI": "%s" }\n' "$LE_LEI" > "${WORK}/le-data.json"
    printf '{ "d": "", "qvi": { "n": "%s", "s": "%s" } }\n' "$qvi_said" "$SCHEMA_QVI" \
      > "${WORK}/le-edges.json"
    rules_for "$SCHEMA_QVI" "${WORK}/rules.json"
    said="$(issue qvi "$(cat "${WORK}/${R}.aid")" "$R" "$SCHEMA_LE" \
            "${CWORK}/le-data.json" "${CWORK}/le-edges.json" "${CWORK}/rules.json")"
    printf '%s' "$said" > "${WORK}/le.said"
    printf '%s' "$qvi_said" > "${WORK}/qvi.said"
    ok "LE credential ${said}"
  fi

  step "Exporting to credentials/regulator/"
  kli vc export --name "$R" --alias "$R" --said "$said" --full > "${OUT}/le.cesr"
  cat > "${OUT}/env.json" <<EOF
{
  "profile":   "regulator",
  "leAid":     "$(cat "${WORK}/${R}.aid")",
  "leSaid":    "${said}",
  "lei":       "${LE_LEI}",
  "leName":    "${LE_NAME}",
  "leNameZh":  "${LE_NAME_ZH}",
  "rootAid":   "$(cat "${MAIN_WORK}/root.aid")",
  "fictional": "All identities are fictional. The root of trust is self-hosted for demonstration.",
  "note":      "The gateway operator's LE, published at /.well-known/vlei. Not the Bureau of Labor Insurance."
}
EOF
  ok "credentials/regulator/le.cesr, credentials/regulator/env.json"
  note "The gateway publishes it when started with"
  note "  VLEI_LE_CREDENTIAL_FILE=../../credentials/regulator/le.cesr (scripts/reset-demo.sh does this)"
}

regulator_main "$@"
