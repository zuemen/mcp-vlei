#!/usr/bin/env bash
#
# bootstrap-credentials.sh — one command to stand up the mcp-vlei credential environment.
#
#   bash scripts/bootstrap-credentials.sh            # full run
#   bash scripts/bootstrap-credentials.sh --down     # tear everything down
#   bash scripts/bootstrap-credentials.sh --verify   # re-run acceptance checks only
#   bash scripts/bootstrap-credentials.sh --reissue  # fresh ECR after a revocation
#   bash scripts/bootstrap-credentials.sh --install-root  # root of trust into a recreated verifier
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
# Machine-local overrides (gitignored), e.g. witness host ports when Windows has reserved 5642-5644.
# `docker compose` reads the same file, so the scripts and the containers agree on the ports.
[[ -f "${HERE}/.env" ]] && { set -a; . "${HERE}/.env"; set +a; }
WITNESS_URL="${VLEI_WITNESS_URL:-http://localhost:5642}"
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
SCHEMA_LE="${SCHEMA_LE:-ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY}"
SCHEMA_ECR="${SCHEMA_ECR:-EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw}"

# The legal entity this demo issues for. LEI is a test value: the association does not hold a
# real LEI, and every artifact says so.
LE_NAME="${LE_NAME:-Taiwan Blockchain Enthusiasts Association}"
LE_LEI="${LE_LEI:-984500ABCDEF12345678}"
# One engagement context, used by every example. A person may hold several ECRs — one per context
# — and a second would be the natural way to give the association and the regulator different
# roles. It is left out because issuing two credentials from one issuer needs the SAID read back by
# diffing the issuer's list, and that is not yet verified against this keripy build.
ECR_ROLE="${ECR_ROLE:-regulatory-filing}"
ECR_PERSON="${ECR_PERSON:-Chen Wei-Ting}"

# Keystore names. Each is an independent controller with its own keystore, as separate parties
# would be in reality.
PARTIES=(root qvi le ecr)

c_reset=$'\033[0m'; c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_hi=$'\033[36m'; c_dim=$'\033[90m'
step()  { printf '\n%s==> %s%s\n' "$c_hi" "$*" "$c_reset"; }
ok()    { printf '%s  ok%s  %s\n' "$c_ok" "$c_reset" "$*"; }
# To stderr: `fail` runs inside `$(issue …)`, where stdout is the captured value. On stdout the
# message was swallowed and the script stopped with no explanation.
fail()  { printf '%s fail%s %s\n' "$c_bad" "$c_reset" "$*" >&2; exit 1; }
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
  until curl -fsS "${WITNESS_URL}/oobi" >/dev/null 2>&1; do
    tries=$((tries+1)); [[ $tries -gt 40 ]] && fail "witness network did not come up on ${WITNESS_URL}"
    sleep 2
  done
  ok "witnesses wan/wil/wes up (${WITNESS_URL})"

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
# Demo witness network: AID keyed by HTTP port. These are the well-known demo identifiers, produced
# by the fixed salts `kli witness demo` uses.
WITNESSES=(
  "5642:BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
  "5643:BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
  "5644:BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"
)

# Resolve each witness OOBI into this keystore.
#
# The config file's `iurls` already do this at `kli init`. Repeating it here is deliberate: a single
# unresolvable entry anywhere in that config aborts the whole OOBI load, leaving a keystore with no
# witness endpoints and an inception that fails with "unable to find a valid endpoint for witness" —
# a message that points at the witnesses rather than at the config. This keeps the witnesses
# resolved regardless, and the operation is idempotent.
resolve_witnesses() {
  local keystore="$1"
  for w in "${WITNESSES[@]}"; do
    local port="${w%%:*}" aid="${w##*:}"
    kli oobi resolve --name "$keystore" --oobi-alias "wit${port}" \
      --oobi "http://witness-demo:${port}/oobi/${aid}/controller" >/dev/null
  done
}

make_parties() {
  step "Stage 2 — creating controllers: ${PARTIES[*]}"
  for p in "${PARTIES[@]}"; do
    if kli status --name "$p" --alias "$p" >/dev/null 2>&1; then
      note "$p already exists, skipping inception"
    elif [[ "$p" == "qvi" ]]; then
      # A QVI is a delegated identifier of the root of trust. This is not a stylistic choice:
      # vlei-verifier rejects a chain whose QVI is standalone, with "The QVI AID must be
      # delegated", and it is right to — a QVI's authority is derived from the root, and a
      # standalone QVI AID would have authority of its own.
      delegated_incept qvi root || fail "QVI delegation failed, and the chain requires it.
      Raise DELEGATION_TRIES and re-run; unlike the agent delegation, this one has no fallback."
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

# The agent's delegated AID, created under the ECR holder's KEL. Revoking the delegation stops the
# agent without touching the person's credential. Optional by design — see SPEC.md "Why a
# delegated AID for the agent"; if this stage is dropped, the ECR holder's AID signs directly.
# Delegated inception: the delegate proposes and blocks, the delegator confirms.
#
# Used twice, for different reasons:
#
#   qvi under root   — required. vlei-verifier enforces the ecosystem rule that a QVI AID is a
#                      delegated identifier of the root of trust; a standalone QVI fails chain
#                      validation with "The QVI AID must be delegated".
#   agent under ecr  — optional. It gives the agent a revocable identifier of its own without
#                      giving it the person's key. See SPEC.md "Delegation".
#
# Returns non-zero if the delegation could not be completed; the caller decides whether that is
# fatal.
delegated_incept() {
  local child="$1" parent="$2"

  kli init --name "$child" --nopasscode \
    --config-dir /keri-config --config-file bootstrap-config >/dev/null
  resolve_witnesses "$child"

  # The delegate must know its delegator before it can propose to it. Stage 3 resolves everyone
  # against everyone, but that runs later — so resolve the one OOBI needed here.
  local parent_oobi
  parent_oobi="$(kli oobi generate --name "$parent" --alias "$parent" --role witness \
                 | head -1 | tr -d '\r\n')"
  [[ -n "$parent_oobi" ]] || fail "could not generate a witness OOBI for ${parent}"
  kli oobi resolve --name "$child" --oobi-alias "$parent" --oobi "$parent_oobi" >/dev/null

  # Confirm the delegator's KEL actually landed. Without it the proposer exits immediately with
  # "delegator <AID> not found, unable to process delegation", and because the proposer runs in
  # the background that error is invisible — the run just reports zero confirm attempts.
  kli contacts list --name "$child" 2>/dev/null \
    | grep -q "$(cat "${WORK}/${parent}.aid")" \
    || fail "${child} does not know ${parent} after resolving ${parent_oobi} — delegation cannot proceed"

  # A delegated AID cannot deliver its own delegation request: it does not exist yet, so it has no
  # established key state to sign transport with. keripy requires a *proxy* — an ordinary AID in
  # the same keystore — to carry the request to the delegator. Without it the proposer exits
  # immediately with "no proxy to send messages for delegation", and since it runs in the
  # background that message is never seen.
  if ! kli status --name "$child" --alias "${child}-proxy" >/dev/null 2>&1; then
    kli incept --name "$child" --alias "${child}-proxy" \
      --file /keri-config/incept-witnesses.json >/dev/null
  fi

  kli incept --name "$child" --alias "$child" \
    --file /keri-config/incept-witnesses.json --delpre "$(cat "${WORK}/${parent}.aid")" \
    --proxy "${child}-proxy" >/dev/null 2>&1 &
  local proposer=$!

  # Let the proposer publish before confirming: a confirm that lands first does nothing, and both
  # sides then wait for each other.
  sleep 4

  # Each confirm attempt gets its own timeout, because `kli delegate confirm` blocks waiting for a
  # request — an unbounded call is indistinguishable from a hang.
  local tries=0
  while kill -0 "$proposer" 2>/dev/null && [[ $tries -lt ${DELEGATION_TRIES:-10} ]]; do
    tries=$((tries+1))
    timeout 15 bash -c "$(declare -f kli); COMPOSE='$COMPOSE'; \
      kli delegate confirm --name $parent --alias $parent --interact --auto" >/dev/null 2>&1 || true
    sleep 2
  done

  local stuck=0
  kill -0 "$proposer" 2>/dev/null && stuck=1
  [[ $stuck -eq 1 ]] && kill "$proposer" 2>/dev/null
  if [[ $stuck -eq 1 ]] || ! wait "$proposer"; then
    note "delegated inception of ${child} under ${parent} did not complete (${tries} attempts)"
    return 1
  fi
  return 0
}

# The agent's delegated AID, under the ECR holder's KEL.
make_delegate() {
  step "Stage 2b — creating the agent's delegated AID under the ECR holder's KEL"
  if kli status --name agent --alias agent >/dev/null 2>&1; then
    note "agent delegated AID already exists"
  elif ! delegated_incept agent ecr; then
    # Not fatal. The delegated AID is the one optional element of the chain, and everything after
    # this stage works without it. Stopping here would cost the credential chain to save a
    # refinement the specification already marks optional.
    note "the ECR holder's AID will sign directly. delegatedAid is optional in the schema;"
    note "what is lost is the second revocation switch, not any other property."
    note "See SPEC.md 'Delegation'. Raise DELEGATION_TRIES to retry more patiently."
    printf '%s\n' "" > "${WORK}/agent.aid"
    ok "agent = (none; the ECR holder's AID signs directly)"
    return 0
  fi
  local aid; aid="$(kli aid --name agent --alias agent 2>/dev/null | tr -d '\r\n')"
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


  # Rules blocks are derived from each schema rather than written out by hand.
  #
  # Every disclaimer in a vLEI schema is a `const`: the text must match to the character, and each
  # schema fixes its own set — QVI and LE require usageDisclaimer + issuanceDisclaimer, ECR
  # requires a third, privacyDisclaimer, whose text differs from the one used elsewhere in the
  # ecosystem. A mismatch is not reported usefully: keripy catches the validation error, returns
  # from a half-built Doer, and the visible message becomes
  # "'CredentialIssuer' object has no attribute '_tock'".
  #
  # Reading the consts out of the schema makes that class of failure impossible, and keeps working
  # when the schemas are updated.
  rules_for "$SCHEMA_QVI" "${WORK}/rules.json"
  rules_for "$SCHEMA_ECR" "${WORK}/ecr-rules.json"
}

# Emit the rules block a schema demands, with every disclaimer's exact const text.
rules_for() {
  local said="$1" out="$2"
  curl -fsS "http://localhost:7723/oobi/${said}" | python -c '
import json, sys
schema = json.load(sys.stdin)
block = next(o for o in schema["properties"]["r"]["oneOf"] if o.get("type") == "object")
rules = {"d": ""}
for name, spec in block["properties"].items():
    if name == "d":
        continue
    rules[name] = {"l": spec["properties"]["l"]["const"]}
json.dump(rules, sys.stdout, ensure_ascii=False, indent=2)
' > "$out" || fail "could not derive the rules block for schema ${said}"
}

# Issue one credential and have the recipient admit it. Returns the credential SAID on stdout.
issue() {
  local issuer="$1" recipient_aid="$2" recipient="$3" schema="$4" data="$5" edges="${6:-}"
  local rules="${7:-/credentials/_work/rules.json}" private="${8:-}"
  local args=(vc create --name "$issuer" --alias "$issuer"
              --registry-name "${issuer}Registry"
              --schema "$schema" --recipient "$recipient_aid"
              --data "@${data}" --rules "@${rules}")
  [[ -n "$edges" ]] && args+=(--edges "@${edges}")
  # ECR schemas require `u`, the privacy salt, at the top level of the credential. Without
  # --private keripy omits it and the schema rejects the result — an ECR names a natural person,
  # so the salt is what keeps the same credential from being correlatable across presentations.
  [[ -n "$private" ]] && args+=(--private)
  # Read the SAID from `vc create` itself ("<SAID> has been created."). Listing the issuer's
  # credentials and taking the last line looked equivalent while each issuer held one credential,
  # and silently returned the wrong one as soon as an issuer held two.
  # `kli vc create` keeps its plain invocation: redirecting its output to a file, or capturing
  # it with `$( )`, makes the run hang — it leaves a background doer holding the stream open.
  #
  # The SAID is therefore read back from the issuer's list — as the one entry that was not there
  # before the call. `tail -1` was not enough: the list is ordered by SAID, not by issuance, so a
  # re-issue (the LE's second and third ECR) returned whichever SAID sorted last — once, the
  # credential that had just been revoked — and granted that one to the holder again.
  local said before after
  before="$(kli vc list --name "$issuer" --alias "$issuer" --issued --said | tr -d '\r')"
  kli "${args[@]}" >/dev/null
  after="$(kli vc list --name "$issuer" --alias "$issuer" --issued --said | tr -d '\r')"
  said="$(printf '%s\n' "$after" | grep -vxF -f <(printf '%s\n' "$before" | grep .) | grep . || true)"
  if [[ "$(printf '%s' "$said" | grep -c .)" -gt 1 ]]; then
    fail "issuing from ${issuer} added more than one credential: ${said//$'\n'/ }"
  fi
  # An empty SAID means `vc create` failed. Stopping here is the whole point: the next steps would
  # otherwise run against an empty identifier and report success on nothing.
  [[ -n "$said" ]] || fail "issuing from ${issuer} produced no credential.
      A schema-validation failure surfaces as: 'CredentialIssuer' object has no attribute '_tock'"

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
              /credentials/_work/ecr-data.json /credentials/_work/ecr-edges.json \
              /credentials/_work/ecr-rules.json private)"
  ok "ECR credential  $ECR_SAID  (le -> ecr, role=${ECR_ROLE})"

  printf '%s' "$QVI_SAID" > "${WORK}/qvi.said"
  printf '%s' "$LE_SAID"  > "${WORK}/le.said"
  printf '%s' "$ECR_SAID" > "${WORK}/ecr.said"

}

# ---------------------------------------------------------------------------------------------
# Stage 5 — export CESR for the packages to consume
# ---------------------------------------------------------------------------------------------
# The file every example reads. Written here and again after the ECR is re-issued, so it always
# names the credential that is actually valid.
_write_env() {
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
}

export_creds() {
  step "Stage 5 — exporting CESR credentials to credentials/"
  kli vc export --name le  --alias le  --said "$(cat "${WORK}/le.said")"  --full \
    > "${OUT}/le.cesr"
  kli vc export --name ecr --alias ecr --said "$(cat "${WORK}/ecr.said")" --full \
    > "${OUT}/ecr.cesr"

  _write_env
  ok "credentials/le.cesr, credentials/ecr.cesr, credentials/env.json"
}

# ---------------------------------------------------------------------------------------------
# Stage 6 — install our root of trust into the verifier
# ---------------------------------------------------------------------------------------------
install_root() {
  step "Stage 6 — installing the self-configured root of trust into vlei-verifier"
  local root_aid; root_aid="$(cat "${WORK}/root.aid")"
  local oobi;     oobi="$(cat "${WORK}/root.oobi")"

  # `vlei` must be the root's own KEL as a CESR stream, not a credential: the verifier parses it
  # and looks for a key event whose `i` is this AID. Sending a credential chain instead produces
  # only "Adding new Root Of Trust ... FAILED", with no indication of what was wrong with it.
  kli export --name root --alias root --ends > "${WORK}/root.kel"

  local code
  code="$(python - "$root_aid" "$oobi" "${WORK}/root.kel" "${VERIFIER}" \
          "${WORK}/root_of_trust.out" <<'PY'
import json, sys, urllib.error, urllib.request

aid, oobi, kel_path, verifier, out_path = sys.argv[1:6]
body = json.dumps({"vlei": open(kel_path, encoding="utf-8").read(), "oobi": oobi}).encode()
request = urllib.request.Request(
    f"{verifier}/root_of_trust/{aid}", data=body,
    headers={"Content-Type": "application/json"}, method="POST",
)
try:
    with urllib.request.urlopen(request) as response:
        status, payload = response.status, response.read()
except urllib.error.HTTPError as err:
    status, payload = err.code, err.read()
open(out_path, "wb").write(payload)
print(status)
PY
)"

  case "$code" in
    200|201|202) ok "root of trust installed: ${root_aid} (HTTP ${code})" ;;
    *) fail "verifier rejected the root of trust (HTTP ${code}): $(cat "${WORK}/root_of_trust.out")" ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Acceptance checks — these are the deliverable, not decoration
# ---------------------------------------------------------------------------------------------
# vlei-verifier requires the HTTP request itself to be signed, with SIGNATURE-INPUT, SIGNATURE,
# SIGNIFY-RESOURCE and SIGNIFY-TIMESTAMP. That is the right requirement: without it, anyone holding
# a copy of a credential could present it as their own. Those headers normally come from a Signify
# client talking to a KERIA agent; this project has neither, so /keri-config/present.py signs
# directly from the keystore. The verifier is reached by service name because keri-cli shares the
# witness container's network namespace.
VERIFIER_INTERNAL="http://vlei-verifier:7676"

# The verifier must know the presenter's KEL before it can check a signed header, or it answers
# "unknown ... used to sign header" — which reads like a signing bug rather than a missing
# introduction.
introduce_to_verifier() {
  local keystore="$1" alias="$2"
  local oobi; oobi="$(kli oobi generate --name "$keystore" --alias "$alias" --role witness \
                      | head -1 | tr -d '\r\n')"
  curl -sS -o /dev/null -X POST "${VERIFIER}/oobi" \
    -H 'Content-Type: application/json' -d "{\"oobi\":\"${oobi}\"}"
}

# The witness URL is passed on every presentation: the verifier reads the credential's TEL from a
# witness to learn about revocation. Without it, it keeps answering "valid" after a revocation,
# because nothing ever tells it otherwise.
WITNESS_INTERNAL="http://witness-demo:5642"

present() {
  local said="$1"
  kli_py present ecr ecr "$said" /credentials/ecr.cesr "$VERIFIER_INTERNAL" "$WITNESS_INTERNAL"
}

authorized() {
  local aid="$1"
  kli_py authorizations ecr ecr "$aid" "$VERIFIER_INTERNAL"
}

# Run present.py inside the container, capturing its response body for the caller to report.
kli_py() {
  MSYS_NO_PATHCONV=1 $COMPOSE exec -T keri-cli \
    python /keri-config/present.py "$@" 2> "${WORK}/verifier.out" | tr -d '\r\n'
}

verify_all() {
  local ecr_said ecr_aid code
  ecr_said="$(cat "${WORK}/ecr.said")"; ecr_aid="$(cat "${WORK}/ecr.aid")"

  step "Check 3 — presenting the ECR credential"
  introduce_to_verifier ecr ecr
  code="$(present "$ecr_said")"
  [[ "$code" == "202" || "$code" == "200" ]] \
    && ok "presentation accepted (HTTP ${code})" \
    || fail "presentation rejected (HTTP ${code}): $(cat "${WORK}/verifier.out")"

  step "Check 4 — the holder is authorized"
  sleep 2
  code="$(authorized "$ecr_aid")"
  [[ "$code" == "200" ]] \
    && ok "authorized (HTTP 200): $(cat "${WORK}/verifier.out")" \
    || fail "expected 200, got ${code}: $(cat "${WORK}/verifier.out")"

  step "Check 5 — revoking the ECR credential"
  # Tolerate an already-revoked credential so `--verify` can be re-run: revocation is not
  # reversible, and a second run of the checks should exercise check 6 rather than stop here.
  if kli vc revoke --name le --alias le --registry-name leRegistry --said "$ecr_said" \
       --send "$ecr_aid" >/dev/null 2>&1; then
    ok "revoked in the LE's TEL"
  else
    note "already revoked — continuing to check 6"
  fi
  sleep 3

  step "Check 6 — the holder is no longer authorized"
  # Re-export before re-presenting. The CESR written in stage 5 predates the revocation, so
  # presenting it again tells the verifier nothing new.
  kli vc export --name ecr --alias ecr --said "$ecr_said" --full --include-revoked \
    > "${OUT}/ecr.cesr"
  present "$ecr_said" >/dev/null || true

  # Revocation detection is asynchronous. The verifier runs a background observer that polls
  # {witness_url}/query?typ=tel for each credential it holds, on a 60-second interval by default,
  # so a revocation takes effect at the next poll rather than at the next request. Poll for it
  # rather than sleeping a fixed amount — and note the delay, because it is the real-world answer
  # to "how quickly does a withdrawal of authority take effect".
  local waited=0
  while [[ $waited -lt ${REVOCATION_WAIT:-150} ]]; do
    code="$(authorized "$ecr_aid")"
    if [[ "$code" != "200" ]] || grep -qi 'revok' "${WORK}/verifier.out"; then
      break
    fi
    sleep 10
    waited=$((waited+10))
  done

  if [[ "$code" != "200" ]]; then
    ok "no longer authorized after ${waited}s (HTTP ${code}): $(cat "${WORK}/verifier.out")"
  elif grep -qi 'revok' "${WORK}/verifier.out"; then
    ok "reported revoked after ${waited}s: $(cat "${WORK}/verifier.out")"
  else
    fail "still authorized ${waited}s after revocation — this check must fail loudly.
      The verifier's observer polls the witness for each credential's TEL every 60s by default;
      raise REVOCATION_WAIT if this machine is slower, but a permanent 'valid' here means the
      revocation never reached the verifier: $(cat "${WORK}/verifier.out")"
  fi
}

# ---------------------------------------------------------------------------------------------
# Check 5 revokes the ECR credential, which is the point of checks 5 and 6 — but it also leaves the
# environment holding a credential nothing can use. Issue a fresh one so the run ends ready to
# demonstrate rather than ready to fail, and so `examples/` has something to present.
reissue_ecr() {
  step "Re-issuing the ECR credential, so the environment is left usable"
  local ecr_aid; ecr_aid="$(cat "${WORK}/ecr.aid")"
  ECR_SAID="$(issue le "$ecr_aid" ecr "$SCHEMA_ECR"               /credentials/_work/ecr-data.json /credentials/_work/ecr-edges.json               /credentials/_work/ecr-rules.json private)"
  printf '%s' "$ECR_SAID" > "${WORK}/ecr.said"

  kli vc export --name ecr --alias ecr --said "$ECR_SAID" --full > "${OUT}/ecr.cesr"
  _write_env
  introduce_to_verifier ecr ecr
  local code; code="$(present "$ECR_SAID")"
  [[ "$code" == "202" || "$code" == "200" ]]     && ok "fresh ECR credential $ECR_SAID presented (HTTP ${code})"     || fail "the re-issued credential was rejected (HTTP ${code}): $(cat "${WORK}/verifier.out")"
}

# ---------------------------------------------------------------------------------------------
main() {
  if [[ "${1:-}" == "--reissue" ]]; then
    # After a revocation — scene 3 of the recording, or acceptance check 5 — issue the holder a
    # fresh ECR and export it, without re-running anything else.
    reissue_ecr
    step "Done"
    return
  fi
  if [[ "${1:-}" == "--install-root" ]]; then
    # A recreated verifier starts with an empty database: it knows no root of trust, so every
    # presentation is rejected until the root is installed again. `reset-demo.sh --keep-credentials`
    # recreates it and calls this.
    install_root
    step "Done"
    return
  fi
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

  reissue_ecr

  step "Done"
  note "Chain:  root -> QVI -> LE (${LE_NAME}) -> ECR (${ECR_ROLE}) -> delegated agent AID"
  note "Real KERI, real ACDC, real verifier. The root of trust is self-configured;"
  note "in production it would be GLEIF's."
}

main "$@"
