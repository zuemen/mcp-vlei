#!/usr/bin/env bash
#
# v03-switch.sh — move the gateway to v0.3, and back, one command each.
#
#   bash scripts/v03-switch.sh rehearse                     # all of it, then the rollback, on the parallel stack
#   V03_TARGET=live bash scripts/v03-switch.sh backup   <ts>
#   V03_TARGET=live bash scripts/v03-switch.sh switch   <ts>
#   V03_TARGET=live bash scripts/v03-switch.sh verify   <ts>
#   V03_TARGET=live bash scripts/v03-switch.sh rollback <ts>
#
# live      the main checkout (VLEI_MAIN_CHECKOUT, default $HOME/mcp-vlei, on `main`) and
#           its gateway project, mcp-vlei-regulator. Only that project is recreated. The witnesses,
#           keri-cli, verifier and schema server (project mcp-vlei) are never touched — keri-cli keeps
#           every keystore in its container layer — and `live-guard.sh check-base` says so after each
#           step. keri-cli is only ever `exec`'d into (BOOT_COMPOSE below), to approve the gateway's
#           AID. Refuses to run in a shell that holds the parallel stack's variables
#           (`eval "$(bash scripts/v03-stack.sh env)"`): open a clean one.
# parallel  the same steps on mcp-vlei-v03p-regulator, from a clone at .v03/rehearsal that starts at
#           v0.2 (scripts/v03-stack.sh up && bootstrap must have run). `rehearse` drives it, so the
#           live run executes commands that have already worked once. It starts from
#           V03_REHEARSAL_BASE, by default `git merge-base HEAD main` — the commit before the first
#           v0.3 merge, until main has merged v0.3. Once it has, that is no longer v0.2: a base that
#           already holds scripts/v03-switch.sh is refused, and V03_REHEARSAL_BASE names the commit.
#
# Backups: .v03/switch/<ts>/ (gitignored), written once — the checkout's commit, image tags
# <image>:pre-v03-<ts>, copies of the gateway's files and decision log, live-guard snapshots — and
# marked `complete` last; switch, verify and rollback refuse a backup without that mark.
# Credentials and keystores are not copied by this script.
#
# verify checks the gateway as a client would — the proof of possession through mcp_vlei's
# prove_server (signature under the witnessed key state, delegation by the operator's LE) and the
# proxy's live tests — then restarts the two simulators so the demo records it filed leave /ledger.
# A failed verify names the rollback command.
#
# A switch that fails after its merge (build, vlei-pop, the AID's delegation, the recreate) runs
# `rollback` itself, then stops. The rollback leaves the checkout detached at the backed-up commit
# and says where `main` points; it does not move `main` back, and it does not restore the decision
# log (the log keeps what the gateway decided while v0.3 ran; the backup holds the earlier copy).
#
# The one change that is not undone by `rollback`: the operator's key event log gains the event
# that approves the gateway's signing AID (scripts/bootstrap-gateway-signer.sh). No v0.2 check reads
# it; the AID and its keystore volume stay, unused, for the next switch.
#
# MSYS_NO_PATHCONV: no command here passes a container path, so it is set nowhere in this script
# (the signer's kli helpers set it per command). Exported for a whole Git Bash shell it makes
# Git for Windows' `curl -o /dev/null` write to a literal path (spec §15 R10), so it is unset here.
set -euo pipefail
unset MSYS_NO_PATHCONV

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) NROOT="$(cygpath -m "$ROOT")" ;;
  *)                    NROOT="$ROOT" ;;
esac
TARGET="${V03_TARGET:-parallel}"
SERVICES=(labor-insurance-sim labor-insurance-before vlei-authz)
SIMULATORS=(labor-insurance-sim labor-insurance-before)   # verify restarts these: their ledgers are in memory
MAIN_BRANCH=main

say()  { printf '\n==> %s\n' "$*"; }
warn() { printf '\nv03-switch: %s\n' "$*" >&2; }
fail() { warn "$@"; exit 1; }
# After the merge, a failure that is not rolled back automatically ends with this one line.
not_rolled_back() {  # $1 ts, $2 what failed
  fail "$2; the switch is NOT rolled back automatically — to roll back: V03_TARGET=${TARGET} bash scripts/v03-switch.sh rollback $1"
}
# A rollback that cannot finish says where it stopped and what it had already put back.
rollback_stopped() {  # $1 the step, $2 what has been restored so far, $3 the backup's directory
  fail "rollback stopped at $1; state: $2; backup: $3"
}

# The live target must not inherit the parallel stack's addresses: a shell that ran
# `eval "$(bash scripts/v03-stack.sh env)"` would point the signer, the verify step's proxy tests
# or the credentials at mcp-vlei-v03p.
refuse_parallel_env() {
  local bad=() name value
  for name in VLEI_CREDENTIALS_DIR VLEI_COMPOSE_CMD; do
    [[ -n "${!name:-}" ]] && bad+=("${name} (set)")
  done
  for name in $(compgen -e); do
    [[ "$name" == VLEI_* ]] || continue
    value="${!name}"
    case "$value" in
      *mcp-vlei-v03p*|*.v03/*|*.v03\\*|*:33000*|*:3564[2-4]*|*:37676*|*:37723*|*:38090*)
        bad+=("${name} (points at the parallel stack)") ;;
    esac
  done
  if [[ -n "${VLEI_GATEWAY_URL:-}" && ! "$VLEI_GATEWAY_URL" =~ ^https?://(localhost|127\.0\.0\.1):3000(/|$) ]]; then
    bad+=("VLEI_GATEWAY_URL (${VLEI_GATEWAY_URL}, not on :3000)")
  fi
  (( ${#bad[@]} == 0 )) && return 0
  printf '  %s\n' "${bad[@]}" >&2
  fail "V03_TARGET=live refuses to run with the parallel stack's variables in the environment (above); open a clean shell"
}

# GW is the gateway project (the only one recreated); BOOT_COMPOSE is the base project whose
# keri-cli holds the operator's `regulator` keystore — bootstrap-gateway-signer.sh only `exec`s
# into it, and requires it explicitly (it would otherwise fall back to the live compose file).
case "$TARGET" in
  live)
    refuse_parallel_env
    CHECKOUT="${VLEI_MAIN_CHECKOUT:-$HOME/mcp-vlei}"
    PROJECT=mcp-vlei-regulator
    GW="docker compose -p ${PROJECT} -f ${CHECKOUT}/deploy/agentgateway/docker-compose.yml"
    BOOT_COMPOSE="docker compose -p mcp-vlei -f ${CHECKOUT}/scripts/docker-compose.yml"
    CREDS="${CHECKOUT}/credentials"
    GATEWAY=http://localhost:3000
    BRANCH=feature/v0.3-binding
    SIGNER="${CHECKOUT}/scripts/bootstrap-gateway-signer.sh"   # the merged v0.3 copy
    CONSOLE_LOG="${CHECKOUT}/console.log"                       # where reset-demo.sh writes it
    ;;
  parallel)
    CHECKOUT="${NROOT}/.v03/rehearsal"
    PROJECT=mcp-vlei-v03p-regulator
    GW="docker compose -p ${PROJECT} -f ${CHECKOUT}/deploy/agentgateway/docker-compose.yml -f ${NROOT}/deploy/v03/parallel.regulator.yml"
    # As scripts/v03-stack.sh builds BASE.
    BOOT_COMPOSE="docker compose -p mcp-vlei-v03p -f ${NROOT}/scripts/docker-compose.yml -f ${NROOT}/deploy/v03/parallel.base.yml"
    CREDS="${NROOT}/.v03/credentials"
    GATEWAY=http://localhost:33000
    BRANCH=origin/feature/v0.3-binding
    SIGNER="${NROOT}/scripts/bootstrap-gateway-signer.sh"
    CONSOLE_LOG=""   # no console on the parallel target
    eval "$(bash "${HERE}/v03-stack.sh" env)"
    export VLEI_AUDIENCE_URLS="${GATEWAY}/mcp,http://127.0.0.1:33000/mcp"
    ;;
  *) fail "V03_TARGET must be live or parallel" ;;
esac

gateway_env() {  # returns non-zero, naming the problem in one line, when env.json cannot be read
  VLEI_ACCEPTED_ROOTS="$(python -c "import json,sys
try:
    print(','.join(json.load(open(sys.argv[1]))['acceptedRoots']))
except Exception as exc:
    sys.exit(f'v03-switch: cannot read acceptedRoots from {sys.argv[1]}: {type(exc).__name__}: {exc}')" \
    "${CREDS}/env.json")" || return 1
  [[ -n "$VLEI_ACCEPTED_ROOTS" ]] || { warn "${CREDS}/env.json lists no accepted roots"; return 1; }
  export VLEI_ACCEPTED_ROOTS
  export VLEI_LE_CREDENTIAL_FILE="${CREDS}/regulator/le.cesr"
}

guard() { bash "${HERE}/live-guard.sh" "$@"; }

# The PID listening on :8800, or nothing. Never an error: "no console" is a state, not a failure
# (awk reads to the end, so no stage of the pipe dies of SIGPIPE under pipefail).
console_pid() {
  { netstat -ano 2>/dev/null || true; } | tr -d '\r' \
    | awk '!found && $2 ~ /:8800$/ && $4 == "LISTENING" { print $5; found = 1 }' || true
}

restart_console() {  # live only: the console (a host process on :8800) runs the checkout's code. $1: what the gateway runs now
  # Returns 1, naming the problem, rather than exiting: the caller says what state that leaves.
  [[ "$TARGET" == live ]] || return 0
  local state="$1" old new i
  old="$(console_pid)"
  if [[ -n "$old" ]]; then
    taskkill //PID "$old" //F >/dev/null 2>&1 || kill "$old" 2>/dev/null || true
    for i in $(seq 1 30); do
      [[ -z "$(console_pid)" ]] && break
      sleep 1
    done
    [[ -z "$(console_pid)" ]] \
      || { warn "the console (PID ${old}) still listens on :8800 after taskkill. The gateway runs ${state}; stop the console by hand, then start it from ${CHECKOUT}"; return 1; }
    say "console stopped (PID ${old})"
  else
    say "no console was listening on :8800: starting one"
  fi
  printf '\n--- v03-switch %s: console started from %s, gateway %s\n' \
    "$(date '+%F %T')" "$CHECKOUT" "$state" >> "$CONSOLE_LOG"
  ( cd "$CHECKOUT" && PYTHONPATH="packages/mcp-vlei/src" VLEI_POLICY_UTC_OFFSET="${VLEI_POLICY_UTC_OFFSET:-+08:00}" \
      python examples/console/app.py >> "$CONSOLE_LOG" 2>&1 & ) </dev/null >/dev/null 2>&1
  for i in $(seq 1 90); do
    new="$(console_pid)"
    if [[ -n "$new" && "$new" != "$old" ]] && curl -fsS http://localhost:8800/state >/dev/null 2>&1; then
      say "console restarted from ${CHECKOUT} (PID ${new})"
      return 0
    fi
    sleep 1
  done
  warn "the console did not come back on :8800 (no new PID answering /state). The gateway runs ${state}; see ${CONSOLE_LOG}"
  return 1
}

checkout_clean() {  # no uncommitted changes to tracked files; on the live target, on main
  local st br
  st="$(git -C "$CHECKOUT" status --porcelain --untracked-files=no)" || fail "${CHECKOUT} is not a git checkout"
  [[ -z "$st" ]] || fail "${CHECKOUT} has uncommitted changes to tracked files; stop and ask"
  if [[ "$TARGET" == live ]]; then
    br="$(git -C "$CHECKOUT" symbolic-ref -q --short HEAD || true)"
    [[ "$br" == "$MAIN_BRANCH" ]] || fail "${CHECKOUT} is on ${br:-a detached HEAD}, not ${MAIN_BRANCH}; stop and ask"
  fi
}

require_backup() {  # $1 dir, $2 ts
  [[ -f "$1/complete" && -s "$1/head" ]] \
    || fail "no complete backup for $2 ($1/complete is missing): run backup with a new <ts> first"
}

backed_up_images() {  # $1 dir, $2 ts: every :pre-v03-<ts> tag exists and is the image the backup recorded (else 1)
  local svc want have
  for svc in "${SERVICES[@]}"; do
    want="$(awk -v n="${PROJECT}-${svc}" '$1 == n { print $2 }' "$1/images.txt")" \
      || { warn "cannot read $1/images.txt"; return 1; }
    have="$(docker image inspect -f '{{.Id}}' "${PROJECT}-${svc}:pre-v03-$2" 2>/dev/null)" \
      || { warn "${PROJECT}-${svc}:pre-v03-$2 cannot be read (missing, or Docker unreachable)"; return 1; }
    [[ -n "$want" && "$have" == "$want" ]] \
      || { warn "${PROJECT}-${svc}:pre-v03-$2 is ${have}, the backup recorded ${want:-nothing}"; return 1; }
  done
}

main_note() {  # $1 the backed-up commit: where main points now
  local m
  m="$(git -C "$CHECKOUT" rev-parse -q --verify "refs/heads/${MAIN_BRANCH}" || true)"
  if [[ -z "$m" ]]; then
    echo "${CHECKOUT} has no local ${MAIN_BRANCH}; the checkout is detached at $1."
  elif [[ "$m" == "$1" ]]; then
    echo "${MAIN_BRANCH} points at ${m}, the backed-up commit."
  else
    echo "${MAIN_BRANCH} still points at ${m} (not moved back); the checkout is detached at $1. To move ${MAIN_BRANCH} back too: git -C ${CHECKOUT} switch -C ${MAIN_BRANCH} $1"
  fi
}

backup() {
  local ts="$1" dir="${ROOT}/.v03/switch/$1"
  checkout_clean
  mkdir -p "${ROOT}/.v03/switch"
  mkdir "$dir" 2>/dev/null \
    || fail "${dir} already exists: a backup is written once. Use a new <ts> (or switch/rollback with this one)"
  guard snapshot "${dir}/live-before.txt"
  git -C "$CHECKOUT" rev-parse HEAD > "${dir}/head"
  : > "${dir}/images.txt"
  local svc id
  for svc in "${SERVICES[@]}"; do
    id="$(docker image inspect -f '{{.Id}}' "${PROJECT}-${svc}:latest")"
    docker image tag "$id" "${PROJECT}-${svc}:pre-v03-${ts}"   # by ID: the tag is the image recorded
    echo "${PROJECT}-${svc} ${id}" >> "${dir}/images.txt"
  done
  cp "${CHECKOUT}/deploy/agentgateway/config.yaml" "${CHECKOUT}/deploy/agentgateway/docker-compose.yml" \
     "${CHECKOUT}/examples/regulator/vlei-authz/policy.json" "$dir/"
  if [[ -f "${CHECKOUT}/deploy/agentgateway/audit/decisions.jsonl" ]]; then
    cp "${CHECKOUT}/deploy/agentgateway/audit/decisions.jsonl" "${dir}/decisions.jsonl"
  fi
  date '+%F %T' > "${dir}/complete"   # last: only a backup that got this far can be switched or rolled back
  say "backed up to ${dir}: commit $(cat "${dir}/head"), ${#SERVICES[@]} images tagged :pre-v03-${ts}"
}

merge_branch() {
  git -C "$CHECKOUT" merge --no-ff --no-edit "$BRANCH" && return 0
  if git -C "$CHECKOUT" rev-parse -q --verify MERGE_HEAD >/dev/null; then
    git -C "$CHECKOUT" merge --abort \
      || fail "the merge stopped with conflicts and 'git merge --abort' failed too: ${CHECKOUT} needs a hand"
    fail "the merge did not apply cleanly; it was aborted and nothing else was changed"
  fi
  fail "git refused to start the merge (its reason is above, e.g. an untracked file in the way); nothing was changed"
}

or_roll_back() {  # $1 ts, $2 what; the rest is the command. If it fails: the rehearsed rollback, then stop
  local ts="$1" what="$2"
  shift 2
  "$@" && return 0
  printf '\nv03-switch: %s failed: rolling back to backup %s\n' "$what" "$ts" >&2
  rollback "$ts"
  fail "${what} failed; the switch was rolled back (see above)"
}

switch() {
  local ts="$1" dir="${ROOT}/.v03/switch/$1"
  require_backup "$dir" "$ts"
  checkout_clean
  local now; now="$(git -C "$CHECKOUT" rev-parse HEAD)"
  [[ "$now" == "$(cat "${dir}/head")" ]] \
    || fail "${CHECKOUT} is at ${now}, not at the backed-up $(cat "${dir}/head"): run backup with a new <ts>"
  say "merge ${BRANCH} into ${CHECKOUT}"
  merge_branch
  gateway_env || not_rolled_back "$ts" "reading the gateway's environment from ${CREDS}/env.json (the checkout is merged; nothing else changed)"
  say "build the v0.3 images; start vlei-pop alone"
  or_roll_back "$ts" "the v0.3 build" $GW build
  or_roll_back "$ts" "starting vlei-pop" $GW up -d --no-deps vlei-pop
  say "the gateway's signing AID (the one KERI change the rollback does not undo)"
  or_roll_back "$ts" "the gateway AID's delegation" \
    env VLEI_BOOTSTRAP_COMPOSE="$BOOT_COMPOSE" VLEI_BOOTSTRAP_POP_COMPOSE="$GW" \
        VLEI_BOOTSTRAP_CREDENTIALS="$CREDS" DELEGATION_TRIES="${DELEGATION_TRIES:-20}" bash "$SIGNER"
  say "recreate the gateway at v0.3"
  or_roll_back "$ts" "recreating the gateway" $GW up -d --force-recreate --remove-orphans
  guard check-base "${dir}/live-before.txt" \
    || not_rolled_back "$ts" "live-guard check-base after the switch (its output is above; the gateway runs v0.3)"
  restart_console "v0.3 (switched)" \
    || not_rolled_back "$ts" "restarting the console (the gateway runs v0.3)"
  say "switched. The new replay store refuses calls for its first minute: verify after 70 s"
}

verify_failed() {  # $1 ts, $2 what failed
  not_rolled_back "$1" "verify: $2 failed, so v0.3 is not shown to work here"
}

verify() {
  local ts="$1" dir="${ROOT}/.v03/switch/$1"
  require_backup "$dir" "$ts"
  local code="$CHECKOUT"   # whose code the checks run: the switched checkout, or (parallel) this worktree
  [[ "$TARGET" == parallel ]] && code="$NROOT"
  local started
  started="$(docker inspect -f '{{.State.StartedAt}}' "${PROJECT}-vlei-authz-1")" \
    || verify_failed "$ts" "reading vlei-authz's start time"
  # Whole seconds only: Docker trims trailing zeros from the fraction, which Python 3.10's
  # fromisoformat does not accept.
  python -c "import datetime,sys,time
s=datetime.datetime.fromisoformat(sys.argv[1].rstrip('Z').split('.')[0]+'+00:00')
w=70-(datetime.datetime.now(datetime.timezone.utc)-s).total_seconds()
time.sleep(max(0,w))" "$started" || verify_failed "$ts" "waiting out the replay store's first minute"
  say "the published document"
  # On failure, only the keys checked are printed — not the document (it carries the LE credential).
  curl -fsS "${GATEWAY}/.well-known/vlei" | python -c "import json,sys
d=json.load(sys.stdin); seen={k: d.get(k) for k in ('signatureFormats', 'pop')}
assert 'vlei-sig/0.3' in (seen['signatureFormats'] or []) and seen['pop'], seen
print('well-known ok:', seen['signatureFormats'], seen['pop'])" || verify_failed "$ts" "the well-known document"
  say "a proof of possession, verified as a client verifies it"
  # mcp_vlei.pop.prove_server: the signature under the responder's key state read from the
  # witnesses, and the responder either the operator's LE or delegated by it in the LE's key event
  # log (an AID the LE never approved is refused). The responder must also be the AID this switch
  # delegated (gateway.aid). Witnesses: VLEI_WITNESS_URLS, else the checkout's scripts/.env, as the
  # proxy reads them (only those keys).
  ( cd "$code" && PYTHONPATH=packages/mcp-vlei/src python - "$GATEWAY" "${CREDS}/regulator/le.cesr" \
      "${CREDS}/regulator/gateway.aid" <<'PY'
import asyncio, sys
from pathlib import Path

sys.path.insert(0, "examples/credential-proxy")
import httpx
from proxy import witness_urls
from mcp_vlei.extension import _presented
from mcp_vlei.kel import WitnessKeyStates
from mcp_vlei.pop import POP_PATH, prove_server

gateway, le_file, aid_file = sys.argv[1:4]
holder = _presented(Path(le_file).read_text(encoding="utf-8").strip(), None).issuee
want = Path(aid_file).read_text(encoding="utf-8").strip()


async def main() -> None:
    key_states = WitnessKeyStates(witness_urls(Path.cwd()))
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            proof = await prove_server(http=http, pop_url=gateway + POP_PATH,
                                       endpoint_url=gateway + "/mcp", holder=holder,
                                       key_states=key_states)
    finally:
        await key_states.aclose()
    if proof.responder_aid != want:
        sys.exit(f"proof of possession: signed by {proof.responder_aid}, not by gateway.aid {want}")
    print(f"proof of possession ok: signed by {proof.responder_aid}, "
          f"{'delegated by' if proof.delegated else 'which is'} the operator's LE {holder} "
          f"({proof.agreeing} of {proof.configured} witnesses agree)")


try:
    asyncio.run(main())
except Exception as exc:  # noqa: BLE001 - every failure is reported, by its layer when it has one
    sys.exit(f"proof of possession NOT established: {type(exc).__name__}: {exc}")
PY
  ) || verify_failed "$ts" "the proof of possession"
  say "the proxy, end to end, and the replay probes"
  ( cd "$code" && VLEI_LIVE=1 VLEI_GATEWAY_URL="${GATEWAY}/mcp" PYTHONPATH=packages/mcp-vlei/src \
      python -m pytest examples/credential-proxy/tests/test_live.py -q ) \
    || verify_failed "$ts" "the proxy's live tests"
  # The live tests file demo records through both simulators (EMP-0901 through the gateway, EMP-0951
  # on the before simulator); they keep them in memory, so a restart clears /ledger for the talk.
  say "restart the simulators, so /ledger starts clean"
  $GW restart "${SIMULATORS[@]}" || verify_failed "$ts" "restarting the simulators"
  local sim
  for sim in "${SIMULATORS[@]}"; do printf '  restarted: %s-%s-1\n' "$PROJECT" "$sim"; done
  if [[ "$TARGET" == live ]]; then
    bash "${CHECKOUT}/scripts/record-check.sh" || verify_failed "$ts" "record-check.sh"
  fi
  guard check-base "${dir}/live-before.txt" || verify_failed "$ts" "live-guard check-base (its output is above)"
  say "verified"
}

rollback() {  # a failed step ends in rollback_stopped: where, what is already back, the backup
  local ts="$1" dir="${ROOT}/.v03/switch/$1"
  require_backup "$dir" "$ts"
  local head; head="$(cat "${dir}/head")"
  local restored="nothing yet"
  say "the backed-up images, checked before anything is moved"
  backed_up_images "$dir" "$ts" || rollback_stopped "checking the backed-up images" "$restored" "$dir"
  say "the checkout back to ${head}"
  if git -C "$CHECKOUT" rev-parse -q --verify MERGE_HEAD >/dev/null; then
    git -C "$CHECKOUT" merge --abort || rollback_stopped "git merge --abort in ${CHECKOUT}" "$restored" "$dir"
  fi
  git -C "$CHECKOUT" switch -q --detach "$head" \
    || rollback_stopped "moving ${CHECKOUT} to ${head}" "$restored" "$dir"
  restored="the checkout (detached at ${head})"
  say "the backed-up images back under :latest"
  local svc tagged=()
  for svc in "${SERVICES[@]}"; do
    docker image tag "${PROJECT}-${svc}:pre-v03-${ts}" "${PROJECT}-${svc}:latest" \
      || rollback_stopped "re-tagging ${PROJECT}-${svc}:pre-v03-${ts} as :latest" \
           "${restored}; images back under :latest: ${tagged[*]:-none}" "$dir"
    tagged+=("$svc")
  done
  restored="${restored}, the images (:latest = :pre-v03-${ts})"
  gateway_env \
    || rollback_stopped "reading the gateway's environment from ${CREDS}/env.json" "${restored}; the containers not yet recreated" "$dir"
  unset VLEI_AUDIENCE_URLS
  $GW up -d --no-build --force-recreate --remove-orphans \
    || rollback_stopped "recreating the gateway from the backed-up images" "${restored}; the containers possibly part-recreated" "$dir"
  restored="${restored}, the gateway's containers (recreated from them)"
  guard check-base "${dir}/live-before.txt" \
    || rollback_stopped "live-guard check-base (its output is above)" "$restored" "$dir"
  if [[ "$TARGET" == live ]]; then
    guard check-images "${dir}/live-before.txt" \
      || rollback_stopped "live-guard check-images (its output is above)" "$restored" "$dir"
  fi
  restart_console "v0.2 (rolled back)" \
    || rollback_stopped "restarting the console" "${restored}; the console not restarted" "$dir"
  if [[ -f "${dir}/decisions.jsonl" ]]; then
    say "the decision log was not restored: it keeps what the gateway decided while v0.3 ran; the copy taken before the switch is ${dir}/decisions.jsonl"
  else
    say "the decision log was not restored: there was none at the backup, and it keeps what the gateway decided while v0.3 ran"
  fi
  say "rolled back: the gateway runs the backed-up images from ${head}. $(main_note "$head")"
}

rehearsal_base() {  # the v0.2 commit a rehearsal starts from; refuses one that is already v0.3
  local base
  if [[ -n "${V03_REHEARSAL_BASE:-}" ]]; then
    base="$(git -C "$ROOT" rev-parse --verify --quiet "${V03_REHEARSAL_BASE}^{commit}")"       || fail "V03_REHEARSAL_BASE=${V03_REHEARSAL_BASE} is not a commit in this repository"
  else
    base="$(git -C "$ROOT" merge-base HEAD "$MAIN_BRANCH")"       || fail "HEAD and ${MAIN_BRANCH} share no commit: set V03_REHEARSAL_BASE to the v0.2 commit to rehearse from"
  fi
  if git -C "$ROOT" cat-file -e "${base}:scripts/v03-switch.sh" 2>/dev/null; then
    fail "the rehearsal base ${base} already contains scripts/v03-switch.sh, so it is not v0.2 (has ${MAIN_BRANCH} merged v0.3?). Set V03_REHEARSAL_BASE to the commit before that merge, e.g. V03_REHEARSAL_BASE=<merge commit>^1"
  fi
  printf '%s
' "$base"
}

rehearse() {
  local ts; ts="rehearsal-$(date +%Y%m%d-%H%M%S)"
  local base; base="$(rehearsal_base)"   # before anything is snapshotted, deleted or cloned
  guard snapshot "${ROOT}/.v03/switch/${ts}-live.txt"
  say "a v0.2 clone at .v03/rehearsal (${base}), and the parallel gateway running it"
  rm -rf "${ROOT}/.v03/rehearsal"
  git clone -q "$NROOT" "${ROOT}/.v03/rehearsal"
  git -C "$CHECKOUT" switch -q --detach "$base"
  gateway_env
  $GW up -d --build --force-recreate --remove-orphans
  sleep 10
  backup "$ts"
  switch "$ts"
  verify "$ts"
  rollback "$ts"
  say "after the rollback the parallel gateway is v0.2 again"
  sleep 10
  curl -fsS "${GATEWAY}/.well-known/vlei" | python -c "import json,sys
d=json.load(sys.stdin); assert 'signatureFormats' not in d, {'signatureFormats': d.get('signatureFormats')}
print('v0.2 again: no signatureFormats')"
  guard check "${ROOT}/.v03/switch/${ts}-live.txt"
  say "rehearsal complete; the live stack was not touched. Restore the parallel v0.3 gateway with: bash scripts/v03-stack.sh gateway"
}

case "${1:-}" in
  backup|switch|verify|rollback) "$1" "${2:?usage: v03-switch.sh $1 <ts>}" ;;
  rehearse)
    [[ "$TARGET" == parallel ]] || fail "rehearse runs on the parallel stack only"
    rehearse
    ;;
  *) echo "usage: [V03_TARGET=live] bash scripts/v03-switch.sh backup|switch|verify|rollback <ts> | rehearse" >&2; exit 2 ;;
esac
