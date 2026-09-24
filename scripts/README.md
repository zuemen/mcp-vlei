# Credential environment

One command stands up a working vLEI trust chain:

```bash
bash scripts/bootstrap-credentials.sh
```

```
self-configured root  →  QVI  →  LE (the association)  →  ECR (regulatory-filing)  →  delegated agent AID
```

## What is real and what is ours

**Real:** KERI inception and key events, witness receipts, ACDC issuance, chained edges, TEL-based
revocation, and verification by GLEIF's own `vlei-verifier`.

**Ours:** the root of trust. We do not hold a production vLEI, so the chain terminates at an AID
this script creates, installed into the verifier through its documented
`POST /root_of_trust/{aid}` endpoint — the mechanism GLEIF provides for exactly this.

Every claim the demonstration makes holds. The trust anchor is the one thing that would differ in
production, and every artifact says so.

## Components

| Service | Image | Port |
|---|---|---|
| Witnesses (wan, wil, wes) | `weboftrust/keri:1.2.14` | 5642–5644 |
| vLEI schema server | `gleif/vlei:0.2.0` | 7723 |
| Verifier | `gleif/vlei-verifier:1.0.0` | 7676 |
| `kli` container (holds the keystores) | `weboftrust/keri:1.2.14` | — |

`gleif/vlei-verifier` publishes no `latest` tag, so the compose file pins an explicit release.

## Acceptance checks

The script's value is that these run every time, not that it produces files:

| # | Check | Expected |
|---|---|---|
| 1 | Witnesses, schema server and verifier start | all healthy |
| 2 | Four credentials issued and admitted | `credentials/` populated |
| 3 | Present the ECR credential | 202 |
| 4 | Query the holder's authorization | 200, valid |
| 5 | Revoke the ECR credential | TEL updated |
| 6 | Query again | no longer valid |

Checks 5 and 6 are the ones that matter. Anyone can issue a credential; the question a relying
party actually has is whether a withdrawal of authority propagates.

## Output

```
credentials/
├── le.cesr       the association's Legal Entity credential (chained)
├── ecr.cesr      the employee's Engagement Context Role credential (chained)
├── env.json      AIDs, SAIDs, LEI, role, accepted roots — read by the examples
└── _work/        intermediate data files, kept for inspection
```

`credentials/` is gitignored. Private keys never leave this machine.

## Recording

```bash
bash scripts/reset-demo.sh                      # clean slate; ends with READY
bash scripts/reset-demo.sh --keep-credentials   # between takes: verifier and console only
bash scripts/record-check.sh                    # preconditions; non-zero if any fail
bash scripts/demo-run.sh                        # drive the six scenes, pausing between
bash scripts/demo-run.sh --scene 3              # one scene
python scripts/rehearse.py                      # every scene, unattended; READY TO RECORD or not
python scripts/record-demo.py                   # a draft recording of the script, from the console
```

`rehearse.py` presses what the presenter presses — keys 0-5, REVOKE, `I` — in a 1920x1080 browser
and checks each scene's outcome, failure layer and evidence line against the script. It ends by
re-issuing, so the environment is left ready for a take.

`record-demo.py` records a **draft**, not the take: each scene from Chrome's own screencast, scene
3's revocation real, the credential re-issued off camera before scene 4, then H.264 at 30 fps and
joined. It cannot pace itself to a narration; it exists so the deck can be rehearsed against a real
recording and the scene lengths judged before anyone records. `--scenes 0:45,1:30,…` sets the
scenes and their lengths.

`record-check.sh` gates on the thing that actually ruins takes: **the agent's credential must not
already be revoked.** The acceptance suite revokes it, so a console started after a test run shows
`revoked` in scene 1 — the console reading the issuer's log correctly, and a reshoot. The check
reports it in seconds; discovering it mid-take costs a scene.

`demo-run.sh` drives the console over HTTP and prints each scene's verification report to the
terminal, so it works as a second screen. The console's own keyboard shortcuts still work — use
whichever suits the take. Hands on a keyboard look less staged than a terminal.

`docs/DEMO.md` has the shot-by-shot script.

## Other commands

```bash
bash scripts/bootstrap-credentials.sh --verify        # re-run checks 3-6, then re-issue
bash scripts/bootstrap-credentials.sh --reissue       # a fresh ECR after a revocation (~30 s)
bash scripts/bootstrap-credentials.sh --install-root  # the root of trust into a recreated verifier
bash scripts/bootstrap-credentials.sh --down          # remove containers and volumes
```

`--reissue` is how you re-arm the demo after a take that ends in revocation; the console's `I` key
runs it and reloads. `--install-root` exists because a recreated verifier starts with an empty
database and trusts no root: `reset-demo.sh --keep-credentials` calls it, and before it did, the
first presentation after that reset — the re-issue between takes — was rejected.

## Configuration

Override from the environment:

| Variable | Default |
|---|---|
| `LE_NAME` | Taiwan Blockchain Enthusiasts Association |
| `LE_LEI` | `984500ABCDEF12345678` (a test value — the association holds no real LEI) |
| `ECR_ROLE` | `regulatory-filing` |
| `ECR_PERSON` | Chen Wei-Ting |
| `SCHEMA_QVI` / `SCHEMA_LE` / `SCHEMA_ECR` | published WebOfTrust/vLEI schema SAIDs |

## Status, 2026-09-23

**All six acceptance checks pass on a clean run.** Real KERI, real ACDC, real verifier, real
revocation. The root of trust is self-configured; in production it would be GLEIF's.

```
Check 3 — presenting the ECR credential      ok  HTTP 202
Check 4 — the holder is authorized           ok  HTTP 200, LEI + role returned
Check 5 — revoking the ECR credential        ok  rev event written to the LE's TEL
Check 6 — the holder is no longer authorized ok  HTTP 401, "Credential revoked"
```

Check 6 returns in seconds rather than at the observer's next poll, because the script re-exports
the credential with `--include-revoked` and re-presents it: the revocation event travels in the
presentation itself. The 60-second background observer is the fallback for relying parties that
are never presented to again.

### Eight things that had to be fixed to get there

Each produced a misleading error, so each is worth keeping written down.

1. **`weboftrust/keri` ships `/keripy/scripts/keri/cf/main/*.json` as zero-byte files.** The
   witnesses then publish no `curls`, and inception fails with *"unable to find a valid endpoint
   for witness"* — which points at the witnesses rather than at their configuration.
   `scripts/witness-config/` is mounted over them.
2. **The LE schema SAID was wrong** (`…62VPxROE` instead of `…62VsDZWY`). The schema server answers
   `200` with a zero-byte body for an unknown SAID, so `kli init` aborted its whole OOBI load and
   left keystores with no witness endpoints — appearing as failure 1.
3. **ECR credentials need `--private`.** The ECR schema requires `u`, the privacy salt. An ECR
   names a natural person, and the salt is what stops one credential being correlatable across
   presentations.
4. **Rules blocks are `const`-matched per schema.** ECR requires a third disclaimer,
   `privacyDisclaimer`, whose text differs from the one used elsewhere. `rules_for()` derives them
   from the schema instead of hardcoding them.
5. **Failures 3 and 4 both surface as `'CredentialIssuer' object has no attribute '_tock'`** —
   keripy catches the validation error, returns from a half-built Doer, and the real message is
   lost. It is printed above, as `error issuing credential …`; read that, not the `ERR:` line.
6. **A delegated AID needs a `--proxy`.** It cannot deliver its own delegation request — it does
   not exist yet, so it has no key state to sign transport with. Without one the proposer exits
   immediately with *"no proxy to send messages for delegation"*, and because it runs in the
   background that message is never seen. `delegated_incept` creates `<name>-proxy` first.
7. **A QVI AID must be delegated from the root.** The verifier enforces it: *"The QVI AID must be
   delegated"*. It is right to — a QVI's authority derives from the root, so a standalone QVI AID
   would carry authority of its own.
8. **vlei-verifier 1.0.0 requires signed HTTP headers** (`SIGNATURE-INPUT`, `SIGNATURE`,
   `SIGNIFY-RESOURCE`, `SIGNIFY-TIMESTAMP`), and must be given the presenter's OOBI first
   (`POST /oobi`) or it answers *"unknown … used to sign header"*. Without this, anyone holding a
   copy of a credential could present it as their own. `keri-config/present.py` signs from the
   keystore against exactly the serialization the verifier reconstructs.

Two configuration details that are easy to lose:

- **`revocationCheck` defaults to false** and is read from the verifier's **config file only** —
  there is no environment variable. `scripts/verifier-config/` sets it true.
- **That config file must be mounted writable.** keripy's Configer opens a config file for writing
  even when it only reads it, and silently falls back to a path that does not exist.

### If a re-run behaves strangely

The verifier keeps its decisions in a database inside its container. A stale database will keep
answering `has valid login account` for a credential the current run has just revoked, because the
account it holds was established by a previous run. When in doubt, recreate everything:

```bash
docker rm -f mcp-vlei-cli mcp-vlei-verifier mcp-vlei-witness mcp-vlei-schema
docker compose -f scripts/docker-compose.yml up -d
```

`docker compose down -v` has been observed to leave containers behind on this setup, which produces
exactly this symptom, so prefer the explicit `rm -f` when a run misbehaves for no visible reason.

## If it does not run

The script is written to fail loudly at the stage that broke rather than continue into a
half-configured state. Two known sensitivities:

- **Delegated inception** is a two-sided operation — the delegate proposes and the delegator
  confirms. If stage 2b hangs, the confirm did not reach the proposer. Dropping the delegated AID is
  the documented fallback: the ECR holder's AID signs directly, `delegatedAid` is optional in the
  schema for this reason, and nothing else in the design changes.
- **Verifier API verbs** have varied across releases. The script tries `PUT /presentations/{said}`
  and falls back to `POST`; `packages/mcp-vlei/verifier.py` does the same.

If the environment cannot be made to run at all, the fallback stated in the task plan applies: a
minimal ACDC implementation, with the talk marked `simulated`. The architecture does not change —
only the honesty statement does.
