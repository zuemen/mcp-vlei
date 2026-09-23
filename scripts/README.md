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

## Other commands

```bash
bash scripts/bootstrap-credentials.sh --verify   # re-run checks 3-6 only
bash scripts/bootstrap-credentials.sh --down     # remove containers and volumes
```

`--verify` is how you re-arm the demo: after a recording take that ends in revocation, re-issue and
confirm the chain is live again before the next take.

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

Most of the chain now runs. What follows is what has actually been observed, so the next session
starts from evidence rather than from guesses.

### Verified working

| Step | Evidence |
|---|---|
| Witness receipting | Inception completes; `Prefix ...` printed with receipts collected |
| Root, LE, ECR inception | Four controllers created with witnessed KELs |
| Agent delegated AID under the ECR holder | Completed in one run: `agent (delegated) = EKo7EPKx…` |
| Credential chain: QVI -> LE -> ECR | All three issued, with edges and SAIDs |
| CESR export | `credentials/le.cesr`, `credentials/ecr.cesr` written with `--full` |
| Root of trust installed | `POST /root_of_trust/{aid}` -> HTTP 202 |
| Signed presentation | `PUT /presentations/{said}` -> **HTTP 202**, verifier returned the parsed credential |
| Authorization query | Answers with a reasoned verdict (see below) |

### Six things that had to be fixed to get there

Each produced a misleading error, so each is worth keeping written down.

1. **`weboftrust/keri` ships `/keripy/scripts/keri/cf/main/*.json` as zero-byte files.** The
   witnesses then publish no `curls`, and inception fails with *"unable to find a valid endpoint
   for witness"* — which points at the witnesses rather than at their configuration.
   `scripts/witness-config/` is mounted over them.
2. **The LE schema SAID was wrong** (`…62VPxROE` instead of `…62VsDZWY`). The schema server answers
   `200` with a zero-byte body for an unknown SAID, so `kli init` aborted its whole OOBI load and
   left keystores with no witness endpoints — appearing as failure 1.
3. **ECR credentials need `--private`.** The ECR schema requires `u`, the privacy salt, at the top
   level. An ECR names a natural person, and the salt is what stops one credential being
   correlatable across presentations.
4. **Rules blocks are `const`-matched per schema.** ECR requires a third disclaimer,
   `privacyDisclaimer`, whose text differs from the one used elsewhere. The script now derives
   rules from the schema instead of hardcoding them.
5. **Any of the above surfaces as `'CredentialIssuer' object has no attribute '_tock'`** — keripy
   catches the validation error, returns from a half-built Doer, and the real message is lost. The
   underlying error is printed above it as `error issuing credential …`; read that, not the `ERR:`
   line.
6. **vlei-verifier 1.0.0 requires signed HTTP headers** (`SIGNATURE-INPUT`, `SIGNATURE`,
   `SIGNIFY-RESOURCE`, `SIGNIFY-TIMESTAMP`), and it must be given the presenter's OOBI first
   (`POST /oobi`) or it answers *"unknown … used to sign header"*. `keri-config/present.py` signs
   from the keystore, against exactly the serialization the verifier reconstructs.

### The remaining blocker

`delegated_incept qvi root` fails: the proposer exits before the first confirm attempt.

This became necessary once presentation worked, because the verifier rejects the chain with:

> ECR chain validation failed, LE chain validation failed, **The QVI AID must be delegated**

That is the verifier correctly enforcing an ecosystem rule — a QVI's authority derives from the
root, so a standalone QVI AID would have authority of its own. The same delegation machinery
**does** work for the agent under the ECR holder, so the mechanism is sound; something about doing
it for `qvi` under `root`, as the first delegation in a fresh environment, is not.

Ruled out: the delegator's OOBI is generated and resolves (`… resolved`), the delegator's KEL is
reachable, witnesses receipt normally, and `kli delegate confirm` takes the documented flags. The
one observed proposer error, when the OOBI step is skipped, is *"delegator … not found, unable to
process delegation"* — so the next thing to check is whether the resolved contact is actually
usable by the delegation code, rather than merely present.

**Next step:** run the delegated inception by hand with the proposer in the foreground, so its
error is visible instead of being swallowed by the background job:

```bash
docker compose -f scripts/docker-compose.yml exec keri-cli sh -c '
  kli incept --name qvi --alias qvi --file /keri-config/incept-witnesses.json --delpre <root-aid>'
# and in a second shell:
docker compose -f scripts/docker-compose.yml exec keri-cli sh -c '
  kli delegate confirm --name root --alias root --interact --auto'
```

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
