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
| Witnesses (wan, wil, wes) | `weboftrust/keri:1.2.6` | 5642–5644 |
| vLEI schema server | `gleif/vlei:0.2.0` | 7723 |
| Verifier | `gleif/vlei-verifier:1.0.0` | 7676 |
| `kli` container (holds the keystores) | `weboftrust/keri:1.2.6` | — |

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

## Known blocker: witness endpoints (as of 2026-09-23)

`kli incept` fails at receipt collection:

```
Waiting for witness receipts...
ERR: unable to find a valid endpoint for witness BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
```

What has been established, so the next session does not re-derive it:

| Checked | Result |
|---|---|
| Witness AIDs (wan/wil/wes) | Match the hardcoded demo set — `curl localhost:5642/oobi` confirms |
| Witness reachability from the CLI container | HTTP 200 |
| `kli oobi resolve` against each witness, with and without `/controller` | Reports `resolved` |
| `kli init --config-dir` layout | keripy reads `<dir>/keri/cf/<file>.json`; the file was moved there |
| Config directory mounted read-write | Made writable; no change |
| Sharing the witness container's network namespace | Applied, so `127.0.0.1:564x` is correct from the CLI; no change |

The error fires **before** any dial: there is no location-scheme record for the witness in the
controller's database at all. Resolving the OOBI returns the witness's KEL but apparently no `rpy`
location records, so the controller never learns an endpoint to collect receipts from.

**Most likely cause.** `kli witness demo` starts witnesses from a built-in configuration whose
published location records do not survive this deployment shape. GLEIF's `vlei-trainings` does not
use `kli witness demo`; it runs `kli witness start` against explicit per-witness config files under
`keri/cf/main/`, which declare the HTTP endpoints that end up in those `rpy` records.

**Next step**, in order of cost: take the witness configuration files from
[`GLEIF-IT/vlei-trainings`](https://github.com/GLEIF-IT/vlei-trainings) and start the witnesses with
`kli witness start --name <wan|wil|wes> --alias <…>` against them, instead of `kli witness demo`.
Everything else in this script is downstream of inception and is untested only because inception has
not yet succeeded.

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
