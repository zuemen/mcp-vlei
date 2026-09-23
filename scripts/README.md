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

Checks 1-5 pass on a clean run. Check 6 does not yet.

### Verified working, end to end

| Check | Result |
|---|---|
| 1 — witnesses, schema server, verifier start | healthy |
| 2 — credential chain issued | root → QVI → LE → ECR, with edges and an agent delegated AID |
| 3 — present the ECR credential | **HTTP 202** |
| 4 — query the holder's authorization | **HTTP 200**, `has valid login account`, with LEI and role |
| 5 — revoke the ECR credential | `rev` event written to the LE's TEL and served by the witness |
| 6 — the holder is no longer authorized | **still reports valid** — see below |

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
   `privacyDisclaimer`, whose text differs from the one used elsewhere. `rules_for()` now derives
   them from the schema instead of hardcoding them.
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

### Check 6: revocation does not propagate yet

The revocation itself is real — the `rev` event is in the LE's TEL and the witness serves it:

```bash
curl "http://localhost:5642/query?typ=tel&vcid=<ecr-said>"   # returns the rev event
```

What has not been made to work is the verifier noticing. Detection is **asynchronous**: a
background observer polls `{witness_url}/query?typ=tel&vcid={said}` for every credential it holds,
on a 60-second interval, and `witness_url` comes from a query parameter on the presentation.

Established so far:

- `revocationCheck` defaults to **false** and is read from the **config file only** — there is no
  environment variable. `scripts/verifier-config/` now sets it true, and the container confirms
  `revocationCheck=True` at startup.
- That config file must be mounted **writable**: keripy's Configer opens a config file for writing
  even when it only reads it, and silently falls back to a path that does not exist.
- The presentation passes `?witness_url=http://witness-demo:5642`. The signature covers `@path`,
  which falcon reports without the query string, so the parameter does not disturb signing.
- Check 6 re-exports with `--include-revoked` and re-presents before polling, and polls for up to
  `REVOCATION_WAIT` (default 150s).

Even so the account stays valid, and the observer logs nothing — neither a successful poll nor the
"Witness … is unavailable" it would print on failure. **The next thing to determine is whether the
observer is running at all**: `start.py` only adds `CredentialRevocationChecker` to its doers when
`revocationCheck` is true at startup, so confirm the doer is in the loop before looking any further
at witness URLs or TEL contents.

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
