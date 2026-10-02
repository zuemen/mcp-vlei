# Trust Console

The interface the demonstration is recorded on.

```bash
pip install -e packages/mcp-vlei
pip install fastapi uvicorn
python examples/console/app.py        # http://localhost:8800
```

One frame answers four questions: **who is calling, what did they bring, which layers were checked,
what happened.** Scenes 0 and 1 answer them in the same layout, so the difference between a call
believed on a self-asserted name and one carrying a credential is the only thing that moves.

## Controls

| Key | Action |
|---|---|
| `0`–`4` | Jump to a scene |
| space | Replay the current scene's reveal |
| `R` | Reset to scene 0 |
| `I` | Issue the holder a fresh ECR — after scene 4's revocation, before the next take |
| `O` | Scene 0 only: switch between the in-process measurement and the observatory's records of a real client beside a replay (`examples/observatory/`). Reads `VLEI_OBSERVATORY_URL` if set, else `VLEI_OBSERVATORY_LOG` (default `examples/observatory/data/observations.jsonl`). With nothing recorded it says so |

The `REVOKE` button under the agent card is the one thing meant to be clicked on camera: it sits in
the same frame as the card it changes, which is the proof of causality in scene 4.

`?chrome=off` hides the scene indicator — use it for the final take.

## The five scenes

Scenes 1–4 are a labour-insurance filing — **simulated, not connected to the Bureau of Labor
Insurance**, as the banner under the title says on every one of them. The employer card shows a
test unified business number, linked to the LEI by the record's `registeredAs`; the people are
fictitious (`EMP-0001`, `EMP-0003`).

| # | What it shows |
|---|---|
| 0 | A vendor granting 50 hours on a name the caller chose. No checks run, because the server it models has nothing to check |
| 1 | `enroll_employee` on the start date. Eight checks, `ALLOWED` |
| 2 | The same agent calls `adjust_insured_salary`, which requires `labor-insurance-payroll`: `REFUSED · role_mismatch` |
| 3 | `enroll_employee` fifteen days ahead; the policy allows today to today + 10: `REFUSED · scope_exceeded` |
| 4 | A valid enrolment; then `REVOKE` runs `kli vc revoke` and the call is verified again. Six checks still pass; the seventh reads the withdrawal |

With issued credentials, scenes 1–4 go through agentgateway (`deploy/agentgateway/`, :3000):
`vlei-authz` verifies with `examples/regulator/vlei-authz/policy.json`, and
`examples/regulator/labor-insurance-sim/` — which holds no vLEI code — executes. A scene whose
gateway is down says `NOT RUNNING` and names the URL; `VLEI_CONSOLE_TARGET=gateway` insists on the
gateway even in a minted world.

```bash
# root of trust from credentials/env.json
VLEI_ACCEPTED_ROOTS=$(python -c "import json;print(json.load(open('credentials/env.json'))['acceptedRoots'][0])") \
  docker compose -f deploy/agentgateway/docker-compose.yml up -d --build
```

## What is real

The right-hand column is not illustrative. Every check is run by a real verifier — `vlei-authz`
behind the gateway with issued credentials; in a minted world, the same `verify_call` in process
with the gateway's own `policy.json`, and the outcome note says `minted world` — against real key
event logs, issuances and revocations, and rendered from the `VerificationReport` that verifier
returns. The agent signs with its delegated AID's key inside
the KERI keystore (`kli sign`); the console never holds it.

The footer of the left column states what the current session is running on, and `/state` carries
the same two facts:

| | |
|---|---|
| `credentials: issued` | `scripts/bootstrap-credentials.sh` has run; the chain is the one it issued |
| `credentials: minted` | No environment; `mcp_vlei.testing.World` mints real key event logs, registries and issuances in process, behind an in-process witness. Same code path, no network |
| `signed with: keystore (kli sign)` | The agent's key never leaves the KERI keystore |
| `revocation: witness` | Read from the anchors in the issuers' key event logs, through the witnesses in `scripts/.env` |
| `revocation: in-process witness` | Minted mode: a real `rev` event in the in-process LE's log |

If the agent's credential was already revoked before the console started — the acceptance suite
revokes it — the left column says so in red and names the fix. Better on screen before a take than
discovered during one.

## Recording

`1920×1080`, browser zoom at 100%, `?chrome=off`. `scripts/record-check.sh` verifies the
preconditions; `scripts/rehearse.py` runs the scenes unattended and says whether each ends as it
should.

Nothing on screen is a credential. The cards show the first eight characters of the LEI, the role
and the status — `spec/SPEC.md` §Security Considerations, and an ECR names a natural person.

## The interactive page — `/app`

`http://localhost:8800/app` is the page a visitor operates: 中文 / English, a guided tour, one-click
scenarios, and a call you build yourself (tool, arguments, an attack). Every result is the same real
verification as the recording page — the gateway's report, read back, never decided by the page.

| Group | Scenario | Refused at |
|---|---|---|
| The problem | impersonation — a plain MCP server trusts a self-reported name | — (granted) |
| Allowed | enrol on the start date · list the insured | — |
| Refused by the rules | a filer adjusts a salary · filing fifteen days ahead | 8 authority |
| Attacks | no credential · replayed signature · tampered after signing · another key | 1 · 2 · 3 · 4 |
| Revocation | revoke (for real), send again · re-issue | 7 revocation |

`python scripts/try-app.py --out <dir> [--revoke]` operates the page in a browser and checks every
scenario in both languages. With `VLEI_PUBLIC=1` the page refuses revoke and re-issue: they change
the credential every visitor shares.
