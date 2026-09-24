# Trust Console

The interface the recording is shot on. Design and rationale: [`docs/DEMO-CONSOLE.md`](../../docs/DEMO-CONSOLE.md).

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
| `0`–`5` | Jump to a scene |
| space | Replay the current scene's reveal |
| `R` | Reset to scene 0 |
| `I` | Issue the holder a fresh ECR — after scene 3's revocation, before scene 4 |

The `REVOKE` button under the agent card is the one thing meant to be clicked on camera: it sits in
the same frame as the card it changes, which is the proof of causality in scene 3.

`?chrome=off` hides the scene indicator — use it for the final take.

## The six scenes

| # | What it shows |
|---|---|
| 0 | A vendor granting 50 hours on a name the caller chose. No checks run, because the server it models has nothing to check |
| 1 | The same shape of call, carrying a credential. Eight checks, `ALLOWED` |
| 2 | A client without the extension: the public tool works, the protected one stops at `missing_credential` |
| 3 | A valid call; then `REVOKE` runs `kli vc revoke` and the call is verified again. Six checks still pass; the seventh reads the issuer's log |
| 4 | The same call sent through agentgateway (`deploy/agentgateway/`, :3000): `vlei-authz` verifies, a filing server with no vLEI code executes |
| 5 | The same call sent to `examples/skill-server/` (:8082), written from `skills/implementing-vlei/` alone |

Scenes 4 and 5 need their servers running; a scene whose server is down says `NOT RUNNING` and
names the URL.

```bash
# scene 4 — root of trust from credentials/env.json
VLEI_ACCEPTED_ROOTS=$(python -c "import json;print(json.load(open('credentials/env.json'))['acceptedRoots'][0])") \
  docker compose -f deploy/agentgateway/docker-compose.yml up -d
# scene 5
VLEI_LE_CREDENTIAL=credentials/le.cesr VLEI_ACCEPTED_ROOTS=<same root> \
  VLEI_WITNESS_URL=http://localhost:15642 python examples/skill-server/server.py
```

## What is real

The right-hand column is not illustrative. Every check is run by a real verifier — the extension
in process for scenes 1–3, `vlei-authz` behind the gateway for scene 4, the skill-generated server
for scene 5 — against real key event logs, issuances and transaction event logs, and rendered from
the `VerificationReport` that verifier returns. The agent signs with its delegated AID's key inside
the KERI keystore (`kli sign`); the console never holds it.

The footer of the left column states what the current session is running on, and `/state` carries
the same two facts:

| | |
|---|---|
| `credentials: issued` | `scripts/bootstrap-credentials.sh` has run; the chain is the one it issued |
| `credentials: minted` | No environment; `mcp_vlei.testing.World` mints real key event logs, registries and issuances in process, behind an in-process witness. Same code path, no network |
| `signed with: keystore (kli sign)` | The agent's key never leaves the KERI keystore |
| `revocation: witness` | Read from the issuers' transaction event logs at the witness in `scripts/.env` |
| `revocation: in-process witness` | Minted mode: a real `rev` event in the in-process LE's log |

If the agent's credential was already revoked before the console started — the acceptance suite
revokes it — the left column says so in red and names the fix. Better on screen before a take than
discovered during one.

## Recording

`1920×1080`, browser zoom at 100%, `?chrome=off`. `scripts/record-check.sh` verifies the
preconditions; `docs/DEMO.md` has the shot-by-shot script.

Nothing on screen is a credential. The cards show the first eight characters of the LEI, the role
and the status — `spec/SPEC.md` §Security Considerations, and an ECR names a natural person.
