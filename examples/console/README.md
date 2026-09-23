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
| `R` | Reset to scene 0 and clear the revocation |

The `REVOKE` button under the agent card is the one thing meant to be clicked on camera: it sits in
the same frame as the card it changes, which is the proof of causality in scene 3.

`?chrome=off` hides the scene indicator — use it for the final take.

## The six scenes

| # | What it shows |
|---|---|
| 0 | A vendor granting 50 hours on a name the caller chose. No checks run, because the server it models has nothing to check |
| 1 | The same shape of call, carrying a credential. Eight checks, `ALLOWED` |
| 2 | A client without the extension: the public tool works, the protected one stops at `missing_credential` |
| 3 | Revoke, then call again. Six checks still pass; the seventh reads the issuer's log |
| 4 | The same agent through the regulator's gateway, with an empty `git diff` |
| 5 | A server written from `skills/implementing-vlei/` |

## What is real

The right-hand column is not illustrative. Every check is run by `packages/mcp-vlei` — real SAID
recomputation, real edge walking, real Ed25519 verification — and rendered from the same
`VerificationReport` a server attaches to a refusal.

The footer of the left column states what the current session is running on, and `/state` carries
the same two facts:

| | |
|---|---|
| `credentials: issued` | `scripts/bootstrap-credentials.sh` has run; the chain is the one it issued |
| `credentials: minted` | No environment; a chain is minted locally. It verifies by the same code path, but has no witness behind it |
| `revocation: witness` | Read from the issuer's transaction event log |
| `revocation: console` | Session state. Scene 3 still demonstrates revocation; it is not evidence of one |

If the agent's credential was already revoked before the console started — the acceptance suite
revokes it — the left column says so in red and names the fix. Better on screen before a take than
discovered during one.

## Recording

`1920×1080`, browser zoom at 100%, `?chrome=off`. `scripts/record-check.sh` verifies the
preconditions; `docs/DEMO.md` has the shot-by-shot script.

Nothing on screen is a credential. The cards show the first eight characters of the LEI, the role
and the status — `spec/SPEC.md` §Security Considerations, and an ECR names a natural person.
