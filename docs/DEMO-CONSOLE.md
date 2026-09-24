# Trust Console — design specification

The console at `examples/console/` exists to be filmed. `examples/association-server/dashboard/` is
a record of decisions, which is right for debugging and wrong for a camera: it shows what happened
after the fact, one row at a time, and a viewer has to assemble the story themselves.

A recording needs one frame that answers four questions at once — **who is calling, what did they
bring, which layers were checked, and what happened** — and it needs scene 0 and scene 1 to answer
them in the same visual language, so the difference between them is the only thing that moves.

## Layout

1920 × 1080, the recording's native resolution. Three fixed columns; deliberately not responsive,
because there is exactly one size.

```
┌──────────────────────────────────────────────────────────────────┐
│  MCP × vLEI Trust Console          ● live    Scene 3 / 6         │  72px
├───────────────────┬──────────────────────────┬───────────────────┤
│  IDENTITIES       │  REQUEST                 │  VERIFICATION     │
│  420px            │  860px                   │  640px            │
│                   │                          │                   │
│  server card      │  tools/call              │  ① credential  ✓  │
│  agent card       │  submit_filing           │  … eight checks   │
│  [ REVOKE ]       │  syntax-coloured JSON    │  outcome banner   │
├───────────────────┴──────────────────────────┴───────────────────┤
│  LOG   10:02:13 verified · 10:02:47 revoked · 10:02:51 refused   │  96px
└──────────────────────────────────────────────────────────────────┘
```

## Palette

Light, to match the deck and because a dark panel washes out under a projector in a lit room.

| Use | Hex |
|---|---|
| Background | `#F7F5EF` |
| Panel | `#FFFFFF` |
| Primary text | `#1B2330` |
| Secondary text | `#5B6472` |
| Muted | `#8A93A0` |
| Pass / primary | `#2E5D89` |
| Fail / emphasis | `#C0392B` |
| Code background | `#EFEDE6` |
| Rule | `#D8D3C8` |

## Type

| Element | Size | Weight |
|---|---|---|
| Header title | 28px | 600 |
| Column heading | 15px | 600, 0.08em tracking, uppercase |
| Credential card primary | 20px | 600 |
| JSON | 17px | 400, monospace |
| Check row | 19px | 500 |
| Outcome banner | 34px | 700 |
| Log | 14px | 400 |

17px monospace stays legible after 1080p scaling. Nothing smaller.

## Behaviour

### Identities

Two cards, styled as credentials: 12px radius, 1px border, a 4px status bar down the left edge.

| Status | Bar | Marker |
|---|---|---|
| valid | `#2E5D89` | ● valid |
| unverified | `#8A93A0` | ● not presented |
| revoked | `#C0392B` | ● revoked, card at 0.6 opacity |

Cards show the role (SERVER / AGENT), the credential type (LE / ECR), the first eight characters of
the LEI, the role name and the status. **Never the credential itself** — `spec/SPEC.md`
§Security Considerations, and an ECR names a natural person.

`REVOKE` sits under the agent card: `#C0392B` outline on white. Pressing it reads `revoking…`, then
the card turns red and gains a timestamp. **The button and the card must be in the same frame** —
that adjacency is the proof of causality in scene 3.

### Request

The call's JSON, syntax-coloured.

- The four `org.gleif.vlei/*` keys: `#C0392B` on `rgba(192,57,43,.06)`
- Everything else: normal
- Credential and signature values truncated to 18 characters and an ellipsis
- **Scene 0** shows only `clientInfo`, with a `#8A93A0` note beneath:
  `self-asserted · not verified by the protocol`

### Verification

Eight rows, lighting in sequence.

| State | Rendering |
|---|---|
| pending | `#8A93A0`, `–` |
| running | `#2E5D89`, 2px progress bar on the left |
| pass | `#2E5D89`, `✓`, elapsed ms at the right |
| fail | `#C0392B`, `✗`, the failure layer beneath |
| skipped | `#D8D3C8`, `–` (everything after a failure) |

**280ms between rows.** Faster is unreadable; slower wastes the clock. On failure the remaining
rows become skipped immediately rather than continuing.

Outcome banner:

- pass: `#2E5D89`, white, `ALLOWED`
- fail: `#C0392B`, white, `REFUSED · <layer>`
- scene 0: `#8A93A0`, `GRANTED ON SELF-ASSERTION` — the wording is meant to be uncomfortable

### Log

One line, at most six entries, `HH:MM:SS · event`. **No scroll animation** — it shakes on camera.

## Scene control

`Scene N / 6` at the top right. Two ways to drive it:

1. Keyboard: `0`–`5` to jump, space to replay the current scene, `I` to issue a fresh ECR after
   scene 3's revocation
2. HTTP: `POST /scene/{n}`, for `scripts/demo-run.sh`

Use the keyboard when recording: hands on a keyboard look less staged than switching to a terminal.

`?chrome=off` hides the scene indicator, for the final take.

## The six scenes

| # | Scene | Identities | Request | Verification | Seconds |
|---|---|---|---|---|---|
| 0 | Impersonation | both `not presented` | only `clientInfo: Claude Desktop` | no checks run; `GRANTED ON SELF-ASSERTION`, 50 hours approved | 45 |
| 1 | A verified call | both valid | four keys highlighted | eight pass → `ALLOWED` | 45 |
| 2 | Client without the extension | server valid, agent `not presented` | only `clientInfo` | check 0 fails → `REFUSED · missing_credential`; the public tool still succeeds | 40 |
| 3 | Revocation | valid; press `REVOKE` (a real `kli vc revoke`), agent turns red | as scene 1 | eight pass; after the revocation six pass, seventh fails → `REFUSED · revoked` | 45 |
| 4 | Through the gateway | server card becomes the regulator's LE | as scene 1, sent to agentgateway on :3000 | eight pass in `vlei-authz` → `ALLOWED`, with the measured `git diff` below | 40 |
| 5 | A server written from the skill | server card annotated `generated from skill` | as scene 1, sent to `examples/skill-server` on :8082 | eight pass in that server → `ALLOWED` | 30 |

A scene whose server is not running shows `NOT RUNNING` and names the URL. It never falls back to
verifying in the console.

**Scenes 0 and 1 are the most important thirty seconds of the recording.** Same interface, same
layout; the only differences are whether the request carries four keys and whether the right-hand
column has anything to run.

## Rules that are not style preferences

- Verification results come from `packages/mcp-vlei`'s real flow (`VerificationReport`). Nothing on
  the right-hand column is written by hand. A console that fakes its own output would make every
  other claim in the talk worth less.
- Transitions are CSS, 200–300ms, no bounce or scale. Motion that draws attention to itself competes
  with the thing being explained.
- No credential content on screen, ever.
- One HTML file, one CSS file, one JS file, no bundler and no CDN. A conference network is not a
  dependency worth having.
