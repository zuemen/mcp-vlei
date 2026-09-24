# Talk and Recording — 15 minutes, English

**Audience:** GLEIF, AAIF, government officials.
**Register:** neutral and factual throughout. This is an applicability boundary and a proposed
extension, not a disclosure.

## Timing, slide by slide

Spoken words at 130 a minute, stage directions excluded; the recording counted at its length. Total **13:46** — the limit is 14:30, leaving the rest of the slot for questions.

| Slide | Heading | Words | Seconds | Running |
|---|---|---|---|---|
| 1 | Title | 25 | 12 | 0:11 |
| 2 | What MCP verifies | 81 | 37 | 0:48 |
| 3 | The measurement | 68 | 31 | 1:20 |
| 4 | The agent is absent from the protocol | 42 | 19 | 1:39 |
| 5 | This is a boundary, not a defect | 77 | 36 | 2:15 |
| 6 | Why now | 28 | 13 | 2:28 |
| 7 | GLEIF already solved the identity half | 44 | 20 | 2:48 |
| 8 | Why ECR and not OOR | 36 | 17 | 3:05 |
| 9 | What we added: the schema | 71 | 33 | 3:37 |
| 10 | What we added: verification | 119 | 55 | 4:32 |
| 11 | Three things the paper design did not predict | 59 | 27 | 5:00 |
| 12 | Every requirement, traced | 118 | 54 | 5:54 |
| 13 | Demo | 88 + video 2:50 | 211 | 9:25 |
| 14 | Taiwan already runs this model | 133 | 61 | 10:26 |
| 15 | Two ways to check an identity | 91 | 42 | 11:08 |
| 16 | Six stages, one of which touches IT | 82 | 38 | 11:46 |
| 17 | What an institution gets | 51 | 24 | 12:09 |
| 18 | Limits | 71 | 33 | 12:42 |
| 19 | Three requests | 96 | 44 | 13:26 |
| 20 | Artifacts | 43 | 20 | 13:46 |

## Fixed vocabulary

Used consistently in the slides, the script, and every answer in Q&A:

- **Host** = the AI application. **Client** = the connection component inside the host.
  **Server** = the tool provider.
- **OAuth verifies the user (`sub`) and the client software (`client_id`)** — not the agent inside
  it, and not a legal entity.
- **`clientInfo` MUST NOT be used as a basis for trust.** This is a scoping statement about one
  self-asserted field. It is *not* zero trust: TLS and OAuth still verify.
- **ECR, not OOR.** An agent mandate is an engagement context, not a public office.

Three formulations to avoid, each of which an expert in the room will catch:

| Do not say | Say |
|---|---|
| "OAuth only recognizes Claude Desktop" | "OAuth verifies the user and the client software; it does not verify which agent is acting, and does not bind either to a legal entity" |
| "The spec says don't trust each other" | "The spec says `clientInfo`/`serverInfo` must not be used for trust decisions; other layers still verify" |
| "MCP has a vulnerability" | "MCP has an applicability boundary: its trust model assumes a human in the loop" |

## Time allocation

| Minutes | Section | Landing point |
|---|---|---|
| 0–2¼ | The problem | Every layer proves domain control or a human user. The agent is absent from the protocol |
| 2¼–2½ | Why now | Autonomous execution × actions with legal effect × across organizations |
| 2½–3 | What GLEIF already solved | LE, ECR, revocation, offline verification — and why ECR, not OOR |
| 3–6 | What we added | The schema, verification, what building it taught us, every requirement traced |
| 6–9½ | Demo recording | Five scenes, 2:50 |
| 9½–12¾ | Government | Taiwan, two verification modes, six stages, what an institution gets, limits |
| 12¾–13¾ | Three requests | Government, GLEIF, AAIF — then the artifacts |

Rehearse to 13:45; 14:30 is the limit. If questions come out of the same fifteen minutes, cut slide
15 to its first two sentences and slide 10 to its last paragraph first.

## The honesty statement

On a slide **and** spoken, at the start of the demo section, and again on the last slide:

> "Real KERI, real ACDC, real revocation. The root of trust is self-configured; in production it
> would be GLEIF's."

Said before the demo, not after. Afterwards it sounds like a caveat being extracted; first, it is a
specification of what is being shown.

---
---

# Recording script — 2:50, five scenes

Everything happens in one interface: `examples/console/`, the Trust Console. No terminal, no window
switching. Scenes 0 and 1 use the same layout, so the difference between a call believed on a name
and one carrying a credential is the only thing that moves — **that comparison is the most
important thirty seconds of the recording.**

Recorded rather than live: the demo depends on a witness network and a revocation round trip, and a
15-minute slot has no room to recover from a cold container. Narrate live over the recording so it
stays a talk rather than a video.

## Before the camera

```bash
bash scripts/reset-demo.sh          # ends with READY, or says why not
bash scripts/record-check.sh        # run again immediately before the take
```

`record-check.sh` gates on the thing that actually ruins takes: **the agent's credential must not
already be revoked.** The acceptance suite revokes it, so a console started after a test run shows
`revoked` in scene 1 — the console being right, and a reshoot.

- Browser at **1920×1080**, zoom **100%**, opened at `http://localhost:8800/?chrome=off`
- Notifications off, do-not-disturb on
- Bookmarks bar hidden, dock hidden
- Nothing else on the screen — the console fills it exactly

---

## Scene 0 — Impersonation (45s)

**Proves:** the problem is real, and measured rather than argued.

**Do:** press `0`.

**On screen.** Both credential cards grey, `● not presented`. The middle column shows only
`clientInfo`, with `self-asserted · not verified by the protocol` beneath it. The right column runs
nothing. The banner is grey: **GRANTED ON SELF-ASSERTION**, with *approved 50 hours on a name the
caller chose*.

**Narration.**
> "A vendor's server gives partner-tier quota to callers it recognises. We asked it for fifty GPU
> hours three times from the same binary, changing only the name the client gave.
>
> Honest: one hour. Claiming to be a well-known client: fifty. Omitting the name: one — the SDK
> sends a default, so you cannot even decline to identify yourself.
>
> The specification says this field must not be used for security, and it is right. The point is
> that nothing in the protocol can tell the difference. Look at the right-hand column: there is
> nothing to check."

**Land on:** the empty verification column beside the grey banner.

---

## Scene 1 — A verified call (30s)

**Proves:** the mechanism works, and what it costs.

**Do:** press `1`.

**On screen.** Both cards blue, `● valid`. The middle column now carries four keys picked out in
red. The right column lights eight rows in sequence, each with its elapsed time. Blue banner:
**ALLOWED**.

**Narration.**
> "Same interface, same call — now carrying the credential, the agent's delegated identifier and a
> signature. Eight checks: what the request alone settles; the signature, under the signer's current
> key read from a witness, never from the request; the signer is the holder or their agent; every
> issuance anchored in its issuer's log; revocation; the role. Allowed."

**Land on:** eight blue rows and `ALLOWED`, with the LEI and role on the cards.

---

## Scene 2 — A client without the extension (20s)

**Proves:** additive. Adoption costs nothing to those who have not adopted.

**Do:** press `2`.

**On screen.** Server card blue; agent card grey, `● not presented`. Middle column shows only
`clientInfo`. The first check fails red — `missing_credential` — and the remaining seven go pale:
skipped, not still to come.

**Narration.**
> "An ordinary client with none of this. It connects, sees every tool, and the public tool works.
> The protected one stops at the first check — unverified, not refused: it never made a claim.
> Nothing broke."

**Land on:** the pale skipped rows — the sequence stopped, it did not fail seven times.

---

## Scene 3 — Revocation (45s)

**Proves:** the thing MCP cannot do today. This is the high point.

**Do:** press `3` — the same call as scene 1, eight rows pass. Then click **REVOKE** on the agent
card. The console runs `kli vc revoke` and verifies the same call again as soon as the witness
serves the withdrawal (about seven seconds; nothing is set by the console).

**On screen.** The button reads `revoking…`, then the agent card turns red at 0.6 opacity with a
timestamp. On the re-run, six rows go blue, the seventh red — `revoked` — and the eighth pale.

**After the take, before scene 4 (cut here):** press `I`. The legal entity issues the holder a fresh
ECR (about 25 seconds). Without it, scenes 4 and 5 are — correctly — refused `revoked`, and the
left column says so in red.

**Narration.**
> "First, the same call: allowed. Now the legal entity withdraws the credential — a real revocation,
> written to its transaction event log, not a flag in a database.
>
> Same agent, same call, same key. Read the report, not the verdict: the signature still verifies,
> the arguments still match, the chain still holds. Six checks pass. The seventh reads the issuer's
> log and finds the withdrawal.
>
> Not 'access denied' — six things still true and one that stopped being true. And the agent knows
> not to retry."

**Land on:** the six blue rows above the one red one.

---

## Scene 4 — Through the gateway (30s)

**Proves:** an institution adopts this without modifying its systems.

**Do:** press `4`.

**On screen.** The server card is now the regulator's LE. Eight rows pass — run by `vlei-authz`
behind agentgateway, not by the console. Below the banner, the output of an actual
`git diff HEAD -- examples/my-agent/`: none.

**Narration.**
> "Same agent, one environment variable: it now files with a regulator. The diff on the agent is
> empty. The regulator's filing server does no verification — it reads headers a gateway sets: the
> LEI, the role, the holder, the agent. Which entity is filing is not a parameter of the call; it
> comes from the verified credential."

**Land on:** the empty diff beside the passing checks.

---

## Scene 5 — cut

Not recorded. Its point — a server written from the skill alone, running, and the hole it found in ours — is one sentence on slide 12, where the conformance story already is.

---

## Recording rules

- **One take per scene, no cuts within a scene.** Cuts between scenes are fine.
- **Normal speed.** No time-lapse. The 280ms between check rows is deliberate; speeding it up
  destroys the thing the column is for.
- **No music.** Narration is live at the talk; the file has no audio track.
- **Keep the timestamps visible.** They are evidence that scene 3 happened when it appears to.
- **Record at least three times and use the smoothest.** Budget an hour for what is four minutes of
  footage.

## Output

| | |
|---|---|
| Resolution | 1920×1080, 30fps |
| Codec | H.264, 8–12 Mbps |
| Audio | none — narrated live |
| Also export | one PNG per scene, full-frame, as the fallback |

```
demo-full.mp4          4:05, all six scenes
demo-scene0.mp4        0:45, for the problem section
stills/scene-0.png …   six frames
```

The recordings are **not kept in the repository** — there is no `docs/media/`. They live on the
presenting machine, beside the deck (see below). No ignore rule covers them yet — `docs/slides/.gitignore`
excludes only `render/` — so if they sit next to `docs/slides/mcp-vlei.pptx` in a working tree, do
not `git add` them.

## Embedding in the deck

- `python scripts/build-deck.py --video docs/slides/demo-full.mp4` embeds it — embedded, not
  linked, so it survives being moved to another machine — set to play full screen; with PowerPoint
  installed it also sets **Start automatically** and no rewind, and prints what it read back. Open
  the file in PowerPoint once anyway and play slide 13 through.
- Keep `demo-full.mp4` beside the `.pptx`, and keep relative paths, in case the embed has to be
  redone on the conference machine.
- **Fallback:** six stills and the same narration. Rehearse it once. A projector that will not play
  video is a normal event, not a disaster, and the six frames carry the whole argument.

Slide 3 (the problem) uses `demo-scene0.mp4` — 45 seconds, so the problem section has a picture.
Slide 13 (Demo) uses the full file; until it is embedded, the frame shows the still of scene 3. Same interface in both places, so nobody has to learn the layout
twice.

---
---

# Slides

Twenty slides, fourteen minutes and thirty seconds at most, video included. Notes are what to say, not what is on the slide.

The deck is **generated from this section** — `scripts/build-deck.py` carries each slide's layout
and reads these block quotes into its speaker notes at build time; a stage direction on its own line
becomes a bracketed note. The build stops if a heading here does not match the slide at that
position. Edit the talk here, then:

```bash
python scripts/capture-console.py                              # the console stills the deck uses
python scripts/build-deck.py --render                          # -> docs/slides/mcp-vlei.pptx
python scripts/build-deck.py --video docs/slides/demo-full.mp4 # once the recording exists
```

Native PowerPoint, real text boxes and tables, editable on the machine that meets the projector.

### 1 — Title

**Slide.** Organizational Identity for MCP Agents · vLEI × Model Context Protocol · `mcp-vlei`

> "Fifteen minutes on one question: when an agent calls a tool across an organizational boundary,
> who is accountable, and how does the other side check?"

---

### 2 — What MCP verifies

**Slide.** The five-row table: TLS, OAuth `iss`, OAuth `client_id`, OAuth `sub`, `clientInfo` — what
each proves, what each does not.

> "MCP inherits a well-specified authentication stack. Every layer answers a real question. TLS
> proves control of a domain name. The OAuth issuer identifies the authorization server. The client
> ID proves control of the URL serving the client metadata. The subject identifies the human user.
>
> Read the right-hand column. Domain control, domain control, domain control, human user. No layer
> expresses a legal entity, and the specification is explicit that `clientInfo` must not be used for
> security decisions — correctly, because nothing backs it."

---

### 3 — The measurement

**Slide.** The three runs, one variable — the name the server received: honest `zuemen-script` 1h ·
`Claude Desktop` 50h · omitted (the SDK sends `mcp`) 1h — beside the console's scene 0.
**Video:** `demo-scene0.mp4`, 45 seconds.

> "We measured it rather than asserting it. One binary, one server, fifty hours requested three
> times, changing only what the client said its name was.
>
> The server's policy deliberately violates the specification — that is the experiment, not a
> recommendation. What it establishes is that no layer of the stack can tell the three runs apart.
>
> The code is in the repository. Nothing was run against anyone else's service."

---

### 4 — The agent is absent from the protocol

**Slide.** `schema.ts`, 2026-07-28, 3197 lines. `agent` 0 · `principal` 0 · `delegation` 0 ·
`mandate` 0.

> "The protocol models a host, a client, and a server. The thing that decides to invoke a tool has
> no representation — so it cannot be named, delegated to, constrained, or revoked at the protocol
> layer, because there is nothing there to name."

---

### 5 — This is a boundary, not a defect

**Slide.** "MCP's trust model assumes a human in the loop" — stated in the Tools chapter's warning
box. NSA, May 2026. Security IG `server-identity` proposals root in domain / DNS / registry.

> "Under that premise, self-asserted metadata is harmless: a person is accountable at the point of
> action. When the agent executes autonomously, the premise no longer holds, and the layer carrying
> accountability is simply not present.
>
> Everyone has noticed. The published server-identity proposals all root trust in a domain, DNS, or
> a registry. Those answer 'which deployment is this'. None answers 'which legal entity is this',
> and none is revocable by an authority the counterparty's regulator also recognizes."

---

### 6 — Why now

**Slide.** Autonomous execution × actions with legal effect × across organizations.
NSA, May 2026: *MCP does not define how a session maps to a verifiable identity.*

> "Any one alone is survivable. Together they are not: an agent acting without review, on something
> that binds its organization, against a counterparty that has never met it."

---

### 7 — GLEIF already solved the identity half

**Slide.** LE → ECR, chained ACDCs, revocable, offline-verifiable, anchored in KERI.

> "This is not a proposal for a new identity system. The Legal Entity credential binds an identifier
> to an LEI. The Engagement Context Role credential binds a person's identifier to a role within
> that entity. Both are chained ACDCs, both revocable, both verifiable offline."

---

### 8 — Why ECR and not OOR

**Slide.** OOR = public office, controlled vocabulary, GLEIF-validated · ECR = engagement context,
entity-defined vocabulary.

> "An agent's mandate — 'may file regulatory returns up to this amount' — is an engagement context,
> not a public office. ECR is the correct credential type, and the vocabulary belongs to the entity
> that defines the engagement."

---

### 9 — What we added: the schema

**Slide.**

```
capabilities.extensions["org.gleif.vlei/identity"]  →  presents / requires / acceptedRoots / ttlMs
params._meta  →  org.gleif.vlei/credential
                 org.gleif.vlei/credentialSaid
                 org.gleif.vlei/delegatedAid
                 org.gleif.vlei/signature
Tool._meta    →  org.gleif.vlei/requires { credential, role, scope }
```

**Footer:** *Four keys in `_meta`. Nothing in core changes.*

> "Everything travels in fields MCP already reserves for extensions, so a party that does not
> understand them behaves exactly as core MCP specifies.
>
> The last line is the one I would point at. The permission is declared in the schema the client
> already reads, so an agent can determine *before* calling whether it is entitled — and decline in
> terms a user understands, instead of attempting the call and interpreting a rejection.
"

---

### 10 — What we added: verification

**Slide.** Eight checks in order, each with where it is decided — credential presented · freshness ·
digest · signature · delegation · chain · revocation · authority — beside the console's scene 1, and
nine failure layers. Two checks read from a witness: the
signature (the signer's current key state) and revocation. Authority is last.

**Footer:** *Eight checks. The verifier decides; nothing else does.*

> "Eight checks, and the order is the design. The first three are decided from the request itself,
> before anything is fetched. Two read from a witness: the signer's current key, and the issuers'
> logs for revocation. A witness that is slow or down then costs you those checks, never the ones
> before them — a tampered request is refused as tampered, not as a timeout.
>
> Nine failure layers, and the correct response differs for each. A stale signature is retried once.
> `revoked` means stop and tell the user a new credential is needed. `unknown_root` means two
> organizations disagree about whom they trust and only they can fix it. An agent that receives
> 'access denied' can do none of that."

---

### 11 — Three things the paper design did not predict

**Slide.**
1. Presentation is the **holder's** step → a counterparty's credential must be verified locally
2. Ask about the **issuee**, not the signer
3. Protocol version negotiation decides whether extensions exist at all

> "Three things cost us days; I will name two, because a second implementer would otherwise pay for
> them again. Presentation is the holder's step: a relying party cannot hand someone else's
> credential to a service and ask about it, so it verifies the chain itself — that one fact shapes
> every deployment. And ask about the issuee, never the signer."

---

### 12 — Every requirement, traced

**Slide.** `docs/CONFORMANCE.md` — twenty-two normative statements, each with its implementation and
its test. Three rows added during the review. A section listing what is **not** claimed.

> "Every MUST and SHOULD in our specification has a row: the code that implements it and the test
> that holds it.
>
> A review found something worse than a missing row, and I would rather tell you than have you find
> it: our verifier checked the request signature under a key the request itself carried. Every test
> passed, because every test signed with the right key. It now reads the key from the signer's own
> log, and the tests that would have caught it fail against the old code.
>
> And a server written by a fresh model from our skill alone found one more gap in ours: nothing
> tied an ECR's LEI to its legal entity. Both are fixed."

---

### 13 — Demo

**Slide.** The recording, 16:9, about four fifths of the width — the still of scene 3 until it is
embedded — and under it the honesty statement: *Real KERI, real ACDC, real revocation. The root of
trust is self-configured; in production it would be GLEIF's.*

> "Everything you are about to see is real KERI and real ACDCs, issued through GLEIF's own schemas,
> with a revocation read from the issuer's transaction event log. The one thing I control is the
> root of trust, because I do not have a production vLEI. In production the chain terminates at
> GLEIF's root.
>
> One more thing while this slide is up. We did use GLEIF's verifier, and we found a defect in its
> revocation path that takes the service down. It is written up and ready to file."

*(Play `demo-full.mp4`, 2:50.)*

---

### 14 — Taiwan already runs this model

**Slide.** Two columns — Taiwan today and this proposal: holder (people, through the Digital Identity
Wallet 數位憑證皮夾; companies, through the MOEA business certificate 工商憑證 · legal entities and the
agents acting for them), delegation (to employees, through the certificate's attached card 附卡 —
per site and time limit announced for the phone · to an agent, a delegated identifier under the ECR
holder), identifier (統一編號 · LEI, whose record for a Taiwanese entity carries the 統一編號), reach
(domestic, over 180 G2B and B2B systems · verifiable abroad, back to GLEIF — ISO 17442-3:2024),
built on (X.509 for the certificate, OpenID4VC and SD-JWT VC for the wallet · KERI, ACDC).

**Footer:** *Taiwan already delegates a company's authority to its people. What it does not yet do is
delegate it to an agent, or make it verifiable abroad.*

> "Taiwan already runs this model — for people. The Digital Identity Wallet lets a person show only
> what a counter needs to see. And the MOEA business certificate already lets a company hand its
> authority to an employee, through an attached card; the ministry has announced the same on the
> phone, per site and per time limit.
>
> What neither does is the holder on the right: an agent acting for the entity. The certificate's
> own practice statement marks authenticating server software 'not applicable'. And it is domestic
> by design — but a Taiwanese company's LEI record already carries its unified business number, so
> the two meet at the same number. The Deputy Minister made the point this month: agents may need an
> ID.
>
> Same idea, a different holder — and one a counterparty abroad can verify."

*(Say "attached card" and, for the phone, "announced": MOEA's own release says the mobile delegation
"will be provided" (將提供), and today every mobile certificate is itself an attached card. Do not
say the business certificate is in the wallet — it has its own app, and its place in the wallet
ecosystem is reported by the press, not shown. The finance, HR and sales example is CNA's reporting,
not the ministry's release. GLEIF's data lists Taiwan as "Taiwan (Province of China)": put no GLEIF
search page on screen. The Deputy Minister's words are as reported; say "made the point".)*

**Sources** (checked 2026-09-24):
- Wallet pilot since 17 Dec 2025, selective disclosure: MODA press release 18262,
  <https://moda.gov.tw/press/press-releases/18262>
- Wallet stack — OID4VCI, OID4VP, DIDs, SD-JWT at the verifier; no KERI or ACDC: MODA's
  <https://github.com/moda-gov-tw/TWDIW-official-app> (README, `core-system/twdiw-vp-handler`)
- Mobile business certificate, 18 May 2026; "將提供行動附卡授權功能", per-site and per-period
  authorization as a future function; "目前核發的行動工商憑證在系統定義上均為「附卡」": MOEA news
  122729, <https://www.moea.gov.tw/MNS/populace/news/News.aspx?kind=1&menu_id=40&news_id=122729>;
  the release's presentation, p.12–14 ("附卡授權機制上路後", "未來藍圖"),
  <https://www.moea.gov.tw/MNS/populace/news/wHandNews_File.ashx?file_id=125306>
- Finance, HR, sales by site and time limit — CNA via UDN, 18 May 2026,
  <https://udn.com/news/story/7238/9510151> (reporting, not the release)
- Separate app (tw.gov.nat.moeaca); "joins the wallet ecosystem"; disclosure control in future:
  iThome, 18 May 2026, <https://www.ithome.com.tw/news/175909>
- Attached-card delegation on the IC card, in 14 systems; holders "仍以人為主":
  <https://moeaca.nat.gov.tw/attachedCard/attachedCard_1.html>; the holder field is a natural
  person's ID: <https://moeaca.nat.gov.tw/develop/develop_1.html>
- Practice statement v2.5 — §3.2.7 server application software authentication "不適用"; §3.2.6
  interoperation "不適用"; X.509 v3 and RFC 5280 (§7.1.1):
  <https://moeaca.nat.gov.tw/document/moeaca_cps_v2.5.pdf>
- 統一編號 in `subjectDirectoryAttributes` (uniformOrganizationID, OID 2.16.886.1.100.2.101), not in
  the subject name: GPKI certificate profile v2.4 §1.3.6,
  <https://grca.nat.gov.tw/download/GPKI_Cert_and_CRL_Profiles_v2.4.pdf>
- Over 180 G2B and B2B systems:
  <https://gcis.nat.gov.tw/mainNew/English/subclassEnAction.do?method=getFile&pk=1>
- ISO 17442-3:2024, *Verifiable LEIs (vLEIs)*, October 2024: <https://www.iso.org/standard/85628.html>
- A Taiwanese LEI record's `registeredAs` is the 統一編號 (checked: 82920981; TWSE 03559508);
  1,094 issued and 592 lapsed LEIs with a Taiwanese legal address; no LEI issuer based in Taiwan,
  ten accredited for it; no QVI based in Taiwan: GLEIF API, 2026-09-24
- Deputy Minister Hou Yi-hsiu on agents needing an ID, 9 Sep 2026, as reported:
  <https://techorange.com/2026/09/09/moda-ai-agent/>
- **Not used:** "已非超前部署，而是不得不正面應對" — see docs/DEMO.md, slide 14.

---

### 15 — Two ways to check an identity

**Slide.** (a) Passive from a public location — publish once, verify anywhere, no per-check cost ·
(b) Attested confirmation — 來函確認, one institution confirms to another, signed.

> "Institutions already check identity two ways. A public directory: publish once, anyone verifies,
> even before making contact. And the letter of confirmation — office A writes to office B, B
> replies, A relies on the reply.
>
> As an agent call, B returns a signed attestation and A verifies B's signature: a second instead of
> days, a signature instead of a letterhead. The limit is today's: relying on an attestation means
> relying on that institution's judgment. The system insists only that the attesting institution was
> verified first, and records whose word it took."

*(來函確認 stays in Chinese on the slide on purpose: it is the name this room uses for the procedure,
and recognising it is the point of the slide. Say it in English; let the slide say it in Chinese.)*

---

### 16 — Six stages, one of which touches IT

**Slide.** 0 credential and role vocabulary · 1 publish · 2 declare per tool · **3 verify at the
gateway** · 4 attestations between institutions · 5 audit records.

**Footer:** *The filing service contains no verification code. It reads five headers the gateway
sets: LEI, role, holder, agent, and the verification report.*

> "Each stage is independently useful. An institution that stops after stage two has gained
> something real.
>
> Stage zero is the substantive one and it is not technical: the business unit defines its role
> vocabulary. Those names appear in every authorization decision and every audit record afterwards.
>
> Only stage three touches IT, and it is the one that decides whether this is a configuration change
> or a project. Verification goes at the gateway; the systems behind it read headers, as they
> already do."

---

### 17 — What an institution gets

**Slide.** The before/after table: who filed · authority changed · new system built · integration
with existing identity · audit record.

> "One row deserves emphasis, because it is the one most likely to be misread. This does not replace
> existing user authentication. vLEI answers which organization; your existing sign-on still answers
> which user. A high-value action should require both. An institution that drops one because it
> gained the other has weakened itself."

---

### 18 — Limits

**Slide.** Verifiable ≠ trustworthy · LEIs are not issued to private individuals · There is a cost ·
QVI coverage still expanding · Our demo root is self-configured · Key logs compared across the
configured witnesses — no independent watcher yet · Revoking one agent's delegation is not implemented; revoking the
credential is · Agent delegation conventions not yet settled.

> "I would rather state these than be asked. A valid credential proves an organization asserted a
> role; it does not prove the request is legitimate — that policy stays yours.
>
> Two are ours to fix. We compare key logs across the witnesses we are given, but run no independent
> watcher. And withdrawing one agent without touching the person's credential is not built;
> withdrawing the credential works, and stops every agent under it."

---

### 19 — Three requests

**Slide.**
- **Government** — one small pilot: one filing or lookup procedure, stages 0 to 3, no change to the
  department's systems
- **GLEIF** — an ECR role vocabulary for agent contexts · confirmation of the delegation model
  against the EGF · test credentials
- **AAIF** — take this to the Security Interest Group and the ext-auth discussion

> "To the institutions here, first, because you would carry the risk: one procedure, one
> counterpart, stages zero to three, and no change to the system behind your gateway.
>
> To GLEIF: an ECR role vocabulary for agent contexts; a confirmation or correction of our
> delegation model against the Ecosystem Governance Framework — we would rather be corrected now
> than at deployment; and test credentials against a real root, so the honesty statement can be
> retired.
>
> To AAIF: this belongs in the Security Interest Group and the ext-auth discussion. I would like to
> be told where it is wrong."

---

### 20 — Artifacts

**Slide.** The repository's six directories, a QR code to it, and the honesty statement repeated.

```
spec/      specification v0.2, type definitions, wire examples, error shapes
packages/  mcp-vlei — extension, client, KEL + chain verification, 155 tests
skills/    implementing-vlei (build time) · vlei-identity (runtime)
examples/  impersonation · console · association server · agent · regulator
deploy/    gateway configuration — zero-code-change adoption
docs/      problem · government adoption · conformance · the upstream defect
```
`github.com/zuemen/mcp-vlei` · Apache 2.0

*Real KERI, real ACDC, real revocation. The root of trust is self-configured; in production it would
be GLEIF's.*

> "Everything is in one repository, Apache licensed. The specification, the package, both skills,
> the reference implementations, the gateway configuration, the conformance table — and the defect
> report, because we used your verifier and we owe you that.
>
> Thank you. I have time for questions."

---
---

# Anticipated questions

One paragraph each, rehearsed.

### "GLEIF has proposed an Agent Mandate Credential. How does this relate?"

> "Closely — and I would rather say so than be told. GLEIF's working paper on agentic payments, this
> September, sketches an Agent Mandate Credential: issued by a role holder to the agent's
> identifier, which is itself a delegated identifier under that person's key event log. That is the
> delegation we built. The difference is where the scope lives: we read it from the ECR; the paper
> puts it in a credential of its own, issued to the agent — which would also give us the one thing
> on our limits slide we have not built, withdrawing one agent without touching the person. The
> paper names two open items: the credential's schema, and a standard interface for presenting and
> verifying the chain. This is a working version of the second, for MCP. The paper says it is not
> an official GLEIF position, and neither is our reading of it."

*(Source: GLEIF Working Paper Series, "Agentic AI in Payments: Establishing Interoperable Trust and
Control", September 2026 — Annex A; the disclaimer is on p.1.
<https://www.gleif.org/organizational-identity/research-publications/2026-08-13_agentic_ai_in_payments_v1.0-1.pdf>)*

### "Taiwan already has the MOEA business certificate. Why vLEI?"

> "They do not compete. The business certificate is Taiwan's domestic credential — X.509, with
> legal effect under the Electronic Signatures Act, naming a company by its unified business number
> — and it already delegates to people, through the attached card. Two things it does not do. It
> does not delegate to an agent with a scope: its practice statement marks server-software
> authentication not applicable. And we found no arrangement for verifying it abroad. A Taiwanese
> LEI record already carries the unified business number, so the two meet at the same number: the
> certificate for signatures at home, vLEI for agents and for counterparties abroad."

中文備用：

> 「兩者不衝突。工商憑證是國內的 X.509 憑證，依電子簽章法具效力，以統一編號識別企業，也已經能透過附卡把權限授權給員工。
> 它目前沒做的有兩件事：一是授權給 agent 並限定範圍——工商憑證的憑證實務作業基準，對伺服器應用軟體鑑別寫的是「不適用」；
> 二是境外驗證——我們查不到對外互認的安排。台灣企業的 LEI 紀錄裡，registeredAs 欄位就是統一編號，兩者在同一個號碼上接得起來：
> 國內簽章用工商憑證，agent 與境外的交易對手用 vLEI。」

*(Do not say the extension already carries other credential systems: it verifies vLEI chains only.
If asked whether the business certificate could be a second profile: "possible in principle; we
have not built it." Do not say vLEI is legally recognized abroad — it is verifiable abroad;
recognition is each jurisdiction's, and we did not check it.)*

### "Hardly any Taiwanese company has an LEI."

> "True today: about eleven hundred issued LEIs have a Taiwanese legal address, and no LEI issuer or
> vLEI issuer is based here — ten accredited issuers serve Taiwan from abroad. So this does not start
> as a national scheme. It starts where an LEI is already needed, in cross-border finance and
> reporting, and the first request on the last slide is one procedure with one counterpart, not a
> mandate."

*(Figures from the GLEIF API, 2026-09-24: 1,094 issued, 592 lapsed. Compare roughly 560,000 business
certificate cards, as reported by CNA — if someone raises the gap, agree with it.)*

### "Why not mTLS, or DPoP?"

> "Both are good at what they do, and neither answers this question. mTLS proves the holder of a key
> is on the other end of a connection, and a certificate authority attests to a domain — the same
> domain-control answer one layer down. DPoP binds a token to a key so a stolen token is useless,
> which is a real improvement and still says nothing about who the holder is as a legal person.
> Neither gives you an authority that can revoke a mandate, and neither gives a regulator a statement
> it already recognizes. That is what vLEI adds, and it composes with both."

### "Doesn't this tie MCP to GLEIF?"

> "It should not, and the design does not require it. What the extension really specifies is a
> credential-presentation frame: where a credential travels, how a request is bound to it, how a
> tool declares what it needs, and how a failure names its layer. None of that is vLEI-specific.
> vLEI is the first profile because it is the one that exists, is revocable, and is already
> recognized by financial regulators. If the Extensions Track prefers a generic frame with vLEI as
> one profile, I would support that, and I would rather have that conversation now than after anyone
> has deployed."

### "What about local developers?"

> "Nothing changes for them. The extension is optional and additive — a server that does not declare
> it behaves exactly as core MCP specifies, and a developer running a local server declares nothing
> and notices nothing. You saw that in scene two: an ordinary client connected, listed tools, and
> used the public one. This matters for organizational calls across a boundary and is silent
> everywhere else. A local filesystem server should never require an LEI."

### "Who pays for the LEI?"

> "The legal entity does — registration and annual maintenance, plus credential issuance through a
> Qualified vLEI Issuer. I will not pretend that is nothing. Two things make it less than it first
> appears. Many entities that would use this already hold an LEI for financial reporting. And
> GLEIF's Validation Agent framework lets a financial institution do the verification inside the KYC
> it already performs for a client, so an entity may be able to obtain credentials through an
> existing banking relationship rather than a separate procurement. For a citizen acting personally
> there is no LEI and no cost, because this is not for them."

### "Verifiable is not trustworthy."

> "Agreed, and that is the right objection. A valid ECR proves an organization asserted a role for a
> named person. It does not prove the request is sensible, correct, or authorized by anyone who
> thought about it. What changes is that the question becomes answerable at all — today, a regulator
> receiving an agent call has no way to ask it. Authorization policy remains yours. This makes your
> policy enforceable and auditable; it does not write it for you."

### "Does the agent have an identity now?"

> "No — and it does not need one. What an agent needs is a verifiable **delegation**. ECR credentials
> are issued to natural persons; the schema requires a person's legal name, and no registrar
> validates software. So the agent holds a delegated identifier under the credential holder's key
> event log and presents *that person's* credential. The accountable party stays a person. Revoke
> the credential and everything acting under it stops. Withdrawing one agent alone is not built —
> it is on the limits slide."

*(The canonical answer promises "two independent revocation switches". Only one is built; saying
two contradicts slide 18.)*

### "Aren't AP2 and TAP already doing agent identity?"

> "They are solving adjacent problems, and I do not think this competes with either. Those efforts
> concentrate on payment and transaction authorization — mandates for a payment, trust between
> participants in a transfer. This is about the organizational identity of the caller at the protocol
> layer, before any transaction exists, and specifically inside MCP, which none of them addresses. If
> a mandate framework and this end up overlapping, the right outcome is that a mandate becomes
> another thing carried in `_meta` alongside the credential. The structure has room for that, and I
> would rather it converge than duplicate."

### "Did you fix the problem you found in vlei-verifier?"

> "No — we reported it, and we worked around it. The defect is in the revocation path:
> `process_revocations_from_event_log` writes a database key of `None`, keripy raises, and the HTTP
> service goes down with the background observer and comes back with an empty database. A credential
> presented seconds earlier then answers `unknown AID`, which is why it took us a while to see it as
> a verifier problem rather than a network one. It is present in both 1.0.0 and 0.1.5.
>
> The write-up is in `docs/upstream/`, with a self-contained reproduction and three candidate fixes —
> including one that matters more than the `None` key: the observer should not be able to terminate
> the service. Fixing only the key leaves the next unexpected condition with the same blast radius.
>
> Our workaround is to read revocation from the issuer's transaction event log directly, through a
> witness. Same authority, one fewer moving part. But in production a verifier is an operated service
> with its own view of the ecosystem, and we would rather use it — which is why the source is a
> configuration option with all three paths kept, not a replacement."
