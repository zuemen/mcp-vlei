# Talk and Recording — 15 minutes, English

**Audience:** GLEIF, AAIF, government officials.
**Register:** neutral and factual throughout. This is an applicability boundary and a proposed
extension, not a disclosure.

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
| 0–3 | The problem | Every layer proves domain control or a human user. The agent is absent from the protocol |
| 3–5 | Why now | Autonomous execution × actions with legal effect × across organizations |
| 5–7 | What GLEIF already solved | LE, ECR, revocation, offline verification — and why ECR, not OOR |
| 7–9 | What we added | One slide for the schema, one for verification |
| 9–12.5 | Demo recording | Six scenes, 4:05 |
| 12.5–14 | Government | Two verification modes, six stages, what an institution gets |
| 14–15 | Three requests | Government, GLEIF, AAIF |

Rehearse to 14:00. A 15-minute slot with questions is a 13-minute talk.

## The honesty statement

On a slide **and** spoken, at the start of the demo section, and again on the last slide:

> "Real KERI, real ACDC, real revocation. The root of trust is self-configured; in production it
> would be GLEIF's."

Said before the demo, not after. Afterwards it sounds like a caveat being extracted; first, it is a
specification of what is being shown.

---
---

# Recording script — 4:05, six scenes

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
> "A vendor's server grants a partner-tier quota to callers it recognises. We asked it for fifty
> GPU hours three times, from the same binary, changing one thing: what the client said its name
> was.
>
> Honest: one hour. Claiming to be a well-known client — with the version, the description, the
> website: fifty hours. Omitting the field entirely: one hour, and note that omitting it does not
> send nothing, because the SDK supplies a default. There is no way to decline to identify
> yourself.
>
> That policy violates the specification, which says this field must not be used for security
> decisions. The specification is right. The point is that nothing in the protocol can tell the
> difference — there is no verified statement to compare the claim against. Look at the right-hand
> column: there is nothing to check."

**Land on:** the empty verification column beside the grey banner.

---

## Scene 1 — A verified call (45s)

**Proves:** the mechanism works, and what it costs.

**Do:** press `1`.

**On screen.** Both cards blue, `● valid`. The middle column now carries four keys picked out in
red. The right column lights eight rows in sequence, each with its elapsed time. Blue banner:
**ALLOWED**.

**Narration.**
> "Same interface. Same shape of call. The difference is four keys in the request's metadata: the
> credential, the agent's delegated identifier, the signature, and which credential in the chain is
> being presented.
>
> Eight checks, in order. First what the request alone can settle: something was presented, the
> signature is fresh, and it covers these exact arguments. Then the signature must verify under the
> signer's current key — read from a witness, never from the request — and the signer must be the
> credential's holder or an agent the holder delegated. Then the chain: every credential re-hashed
> against its own identifier, each issuance anchored in its issuer's log, ending at a root this
> server accepts. Then revocation. Last, the role.
>
> Watch the timings. Two rows leave the machine — the signer's key state and the issuers' logs —
> and nothing that can be decided from the request waits for either. That ordering is not an
> optimisation; it is why the next two scenes behave the way they do."

**Land on:** eight blue rows and `ALLOWED`, with the LEI and role on the cards.

---

## Scene 2 — A client without the extension (40s)

**Proves:** additive. Adoption costs nothing to those who have not adopted.

**Do:** press `2`.

**On screen.** Server card blue; agent card grey, `● not presented`. Middle column shows only
`clientInfo`. The first check fails red — `missing_credential` — and the remaining seven go pale:
skipped, not still to come.

**Narration.**
> "This is an ordinary client with no support for any of this. It connects normally. It sees every
> tool. The public tool works — nothing was asked of it, so nothing was required.
>
> The protected tool stops at the first check, and the word the log uses is **unverified**, not
> refused. This client was not judged and found wanting. It never made a claim.
>
> That distinction matters more than it looks. A system that reports 'presented nothing' and
> 'presented something invalid' the same way has lost the thing that makes any of this worth doing.
>
> And nothing broke. The extension lives in the fields MCP already reserves for extensions, so a
> client that does not understand them behaves exactly as the core specification says."

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
> "The legal entity withdraws the credential. This is a real revocation, written to the entity's
> transaction event log — not a flag in a database somewhere.
>
> Same agent, same command, same key. Now look at the report rather than the verdict.
>
> The chain still verifies. The signature still verifies. The arguments still match what was
> signed. Six checks still pass. The seventh reads the issuer's log and finds the withdrawal.
>
> That is what a revocation looks like from the outside: not 'access denied', but six things that
> are still true and one that stopped being true. And the agent knows which — a stale signature it
> would retry once; this one it must not retry at all, and it can tell the user exactly why."

**Land on:** the six blue rows above the one red one.

---

## Scene 4 — Through the gateway (40s)

**Proves:** an institution adopts this without modifying its systems.

**Do:** press `4`.

**On screen.** The server card is now the regulator's LE. Eight rows pass — run by `vlei-authz`
behind agentgateway, not by the console. Below the banner, the output of an actual
`git diff HEAD -- examples/my-agent/`: none.

**Narration.**
> "Same agent. One environment variable. It is now filing with a regulator.
>
> The diff on the agent is empty — not small, empty. And the regulator's filing server does no
> verification at all. It reads five headers that a gateway established: four facts — the LEI, the
> role, the credential holder, the agent — and the report of the checks behind them.
>
> That answers the question an institution asks first: do we have to change our systems? Verification
> goes at the gateway. What is behind it reads headers, as it already does for whatever
> authentication it sits behind today.
>
> One detail worth noticing: which entity is filing is not a parameter of that call. It comes from
> the verified credential, not from the caller. That removes a class of impersonation without the
> filing service containing a line of identity code."

**Land on:** the empty diff beside the passing checks.

---

## Scene 5 — A server written from the skill (30s)

**Proves:** the specification is machine-adoptable, not just human-readable.

**Do:** press `5`.

**On screen.** The server card is annotated `generated from skill`. Eight rows pass.

**Narration.**
> "This server was not written by us. We gave a fresh model one document — the implementation
> skill — and nothing else: no specification, no reference code, no examples. What you are looking
> at is that server, running, verifying this call against the same witness.
>
> It also told us where the document was silent — including one gap our own verifier had: nothing
> tied the LEI an ECR names to the legal entity that issued it. Both are fixed and written up. A
> conformance test that passes cleanly teaches you nothing; this one found a hole in ours."

**Land on:** the passing column beside `generated from skill`.

*If scene 5 is cut for time, say those three sentences over the artifacts slide instead. The claim
is worth making even without the picture.*

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

Twenty slides. Notes are what to say, not what is on the slide.

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

*(Play `demo-scene0.mp4`, 45 seconds.)*

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
>
> One structural note for the implementers here: `Implementation` has no `_meta`. That is why a
> server's credential travels at a well-known URL rather than on the party object."

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

> "These three cost us days, and none of them is derivable from the design. I am putting them on a
> slide because they are what a second implementer would otherwise pay for again.
>
> The verifier's presentation endpoint requires headers signed by the credential holder — so a
> relying party cannot hand someone else's credential to a service and ask about it. It verifies the
> chain itself. That single fact determines the shape of every deployment.
>
> The agent signs with its delegated identifier; the credential was issued to a person; the record
> is keyed by the person. Read the issuee out of the credential, and never take the caller's word
> for whose record to consult.
>
> And extensions only exist at the 2026-07-28 revision. A server that appears to advertise nothing
> is usually a client that never got past the legacy handshake. We spent an afternoon on that."

---

### 12 — Every requirement, traced

**Slide.** `docs/CONFORMANCE.md` — twenty-two normative statements, each with its implementation and
its test. Three rows added during the review. A section listing what is **not** claimed.

> "A specification whose requirements cannot be traced to running code is a document. Every MUST and
> SHOULD in ours has a row: the function that implements it, the test that holds it.
>
> Writing that table found three requirements with nothing behind them. A review found something
> worse, and I would rather tell you than have you find it: our verifier checked the request
> signature under a key the request itself carried. Every test passed, because every test signed
> with the right key. Anyone who had seen a credential could have presented it as theirs. It now
> reads the key from the signer's own log; the tests that would have caught it are in the table,
> each written to fail against the old code first.
>
> The table also has a section on what we deliberately do not claim. A conformance document that
> lists only successes is not evidence of anything."

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

*(Play `demo-full.mp4`, 4:05.)*

---

### 14 — Taiwan already runs this model

**Slide.** Two columns — the Taiwan Digital Identity Wallet (數位憑證皮夾, TW DIW) and this proposal:
who holds (people and, since May 2026, a company's authorized representative · legal entities and
the agents acting for them), what (driving-licence verification card, degree certificates, MOEA
business certificate · LE and ECR), what for (parcel pickup at convenience stores, car-rental pilots
· filing, verification, enquiry between agencies), built on (selective disclosure, OpenID4VC, SD-JWT
VC, W3C VC · selective disclosure, KERI, ACDC).

**Footer:** *The trust model is already in use here. The holder it does not have yet is the agent
acting for the entity.*

> "Taiwan already runs this model. The Ministry of Digital Affairs has piloted the Digital Identity
> Wallet since last December: a person carries a credential and shows only what the counter needs
> to see. It collects parcels at convenience stores, it rents cars in a pilot, it carries degree
> certificates — and since May, a company's business certificate, held by the person authorized to
> act for it.
>
> So the idea is not new here. What the wallet does not have is the holder on the right of this
> table: the agent acting for the entity. The Deputy Minister made the same point this month — if
> agents take part in transactions, they may need an ID, to establish who the agent is and whom it
> represents.
>
> One thing to be precise about. The wallet is built on OpenID4VC and SD-JWT; this is built on
> GLEIF's vLEI, on KERI and ACDC. So this is not an extension of the wallet. It is the same way of
> thinking, applied to the holder that is missing — and to an identity a counterparty in another
> country can also verify."

*(Say "same idea, different holder" — not "we extend the wallet". The stacks are different, and a
room that built the wallet will know. The Deputy Minister's words are as reported by the press,
not a ministry statement; say "made the point", not "said".)*

**Sources** (checked 2026-09-24):
- Pilot since 17 Dec 2025, the scenarios, selective disclosure: MODA press release 18262,
  <https://moda.gov.tw/press/press-releases/18262>; policy page <https://moda.gov.tw/major-policies/wallet/1695>
- 124,000 downloads by end of August 2026 and the live uses: CNA citing MODA, 20 Sep 2026,
  <https://www.cna.com.tw/news/afe/202609200016.aspx>
- MOEA business certificate in the wallet from 18 May 2026: MOEA news 122729,
  <https://www.moea.gov.tw/MNS/populace/news/News.aspx?kind=1&menu_id=40&news_id=122729>
- Driving-licence verification card — "not a digital driving licence", used for car rental: Highway
  Bureau Q&A, March 2026 (mvdis.gov.tw)
- OpenID4VCI / OpenID4VP, SD-JWT VC, W3C VC, DIDs; no KERI or ACDC anywhere in the code: MODA's
  <https://github.com/moda-gov-tw/TWDIW-official-app> (commit 99e9deb)
- Deputy Minister Hou Yi-hsiu on agents needing an ID, 9 Sep 2026, as reported:
  <https://techorange.com/2026/09/09/moda-ai-agent/>, <https://technews.tw/2026/09/09/ai-agent-id/>
- **Not used:** "已非超前部署，而是不得不正面應對". It was reported (CIO Taiwan, May 2026) from a
  deputy director-general of MODA's Administration for Digital Industries, about AI security issues
  in general, as two quoted fragments; the version attributing it to MODA in 2025, about AI agents,
  joins two sentences and is not what was said.

---

### 15 — Two ways to check an identity

**Slide.** (a) Passive from a public location — publish once, verify anywhere, no per-check cost ·
(b) Attested confirmation — 來函確認, one institution confirms to another, signed.

> "Institutions already have both. The first is a public key directory: publish once, and anyone
> verifies independently, including before making contact.
>
> The second is the letter of confirmation. District office A writes to office B to confirm a
> record; B replies; A relies on B's reply. As an agent call, B returns a signed attestation and A
> verifies B's signature.
>
> The correspondence procedure is not replaced by something unfamiliar. It becomes a verifiable call
> that completes in a second and leaves a signature rather than a letterhead.
>
> The honest limit: relying on an attestation means relying on that institution's judgment, exactly
> as relying on a letter does today. What the system enforces is that the attesting institution must
> itself have been verified first, and that every decision records whose attestation it rested on.
> It cannot make that institution careful."

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
QVI coverage still expanding · Our demo root is self-configured · One witness is asked — conflicting
key logs are not yet detected · Revoking one agent's delegation is not implemented; revoking the
credential is · Agent delegation conventions not yet settled.

> "I would rather state these than be asked. A valid credential proves an organization asserted a
> role. It does not prove the request is legitimate — authorization policy stays yours, and this
> makes it enforceable rather than writing it for you.
>
> Two are ours to fix. We ask one witness for a key log, so two conflicting logs for the same
> identifier — what watchers exist to catch — would not be noticed. And the specification describes
> withdrawing one agent without touching the person's credential; we have not built that switch.
> Withdrawing the credential works, and stops every agent under it.
>
> The last one is a genuine open question, which brings me to what I am asking for."

---

### 19 — Three requests

**Slide.**
- **Government** — one small pilot: one filing or lookup procedure, stages 0 to 3, no change to the
  department's systems
- **GLEIF** — an ECR role vocabulary for agent contexts · confirmation of the delegation model
  against the EGF · test credentials
- **AAIF** — take this to the Security Interest Group and the ext-auth discussion

> "To the institutions here, first, because you are the ones who would carry the risk: one
> procedure, one counterpart, stages zero through three. Not a programme. One correspondence
> procedure that currently takes days, and no change to the system behind your gateway.
>
> To GLEIF: an ECR role vocabulary for agent engagement contexts. A confirmation of, or correction
> to, the delegated-AID model, including whether it is compatible with the Ecosystem Governance
> Framework — we chose a reading of the existing mechanisms and would rather be corrected now than
> at deployment. And test credentials against a real root, so the honesty statement can be retired.
>
> To AAIF: this belongs in the Security Interest Group and in the ext-auth discussion. I would like
> it discussed, and I would like to be told where it is wrong."

---

### 20 — Artifacts

**Slide.** The repository's six directories, a QR code to it, and the honesty statement repeated.

```
spec/      specification v0.2, type definitions, wire examples, error shapes
packages/  mcp-vlei — extension, client, KEL + chain verification, 143 tests
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
> event log and presents *that person's* credential. The accountable party stays a person. A useful
> consequence: two independent revocation switches. Revoke the delegation and one agent stops.
> Revoke the credential and everything acting under it stops, including the person."

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
