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
| 0–3 | The problem | Every layer proves domain control or a human user. The agent is absent from the protocol. |
| 3–5 | Why now | Autonomous execution × actions with legal effect × across organizations |
| 5–7 | What GLEIF already solved | LE, ECR, revocation, offline verification — and why ECR is the right credential |
| 7–9 | What we added | One slide for the schema extension, one for the skill and workflow |
| 9–12 | Demo recording | Four shots |
| 12–14 | Government | Two verification modes, five stages, what an institution gets |
| 14–15 | Three requests | AAIF, GLEIF, government |

Rehearse to 14:00. A 15-minute slot with questions is a 13-minute talk.

## The honesty statement

On a slide **and** spoken, at the start of the demo section:

> "Real KERI, real ACDC, real revocation. The root of trust is self-configured; in production it
> would be GLEIF's."

Said before the demo, not after. Said afterwards it sounds like a caveat being extracted; said
first it is a specification of what is being shown.

---

# Recording script — 3 to 4 minutes, four shots

Recorded rather than live: the demo depends on a witness network, a verifier, and a revocation
round trip, and a 15-minute slot has no room to recover from a cold container. Narrate over the
recording live so it stays a talk rather than a video.

Screen layout for every shot: terminal on the left, the dashboard at `localhost:8080/dashboard/` on
the right. The dashboard is what makes verification legible to a non-technical viewer — the
terminal shows what happened, the dashboard shows what the *institution* saw.

---

## Shot 1 — The agent calls its own association's server (60 s)

**Screen.** Left: `python examples/my-agent/agent.py "register Chen Wei-Ting…"`, showing the
stage markers and then the verification report — eight checks, one per line, each with its cost.
Right: the dashboard filling in, one row per decision, the newest marked `✓ verified`.

**Narration.**
> "The agent connects to the association's server. Before it calls anything, it fetches the
> server's Legal Entity credential and verifies the chain to a root it accepts — this is passive
> verification from a public location, and the association did nothing to serve it.
>
> Then it reads the tool list. `register_member` declares, in its own schema, that it needs an ECR
> credential with the `member-registration` role. The agent checks that against the credential it
> holds *before* calling — so a refusal it could have predicted never becomes a failed attempt in
> someone else's audit log.
>
> It signs the request, presents the ECR credential and its delegated identifier, and calls. On the
> right, the association sees the LEI, the role, the person who holds the credential, and the
> delegated identifier of the agent that acted. Not an account name — an accountable organization."

**Land on:** the report's eight green lines and `ALLOWED`, beside the dashboard row showing the
LEI, the role, the holder and the agent.

**If anyone asks what the timings are for:** every line but the last is decided from the request
itself. Only revocation leaves the machine. That ordering is why the next two shots behave the way
they do.

---

## Shot 2 — Claude Desktop, unmodified, on the same server (45 s)

**Screen.** Claude Desktop connected to the same server. `list_events` returns results;
`register_member` returns a refusal. The dashboard marks them differently: `○ public` for the tool
that asked for nothing, and `— unverified` for the call that presented nothing.

**Narration.**
> "This is Claude Desktop. It has no vLEI support and is not configured for any of this. It
> connects normally, sees every tool, and calls the public one successfully.
>
> The protected tool is refused, and the refusal names its layer: no credential was presented.
>
> Nothing broke, nothing was locked out, and nothing was silently granted. That is what 'additive'
> means — the extension lives in the fields MCP already reserves for extensions, so a client that
> does not understand them behaves exactly as core MCP specifies."

> "And note which word the dashboard uses. Not *refused* — **unverified**. This client was not
> judged and found wanting. It never made a claim. Those are different things, and a system that
> reports them the same way has lost the distinction that makes any of this worth doing."

**Land on:** `○ public` and `— unverified` side by side, in a different colour and a different word
from the red `✗ refused` that appears in the next shot.

---

## Shot 3 — Revocation (45 s)

**Screen.** Click **Revoke the ECR credential** on the dashboard. The button reads `Revoking…`,
then reports the time it completed. Re-run the same agent command from shot 1. The report comes
back with six green lines, one red, and one not reached.

**Narration.**
> "The association revokes the credential. This is a real revocation in the legal entity's
> transaction event log — not a flag in a database.
>
> The same agent, the same command, the same key. Look at the report rather than the verdict: the
> credential chain still verifies, the signature still verifies, the arguments still match. Six
> checks pass. The seventh reads the issuer's log and finds the withdrawal.
>
> That is what a revocation looks like from the outside — not 'access denied', but five things that
> are still true and one that stopped being true.
>
> That specificity is deliberate. The skill this agent follows responds differently to each layer:
> a stale signature is retried once; `revoked` means stop and tell the user a new credential must
> be issued. An agent that receives only 'denied' cannot do either correctly."

**Land on:** the failure layer, on screen, spelled out.

---

## Shot 4 — The same agent, against a government gateway (60 s)

*(If task 6B is not built, replace this shot with the adoption-path diagram from `GOVERNMENT.md`
and narrate the five stages over it. The talk does not depend on 6B.)*

**Screen.** Split: `git diff examples/my-agent/` — empty — beside a terminal running the same agent
with `MCP_SERVER_URL` pointing at port 3000. The filing succeeds. Then open
`examples/regulator/filing-server/server.py` and scroll: no identity code.

**Narration.**
> "Same agent. One environment variable. It is now filing with a regulator.
>
> The diff on the agent is empty. And this is the regulator's filing server — it does no
> verification at all. It reads four headers that the gateway established: the LEI, the role, the
> credential holder, the agent.
>
> That is the adoption question answered. An institution puts verification at its gateway and does
> not modify the systems behind it. Note also what is not a parameter of `submit_filing`: which
> entity is filing. That comes from the verified credential, not from the caller."

**Land on:** the empty diff and the header-only server, side by side.

---

## Recording checklist

- [ ] `bash scripts/bootstrap-credentials.sh` run clean; checks 3–6 pass
- [ ] Terminal font at presentation size; verify the failure layer is readable from the back row
- [ ] Dashboard cleared before shot 1
- [ ] Re-issue the ECR credential between takes (shot 3 revokes it)
- [ ] Both light and dark rendering of the dashboard checked against the projector
- [ ] Total runtime under 4:00 with narration

---

# Slide outline, with speaker notes

Sixteen slides for thirteen minutes. Notes are what to say, not what is on the slide.

---

### 1 — Title

**Slide.** Organizational Identity for MCP Agents · vLEI × Model Context Protocol · `mcp-vlei`

> "Fifteen minutes on one question: when an agent calls a tool across an organizational boundary,
> who is accountable, and how does the other side check?"

---

### 2 — What MCP verifies

**Slide.** The five-row table from `PROBLEM.md`: TLS, OAuth `iss`, OAuth `client_id`, OAuth `sub`,
`clientInfo` — what each proves, what each does not.

> "MCP inherits a well-specified authentication stack. Every layer answers a real question. TLS
> proves control of a domain name. The OAuth issuer identifies the authorization server. The client
> ID proves control of the URL serving the client metadata. The subject identifies the human user.
>
> Read the right-hand column. Domain control, domain control, domain control, human user. No layer
> expresses a legal entity, and the specification is explicit that `clientInfo` must not be used to
> make security decisions — correctly, because nothing backs it."

---

### 3 — The agent is absent from the protocol

**Slide.** `schema.ts`, 2026-07-28, 3197 lines. `agent` 0 · `principal` 0 · `delegation` 0 ·
`mandate` 0.

> "The protocol models a host, a client, and a server. The thing that actually decides to invoke a
> tool — the agent — has no representation. It cannot be named, delegated to, constrained, or
> revoked at the protocol layer, because there is nothing there to name."

---

### 4 — The measurement

**Slide.** Three runs, one variable: honest 1 h · `"Claude"` 50 h · omitted 1 h.

> "Official Python SDK. A server granting partner-tier quota based on `clientInfo.name`. That
> policy deliberately violates the specification's SHOULD NOT — the point is not that the policy is
> unwise, which is already documented, but that no layer of the stack can detect or prevent it.
>
> Same client, three runs, one field changed. No layer observed a difference, because there was no
> verifiable statement to compare against."

---

### 5 — This is a boundary, not a defect

**Slide.** "MCP's trust model assumes a human in the loop." · NSA, May 2026 · Security IG
`server-identity` proposals root in domain / DNS / registry.

> "I want to be precise about the framing. Under the human-in-the-loop premise, self-asserted
> metadata is harmless — a person is accountable at the point of action. When the agent executes
> autonomously, the premise no longer holds, and the layer carrying accountability is simply not
> present.
>
> Everyone has noticed. The published server-identity proposals all root trust in a domain, DNS, or
> a registry. Those are coherent answers to 'which deployment is this'. None is an answer to
> 'which legal entity is this', and none is revocable by an authority the counterparty's regulator
> also recognizes."

---

### 6 — Why now

**Slide.** Autonomous execution × actions with legal effect × across organizations.
NSA, May 2026: *MCP does not define how a session maps to a verifiable identity.*

> "Any one of these alone is survivable. Together they are not: an agent acting without review, on
> something that binds its organization, against a counterparty that has never met it.
>
> The NSA's information sheet from May puts the same observation in one line: MCP does not define
> how a session maps to a verifiable identity. Authentication is optional, and role permissions are
> not part of the protocol."

---

### 7 — GLEIF already solved the identity half

**Slide.** LE → ECR, chained ACDCs, revocable, offline-verifiable, anchored in KERI.

> "This is not a proposal for a new identity system. The Legal Entity credential binds an
> identifier to an LEI. The Engagement Context Role credential binds a person's identifier to a
> role within that entity. Both are chained ACDCs, both are revocable, both verify offline."

---

### 8 — Why ECR and not OOR

**Slide.** OOR = public office, controlled vocabulary, GLEIF-validated · ECR = engagement context,
entity-defined vocabulary.

> "An agent's mandate — 'may file regulatory returns up to this amount' — is an engagement context,
> not a public office. ECR is the correct credential type, and the vocabulary belongs to the entity
> that defines the engagement."

---

### 9 — The extension

**Slide.** `org.gleif.vlei/identity`, on one slide:

```
Implementation.extensions["org.gleif.vlei/identity"]  →  presents / requires / acceptedRoots
params._meta  →  org.gleif.vlei/credential
                 org.gleif.vlei/delegatedAid
                 org.gleif.vlei/signature
Tool._meta    →  org.gleif.vlei/requires { credential, role, scope }
```
Optional · Additive · Composable. MCP core unchanged.

> "Three `_meta` keys and one tool requirement. Everything travels in fields MCP already reserves
> for extensions, so a party that does not understand them behaves exactly as core MCP specifies.
>
> The fourth line is the one I would draw attention to. The permission is declared in the schema
> the client already reads, which means an agent can determine before calling whether it is
> entitled — and decline in terms a user understands, instead of attempting the call and
> interpreting a rejection.
>
> One structural note for the implementers here: `Implementation` has no `_meta`, so a party's
> credential cannot be attached to the party object. That is why the server's credential travels in
> the discover result and at a well-known URL."

---

### 10 — Teaching the model

**Slide.** SKILL.md — rules · workflow.md — stages 0 through 7 · Eight failure layers, one
retryable.

> "A schema tells software what is well-formed. It does not tell a model what to do. So the
> extension ships with a skill and a workflow.
>
> The workflow is staged: load credentials, discover, verify the server, read requirements, check
> your own entitlement, sign and call, handle the response, verify attestations. Each stage has an
> explicit pass condition, and a stage is entered only when the previous one passed.
>
> The failure layers are the part I would ask you to look at. Nine of them, and the correct
> response differs for each. A stale signature is retried once. `revoked` means stop and tell the
> user a new credential is needed. `role_mismatch` means explain which role is required. An agent
> that receives only 'access denied' cannot do any of that — which is why naming the layer is a
> requirement of the specification, not a convenience."

---

### 10b — Every requirement, traced

**Slide.** `docs/CONFORMANCE.md` — sixteen normative statements, each with its implementation and
its test. Three rows added during the review, and a section listing what is **not** claimed.

> "A specification whose requirements cannot be traced to running code is a document. So every
> MUST and SHOULD in ours has a row: the function that implements it, the test that holds it.
>
> Writing that table found three requirements with nothing behind them. It also has a section on
> what we deliberately do not claim — offline issuer signatures, an error path we never exercise,
> and a scope comparison that is one reasonable algebra rather than a standard. A conformance
> document that lists only successes is not evidence of anything."

---

### 11 — Demo

**Slide.** The honesty statement, large, alone:
*Real KERI, real ACDC, real revocation. The root of trust is self-configured; in production it would
be GLEIF's.*

> "Before the recording: everything you are about to see is real KERI and real ACDCs, issued
> through GLEIF's own schemas, with a revocation read from the issuer's transaction event log. The
> one thing I control is the root of trust — because I do not have a production vLEI. In production
> the chain terminates at GLEIF's root.
>
> One more thing worth saying while the disclosure slide is up. We did use GLEIF's verifier, and we
> found a defect in its revocation path that takes the service down. It is written up and ready to
> file. That is why revocation here is read from the log directly — the authority is the same one
> the verifier consults."

*(Play the four shots. 3–4 minutes.)*

---

### 12 — Two ways to check an identity

**Slide.** (a) Passive from a public location — publish once, verify anywhere, no per-check cost ·
(b) Attested confirmation — "來函確認", one institution confirms to another, signed.

> "Institutions already have both of these. The first is a public key directory: publish once, and
> anyone verifies independently, including before making contact.
>
> The second is the letter of confirmation. District office A writes to office B to confirm a
> record; B replies; A relies on B's reply. As an agent call, B returns a signed attestation, and A
> verifies B's signature.
>
> The correspondence procedure is not replaced by something unfamiliar — it becomes a verifiable
> call that completes in a second and leaves a signature rather than a letterhead. That is the
> concrete meaning of agents making government more efficient.
>
> And the honest limit: relying on an attestation means relying on the attesting institution's
> judgment, exactly as relying on a letter does today. What the system enforces is that the
> attesting institution must itself have been verified first, and that every decision records
> whose attestation it rested on. It cannot make that institution careful."

---

### 13 — Five stages

**Slide.** 0 credential and role vocabulary · 1 publish · 2 declare per tool · 3 verify at the
gateway · 4 attestations between institutions · 5 audit records.

> "Each stage is independently useful. An institution that stops after stage two has gained
> something real, and nothing later is required to make anything earlier work.
>
> Stage zero is the substantive one and it is not technical: the business unit defines its role
> vocabulary. Those names appear in every authorization decision and every audit record afterwards.
>
> Stage three is the one that determines whether adoption is a configuration change or a project.
> Verification goes at the gateway; the systems behind it read headers, as they already do."

---

### 14 — What an institution gets

**Slide.** The before/after table from `GOVERNMENT.md`: who filed · authority changed · new system
built · integration with existing identity · audit record.

> "One row deserves emphasis, because it is the one most likely to be misread. This does not
> replace existing user authentication. vLEI answers which organization; your existing sign-on
> still answers which user. A high-value action should require both. An institution that drops one
> because it gained the other has weakened itself."

---

### 15 — Limits

**Slide.** Verifiable ≠ trustworthy · LEIs are not issued to private individuals · There is a cost ·
QVI coverage still expanding · Our demo root is self-configured · Agent delegation conventions not
yet settled.

> "I would rather state these than be asked. A valid credential proves an organization asserted a
> role. It does not prove the request is legitimate — authorization policy stays yours, and this
> makes it enforceable rather than writing it for you.
>
> And the last one is a genuine open question, which brings me to what I am asking for."

---

### 16 — Three requests

**Slide.**
- **AAIF** — take this to the Extensions Track for discussion
- **GLEIF** — ECR role vocabulary for agent contexts · confirm the delegation model · test credentials
- **Government** — one small pilot, one procedure, stages 0 through 3

> "To AAIF: this belongs in the Security Interest Group and in the ext-auth extensions discussion.
> I would like it discussed, and I would like to be told where it is wrong.
>
> To GLEIF: three concrete things. An ECR role vocabulary for agent engagement contexts. A
> confirmation of, or correction to, the delegated-AID model for agents, including whether it is
> compatible with the Ecosystem Governance Framework — we chose a reading of the existing
> mechanisms, and we would rather be corrected now than at deployment. And test credentials against
> a real root, so the honesty statement on slide eleven can be retired.
>
> To the institutions here: one procedure, one counterpart, stages zero through three. Not a
> programme. One correspondence procedure that currently takes days."

---

### 17 — Artifacts

**Slide.** Architecture diagram — five artifacts and their GitHub paths:

```
spec/      specification v0.2, type definitions, wire examples
packages/  mcp-vlei — server extension, client, chain verification, 77 tests
skills/    implementing-vlei (build time) · vlei-identity (runtime)
examples/  association server with a live dashboard, agent, regulator scenario
deploy/    gateway configuration — zero-code-change adoption
docs/      problem, government adoption, conformance table, upstream defect
```
`github.com/zuemen/mcp-vlei`

> "Everything is in one repository, Apache licensed. The specification, the package, both skills,
> the reference implementations, the gateway configuration, the conformance table — and the defect
> report, because we used your verifier and we owe you that.
>
> Thank you — I have time for questions."

---

# Anticipated questions

One paragraph each, rehearsed. The first three are likely from AAIF and the MCP implementers; the
next two from the institutions; the last two from anyone who has been following the space.

### "Why not mTLS, or DPoP?"

> "Both are good at what they do, and neither answers this question. mTLS proves the holder of a
> key is on the other end of a connection, and a certificate authority attests to a domain — it is
> the same domain-control answer one layer down. DPoP binds a token to a key so a stolen token is
> useless, which is a real improvement and still says nothing about who the holder is as a legal
> person. Neither gives you an authority that can revoke a mandate, and neither gives a regulator a
> statement it already recognizes. That is what vLEI adds, and it composes with both."

### "Doesn't this tie MCP to GLEIF?"

> "It should not, and the design does not require it. What the extension really specifies is a
> credential-presentation frame: where a credential travels, how a request is bound to it, how a
> tool declares what it needs, and how a failure names its layer. None of that is vLEI-specific.
> vLEI is the first profile because it is the one that exists, is revocable, and is already
> recognized by financial regulators. If the Extensions Track prefers a generic frame with vLEI as
> one profile, I would support that, and I would rather have that conversation now than after
> anyone has deployed."

### "What about local developers?"

> "Nothing changes for them. The extension is optional and additive — a server that does not
> declare it behaves exactly as core MCP specifies, and a developer running a local server declares
> nothing and notices nothing. You saw that in the second shot: an unmodified Claude Desktop
> connected, listed tools, and used the public one. This matters for organizational calls across a
> boundary, and it is silent everywhere else. A local filesystem server should never require an
> LEI, and nothing here suggests it should."

### "Who pays for the LEI?"

> "The legal entity does — registration and annual maintenance, plus credential issuance through a
> Qualified vLEI Issuer. I will not pretend that is nothing. Two things make it less than it first
> appears. Many entities that would use this already hold an LEI for financial reporting. And
> GLEIF's Validation Agent framework lets a financial institution do the verification inside the
> KYC it already performs for a client, so an entity may be able to obtain credentials through an
> existing banking relationship rather than as a separate procurement. For a citizen acting
> personally there is no LEI and no cost, because this is not for them."

### "Verifiable is not trustworthy."

> "Agreed, and that is the right objection. A valid ECR proves an organization asserted a role for
> a named person. It does not prove the request is sensible, correct, or authorized by anyone who
> thought about it. What changes is that the question becomes answerable at all — today, a
> regulator receiving an agent call has no way to ask it. Authorization policy remains yours. This
> makes your policy enforceable and auditable; it does not write it for you, and it should not be
> presented as if it did."

### "Does the agent have an identity now?"

> "No — and it does not need one. What an agent needs is a verifiable **delegation**. ECR
> credentials are issued to natural persons; the schema requires a person's legal name, and no
> registrar validates software. So the agent holds a delegated identifier under the credential
> holder's key event log and presents *that person's* credential. The accountable party stays a
> person. A useful consequence: there are two independent revocation switches. Revoke the
> delegation and one agent stops. Revoke the credential and everything acting under it stops,
> including the person."

### "Aren't AP2 and TAP already doing agent identity?"

> "They are solving adjacent problems, and I do not think this competes with either. Those efforts
> concentrate on payment and transaction authorization — mandates for a payment, trust between
> participants in a transfer. This is about the organizational identity of the caller at the
> protocol layer, before any transaction exists, and specifically inside MCP, which none of them
> addresses. If a mandate framework and this end up overlapping, the right outcome is that a
> mandate becomes another thing carried in `_meta` alongside the credential. The structure here has
> room for that, and I would rather it converge than duplicate."
