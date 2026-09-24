# REPORT — where `SKILL.md` was not enough

Written 2026-09-24 by the implementer of `server.py` (Claude Opus 5.5), from
`skills/implementing-vlei/SKILL.md` alone. The list is ordered by consequence. "Invented" means
the behaviour is in `server.py` and the skill does not ask for it; "guessed" means the skill asks
for something without saying exactly what; "contradiction" means two parts of the skill disagree.

Summary: the skill's core — the 11-check table, the three bolded rules for checks 3, 5 and 7, the
exact signing formats, and the two failure shapes — was enough to write a server whose central
security property holds on the first attempt (the "someone else's credential, own key" test fails
the right way and was mutation-tested). What it does **not** give is (a) a binding between the LEI a
credential claims and a legal entity, (b) an unambiguous mapping from its own components to its own
check order, and (c) a dozen interop details that a second implementer will choose differently.

> **What became of each gap** (2026-09-24, after this report). The check numbers below are the
> ones the implementer read; the skill's table now has 13 rows (0–12).
>
> | Gap | Disposition |
> |---|---|
> | 1 LEI not bound to an LE | **Fixed** — skill check 9; package `chain.verify_vlei_chain` |
> | 2 only the leaf's schema constrained | **Fixed** — `verify_vlei_chain` checks every edge's declared schema and the ECR/OOR → LE → QVI shape |
> | 3 where scope lives | **Open** — the reference reads `a.scope`; the skill does not say so yet |
> | 4 replay cache is per process | **Known limit** — a replicated deployment needs a shared cache; stated in `docs/CONFORMANCE.md`, *not claimed* |
> | 5 one witness trusted | **Fixed, within limits** — `witness_urls` compares the signer's log across witnesses and refuses a fork; independence of those witnesses is the operator's, as `docs/CONFORMANCE.md` says |
> | 6–10 contradictions in the skill | **Fixed** in `SKILL.md` |
> | 11 which bytes the digest covers | **Open** — needs a test vector in `spec/examples/` |
> | 12, 13 `delegatedAid`, `credentialSaid` semantics | **Fixed** — the skill's key table states both |
> | 14 what an `acceptedRoots` entry is | **Open** — the reference treats it as an issuer AID; the text should say so |
> | 15 whose cache `ttlMs` governs | **Open** — specification text |
> | 16 `wellKnown` needs an absolute URL | **Not changed** — deployment configuration, as `PUBLIC_URL` / `VLEI_PUBLIC_URL` do |
> | 17 "witness down" surfaces as two layers | **Not changed** — both are refusals with "not established" in the message; a tenth layer would break the nine-layer contract clients key off |
> | 18 undeclared client sending a credential | **Not changed** — declaration first is what the specification says |
> | 19 two identical calls in one second are a replay | **Fixed** — `sign_request` now signs millisecond timestamps |
> | 20 replay reported on the `freshness` line | **Not changed** — the report's eight rows are fixed; a replay is a freshness failure |
> | 21 keeping `Tool._meta` and enforcement in sync | **Not applicable to the reference** — `VleiIdentity.bind()` reads requirements from the tools themselves |

---

## A. Security: following the skill literally yields an insecure server

### 1. Nothing binds the ECR's LEI to a legal entity (invented fix)

Every check in the section-4 table passes for:

- an ECR issued by a real LE, correctly anchored and unrevoked, whose `a.LEI` is **another
  company's LEI**; and
- an ECR issued by a **QVI directly**, edged to the QVI's own QVI credential, with **no LE
  credential in the chain at all**, naming any LEI.

Both chains have recomputing SAIDs, continuous links, an ECR leaf schema, issuances anchored in the
issuer's log, an accepted root and live "issued, not revoked" TELs. The server would report the
forged LEI in its audit log and in `filedBy`. I confirmed the second case end to end before fixing
it (`allowed: True, lei: 5299000000000000EVIL`).

What `server.py` does (`_check_lei`, reported under check 6 as `chain_invalid`):

- the leaf must carry `a.LEI`;
- the chain must pass through a Legal Entity credential, identified by the published LE schema SAID
  `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` — **which the skill does not give**; I took it
  from `mcp_vlei.testing`;
- that LE credential's `a.LEI` must equal the ECR's;
- exception: if the ECR's issuer is itself an accepted root (the operator trusts the LE directly),
  the call is allowed with a report caveat, because there is nothing above it to cross-check.

Tests: `test_ecr_naming_a_different_lei_than_its_le_is_refused`,
`test_ecr_issued_by_a_qvi_without_an_le_in_the_chain_is_refused`,
`test_ecr_whose_issuer_is_an_accepted_root_is_allowed_with_a_caveat`.

The skill should state the LEI rule, and should name the LE schema SAID next to the ECR one.

### 2. Only the leaf's schema is constrained

The skill requires "the leaf's schema is the type the tool requires" and nothing about the links
above it. Beyond the LE requirement in gap 1, `server.py` does not check that the parents are the
vLEI types they should be (LE, QVI, ECR Auth), nor that `e.<label>.s` (the schema an edge declares)
matches the target's `s`. I did not invent a full vLEI chain grammar because the skill gives no
basis for one; with gap 1 closed I could not construct an attack from this, but I did not prove
there is none.

### 3. Where the credential's scope lives is never said (guessed)

Section 3 says scope "is compared against the credential", and the ACDC field list ("`d` is the
SAID, `i` the issuer, `a.i` the issuee, …") has no entry for scope. I read `a.scope`. Nothing in
this server exercises it (`submit_filing` declares no scope), so a live deployment that adds a scope
requirement is relying on a guess. Non-numeric, non-list values (strings, objects, booleans) are not
covered by the skill's rule either; I compare them by equality, and a boolean is not treated as a
number.

### 4. The replay cache is state, and the skill calls the design stateless

"A stateless gateway evaluating external authorization sees one message" (section *Do not sign a
nonce alone*) — but check 4 needs a replay cache. `server.py` keeps it in process memory
(`ReplayCache`, retention 2 × 60 s). It is lost on restart, and is not shared between replicas: a
request captured before a restart can be replayed within its 60-second window, and with two
replicas it can be replayed once per replica. The skill does not say whether this is acceptable.

### 5. One witness is trusted for key state

The skill says to read the KEL "from a witness". `mcp_vlei.kel` verifies the log but does not
detect duplicity (its own docstring says so). One compromised or stale witness can serve an old
key state. Not fixable within the skill's instructions; recorded here because check 3 is called
"the security of the whole extension".

---

## B. Contradictions and errors inside the skill

### 6. The component the skill names for checks 6–8 runs them in the wrong order

"`mcp_vlei.verifier.OfflineVerifier` (checks 6–8, including `mcp_vlei.chain.verify_issuance`)".
But `OfflineVerifier.verify` calls `walk_chain`, which raises `unknown_root` **while walking** —
before any issuance is checked. A forged chain that also ends at an unknown root is reported as
`unknown_root`, not `chain_invalid`, which is check 8 before check 7. It also does not check the
leaf's schema against the tool's requirement (part of check 6), and its `expected_role` argument
would run the role check (10) before revocation (9). Using it as pointed to breaks the order the
same document calls mandatory.

`server.py` therefore does not use `OfflineVerifier`. It walks the chain itself with
`chain.recompute_said`, checks the leaf schema, runs `chain.verify_issuance` on every link, and only
then decides the root.

### 7. The component the skill names for check 3 reports the wrong layer

`WitnessKeyStates` raises `ChainInvalid` when a signer's log cannot be read or does not verify
(unreachable witness, unknown AID, a `dip` its delegator never anchored). The table says a check-3
failure is `invalid_signature`, and "a request whose signature cannot be checked is refused".
Called as the skill suggests, the server would answer `chain_invalid` for a signature it never
checked. `server.py` catches it and re-raises `invalid_signature` with the original message
attached.

### 8. "Check 1" means two different things

The table's check 1 is freshness. The prose then says "How to recompute a SAID (check 1)" and
"Note what check 1 buys you without any key at all" — both about the SAID, which the table places
at check 6. A reader who trusts the prose recomputes SAIDs before the freshness check, which
contradicts "decide from the request first" only mildly, but contradicts the report order outright.

### 9. Scope: the table and the prose disagree

Table row 10: "request satisfies its scope". Section 3: "Scope is compared against the credential,
**not against the arguments**." I followed the prose: the tool's declared `scope` is compared with
the credential's; the arguments are not inspected.

### 10. The key table is incomplete

"This extension adds four namespaced keys" — the table below has six rows, and it omits
`org.gleif.vlei/credentialSaid`, which appears only later, in the client section. A server author
reading only the server section does not learn that `credentialSaid` exists.

---

## C. Guesses that a second implementer will make differently (interop risk)

### 11. What `params` is, and which bytes of it

The digest is over "`params` … with the whole `_meta` member removed". I took the JSON-RPC
`params` of `tools/call` — `name` **and** `arguments` (and anything else present, e.g.
`requestState`) — not `arguments` alone. There is no test vector in the skill; one would settle it.

The skill also says check 2 compares against "the received parameters", but the SDK hands the
interceptor a validated pydantic model. Re-serializing that model is exactly what the skill warns
against for SAIDs. From the SDK source (not the skill) I found `ctx.params`, the wire mapping as
received; `server.py` digests that, and falls back to `model_dump(exclude_unset=True)` only if it is
absent. The SDK client also injects `io.modelcontextprotocol/*` keys into `_meta`; the skill's
"remove the whole `_meta`" rule is what makes that harmless.

### 12. `delegatedAid` has no stated semantics

It is "the agent's delegated AID", but nothing says how it relates to `signature.aid`, whether it is
required, or what it is when the holder signs directly. `server.py` treats `signature.aid` as the
signer, refuses (`invalid_signature`) if `delegatedAid` is present and different, and accepts it
absent.

### 13. `credentialSaid` absent

Required or optional is not said. `server.py` falls back to the only credential nothing else points
at, and refuses (`chain_invalid`) if there is not exactly one.

### 14. What an `acceptedRoots` entry is

The example is one `E…` string. I read it as an **issuer AID**: the chain walk stops at the first
credential whose issuer is in the set. It could equally have meant a root credential SAID. The two
readings accept different chains.

### 15. `ttlMs`

The skill defines it as how long "a verification result" may be cached, and puts it in the
capability a server advertises. Whose cache — the client's cache of its verification of the server,
or the server's own? I advertise `0`, which is true under either reading because this server caches
nothing (key state, chain and revocation are established on every call).

### 16. `discovery.wellKnown` must be an absolute URL the server may not know

The example is `https://host/.well-known/vlei`. A server bound to 127.0.0.1 does not know the name
its clients use. I invented `VLEI_PUBLIC_URL` (default `http://127.0.0.1:$PORT`). The well-known
document itself has exactly the four keys the skill shows; it does not say which credential in the
stream is the LE, so a client must find the leaf. The optional copy in the discover result's `_meta`
is not implemented: `Extension` has no hook for `server/discover` (a `MethodBinding` cannot bind a
spec method), and the skill says well-known is the route that works.

### 17. Layers for conditions the table does not cover

| condition | layer chosen | reason |
|---|---|---|
| credential present but not a string | `chain_invalid` | presented, but not a credential |
| signature present but not an object, or missing `aid`/`ts`/`digest`/`sig` | `invalid_signature` | `mcp_vlei.signing` raises it |
| stream unparseable, `credentialSaid` not in stream | `chain_invalid` | recorded under the report's `delegation` item, because check 5 is where the issuee is first needed |
| witness unreachable during check 3 | `invalid_signature` | the signature was not checked (gap 7) |
| witness unreachable / HTTP error during check 9 | `chain_invalid` | `TelRevocationChecker` raises it; the skill only says "refuse" |
| signer's key state needs more than one signature (`kt` > 1) | `invalid_signature` | a request carries one signature; the skill is silent on multi-sig signers |
| any unexpected exception inside a check | that check's own layer | fail closed |

The same operational event, "the witness is down", therefore surfaces as `invalid_signature` or
`chain_invalid` depending on which check hits it first. There is no layer for "could not establish",
and a caller cannot tell an outage from a forgery by layer — only by message.

### 18. Undeclared extension, credential presented anyway

"Client never declared the extension, but the tool requires it → `-32021`". If an undeclared client
nevertheless sends a credential and signature, `server.py` still answers `-32021` (declaration wins)
and does not verify. Over HTTP the SDK returns that error with HTTP status 400 (observed, not in the
skill). The skill's `-32021` shape is a JSON-RPC error, so the verification report the task asks for
cannot be attached to it; `server.py` does not smuggle it into `error.data`, whose type the skill
fixes. The SDK also has `mcp.server.mcpserver.server.require_client_extension`, which the skill does
not mention; I built the error from the types the skill names instead.

### 19. Freshness details

The window is 60 s either side (a future-dated `ts` within the window is accepted; the skill does
not say whether it should be). Because `ts` has one-second resolution and the replay key is
`(aid, digest, ts)`, **two identical, legitimate calls in the same second are a replay**: the second
is refused `stale_signature`. A retry with a new `ts` succeeds, which matches the skill's "retry
stale once" — but the skill does not warn about it, and one of my own tests tripped on it.

### 20. Report mapping

The task asked for `mcp_vlei.report.VerificationReport`, which the skill never mentions. Its fixed
order is `credential_present, freshness, digest, signature, delegation, chain, revocation,
authority` — eight items for eleven checks. Mapping chosen:

| skill check | report item |
|---|---|
| 0 | `credential_present` |
| 1, and 4 (replay) | `freshness` |
| 2 | `digest` |
| 3 | `signature` |
| 5 | `delegation` |
| 6, 7, 8 | `chain` (so `unknown_root` appears on the `chain` line) |
| 9 | `revocation` |
| 10 | `authority` |

Replay is check 4 — after the signature — but the report's `freshness` line comes before
`signature`. `server.py` re-opens `freshness` after the signature has verified, so a replay report
shows `freshness ✗` above `signature ✓`. Correct, and odd to read on a screen.

### 21. Keeping `Tool._meta` and enforcement in sync

The skill says to declare requirements on the tool and to verify in the interceptor, but an
`Extension` is never given the server or its tool list. `server.py` keeps one requirements dict in
the extension, and the tool's `_meta` is generated from it (`VleiIdentity.tool_meta`), so what is
declared is what is enforced. How the tool learns who called it is also unspecified; I pass the
verified identity (LEI, role, SAID, AIDs) through a `ContextVar`, and the tool refuses if it is ever
reached without one.

---

## D. What I had to learn from the SDK, not the skill

- `ctx.params` is the wire params mapping (gap 11).
- On 2026-07-28 the client's capabilities travel per request in
  `_meta["io.modelcontextprotocol/clientCapabilities"]` and are read with
  `ctx.session.client_capabilities`.
- `@server.custom_route` is how to serve `/.well-known/vlei` without a session.
- A tool annotated `-> dict` produces no `structuredContent`; `-> dict[str, Any]` does.
- With the in-process `Client`, an `MCPError` that escapes the `async with` block arrives wrapped in
  an `ExceptionGroup`; catch it inside the block.

---

## E. Live readiness — what was and was not established

Established here: 31 tests through the real SDK against `mcp_vlei.testing.World`, mutation tests of
checks 3, 4, 5, 7 and 9, and one HTTP run of the real `python server.py` against a temporary
witness serving a `World` over HTTP.

Not established at the time of writing: behaviour against a real keripy witness and real
`kli vc export --full` output. (Established afterwards, the same day: the server verified the
agent's `kli sign`-signed call against the rebuilt witness network and a real `kli` chain, all eight
report rows passing — scene 5 of the recording.) The live run depends on:

1. the witness serving the KELs of both the agent **and** the holder (the delegator), and the TELs
   of **all three** registries (GLEIF root, QVI, LE) — check 9 queries every link, and a TEL the
   witness has never seen is refused as `chain_invalid`;
2. `VLEI_ACCEPTED_ROOTS` being the AID that **issued** the QVI credential (gap 14);
3. the calling client signing `{name, arguments}` exactly as in gap 11 and declaring the extension
   at protocol 2026-07-28;
4. single-key (`kt` = 1) signing AIDs, which is `kli`'s default;
5. the real ECR's `a.LEI` equalling the real LE credential's `a.LEI` (gap 1) — true of any correctly
   issued vLEI chain;
6. `VLEI_PUBLIC_URL` being set if a client reaches the server by any name other than 127.0.0.1.
