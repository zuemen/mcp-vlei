# Conformance test: can an AI implement this specification from the skill alone?

The claim behind a build-time skill is that a model reading it can produce a conforming
implementation. That claim is testable, so we tested it.

## Method

A fresh session with no prior context was given **one file** — `SKILL.md` in this directory — and
asked to write a conforming MCP server. It was explicitly forbidden to read `spec/`,
`packages/mcp-vlei/`, `examples/`, or any other document in the repository. It was permitted to
read the installed `mcp` SDK, since looking up a library's API is ordinary work rather than
consulting the answer.

It was asked to produce a server that declares the capability, publishes its own LE credential,
exposes one public and one protected tool, runs the checks in order, and reports failures in the
two shapes the skill describes. It was also asked — in the same weight as the code — to say where
the skill was insufficient, and told not to soften it.

**Limits of this test.** One attempt, one model, one language. It measures whether the skill is
sufficient to produce the right *structure*; the implementation's cryptography was allowed to be
stubbed, so it does not measure whether the skill is sufficient to produce a *secure* one. A skill
that produced conforming structure and subtly wrong cryptography would pass this test.

## Result: conforming on the first attempt, with ten specification gaps

The server ran. It negotiated protocol 2026-07-28, advertised the capability with the right shape,
served `/.well-known/vlei` without a session, declared the per-tool requirement in `Tool._meta`,
ran the checks in order, and **hit all nine failure layers exactly where the table says they
should** — including the two that are easiest to get wrong:

```
TEL unreadable  -> revoked          (refused, rather than reporting "not revoked")
same sig again  -> stale_signature  (replay)
```

So the headline is that the skill works. That is also the least interesting part of the result.

## What the test actually bought: ten gaps, and one bug in our own code

The report named ten places where the skill was insufficient and the implementer had to guess —
eight in the table below, two of a different kind after it.
Every one has been fixed in `SKILL.md`. They are recorded here because the list is the evidence, not
the fix.

### A bug in this repository, not just in the skill

`data.requiredCapabilities` for the `-32021` error was **a list of identifiers** in `errors.py`, in
`spec/SPEC.md`, and in `spec/examples/error-responses.json`. The SDK types it as
`MissingRequiredClientCapabilityErrorData`, whose field is a **`ClientCapabilities` object**:

```json
{"requiredCapabilities": {"extensions": {"org.gleif.vlei/identity": {}}}}
```

The implementer found this by reading the SDK, because the skill's phrasing —
"`data.requiredCapabilities` naming the extension" — is ambiguous between the two. Our own
implementation had been wrong since it was written, in a code path no test exercised because no
server in this repository refuses a connection for want of the capability. `docs/CONFORMANCE.md`
had already recorded that path as untested; it turned out to be untested *and* wrong.

Fixed in all four places, and the output is now validated against the SDK's own type.

### The eight gaps in the skill

| # | Gap | What an implementer had to invent |
|---|---|---|
| 1 | **The SDK's extension framework was never mentioned.** `mcp.server.extension.Extension` is exactly the shape the skill described in prose | All of the plumbing, found by listing `mcp.server`'s submodules |
| 2 | **What `method` is, and what `ts` looks like** | Guessed `"tools/call"`; wrote a parser accepting both epoch and ISO, because nothing said which |
| 3 | **No example of a request `_meta` object anywhere** | Whether `signature` is a bare string or an object; where `ts` and `digest` live |
| 4 | **No SAID algorithm** for the check the skill spends a paragraph praising | Blake3 over JCS with `d` blanked — from prior KERI knowledge, not from the skill |
| 5 | **No ACDC field names** | That `d` is the SAID, `a.i` the issuee, `e.<label>.n` an edge target |
| 6 | **No way to determine a credential's type**, though the requirement says `"credential": "ECR"` | A stub reading a `_type` field that does not exist |
| 7 | **No scope semantics**, and no default when the credential omits a key | Invented a mapping, and chose **allow** when absent — a security decision the skill should have made |
| 8 | **Freshness window conflated with `ttlMs`** | A separate constant, correctly reasoning that an hour-long TTL is the wrong replay window |

Two more, of a different kind: the skill said to name the failing layer "in the text" without
saying where a *machine* reads it, so the implementer put a structured layer in
`org.gleif.vlei/attestation` — a key that means something else entirely — and said so. And the
well-known document was described by its contents but never by its key names, which is the one
artefact where that cannot be left open, because it is parsed before any session exists.

### The scope default is the one worth dwelling on

Asked what to do when a credential does not carry a scope key the tool requires, the implementer
chose to **allow**. That is a defensible reading of silence and it is the wrong default: it means a
credential that says nothing about a limit satisfies any limit. The skill now states the opposite,
as a rule rather than a suggestion.

This is what a conformance test is for. The structure was right; a silence in the specification
produced a permissive default that no reviewer would have noticed in a code review, because the
code did exactly what it was told.

## What the skill got right

Worth recording, because a report that only lists failures is not a measurement either. The
implementer said each of these changed what they would otherwise have written:

- **Ordering revocation last, with the reason given.** They would have put a cheap remote check
  early and produced exactly the failure the skill warns about.
- **Refusing when the revocation log is unreadable.** Their instinct was to degrade to "unchecked"
  and continue — the usual availability reflex, and wrong here.
- **Never taking the holder's word for revocation.** They would have treated the presented bundle
  as complete.
- **Separating `missing_credential` from the eight verification failures**, for the stated reason
  that the caller's fix differs.
- **Removing the whole `_meta` member before hashing** rather than just the signature key — they
  would have produced something that works and cannot be reviewed by eye.
- **The protocol-version trap.** Their smoke test printed `negotiated: 2026-07-28` because the
  skill told them to check it first.
- **That the reserved-prefix rule is about the second label.** They would have assumed any prefix
  containing `mcp` was off-limits.

## Conclusion

**One attempt, conforming structure, ten gaps found.** The skill was sufficient to produce a
server that hits every failure layer in the right order — and insufficient in ten specific ways
that only surfaced because someone had to build from it without the answer key.

A skill that had passed cleanly would have told us less. What this establishes is not that the
document is finished, but that it is now ten questions better than the version a reader would
have received, and that the process which found them can be run again.

## Second run, 2026-09-24: this time the cryptography was not stubbed

The first run's limit was stated above: cryptography could be stubbed, so it measured structure, not
security. After the repository's own verifier was found to check request signatures under a key the
request carried (`docs/CONFORMANCE.md`, *The defect that every green test missed*), the skill was
rewritten around key state, delegation and issuance — and the experiment was run again, with no
stubs. The result is `examples/skill-server/`, and it is the server scene 5 of the recording calls.

- **Written from the skill alone** (plus the `mcp` SDK and the public API of the `mcp_vlei`
  components the skill names; `extension.py` and `client.py` were off limits). 31 tests, including
  the one the skill now insists on — someone else's credential signed with your own key — and
  mutation tests of the checks the skill calls the security of the whole extension.
- **It found a hole in the reference implementation.** Nothing tied the LEI an ECR names to a legal
  entity: a QVI could issue an ECR straight off its own QVI credential, and an LE could issue one for
  another entity's LEI, with every issuance anchored and every SAID recomputing. The implementer
  added a rule for it; the package now has the same rule (`chain.verify_vlei_chain`), and the skill
  states it as check 9.
- **It found contradictions in the rewritten skill**: component-to-check mappings that did not match
  the check order, a component that raised a different layer than the table said, two references to
  "check 1" that meant the SAID check, a key table that was incomplete, and scope described two ways.
  All are fixed in `SKILL.md`.
- **It runs live.** Against the rebuilt witness network and a real `kli` chain, it verifies the
  agent's `kli sign`-signed call and allows it — all eight report rows passing, in its own process.

### Reproducing it

Give a fresh session `skills/implementing-vlei/SKILL.md` and nothing else from this repository.
Ask for a conforming server, and ask — with equal weight — where the document failed them. The
second question is the one that pays.
