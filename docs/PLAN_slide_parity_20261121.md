# Plan: make the repository do what the panel deck says (2026-11-21)

The deck (Trustworthy AI panel, 2026-11-23) is final and will not change. Where the deck says more
than the code does, the code is brought up to it. Constraints: the 8 checks, their order, and the 11
named refusal layers stay exactly as they are (the deck counts them); existing tests stay green;
anything with no KERI/vLEI standard is labelled a proposal in SPEC and CONFORMANCE; the recorded
demo flow (LE → ECR → delegated agent, revoke ECR → refused) keeps working.

## Gaps (deck claim → what the code does today)

| # | Deck (page) | Today | Work |
|---|---|---|---|
| A | p9 "Cancel it any time", p13 "the handler … Cancel it when the role changes" | Withdrawing one agent's delegation is not implemented (CONFORMANCE "Revoke the delegation") | **Delegation withdrawal.** The ECR holder anchors a withdrawal seal for the agent AID in an interaction event in its own KEL (`kli interact --data`). Check 7 (revocation) reads the holder's KEL — already fetched from witnesses for check 5 — and refuses with the existing `revoked` layer if the agent's delegation was withdrawn. Labelled a proposal (no KERI standard). `scripts/revoke-agent.sh`, SPEC section, CONFORMANCE row, unit tests on real `kli`-shaped KELs, live acceptance with containers. |
| A2 | p9 "Its own limit: filing, yes; payroll, no" | Agent's authority = the ECR's role; the agent cannot be narrowed below it | **Optional agent scope.** The same anchor mechanism at delegation time may name the tools the agent may call; check 8 (authority) refuses `role_mismatch` for a tool outside it. Absent = the ECR's role, as today. Proposal. |
| C | p11 "A signed record names who is accountable" | Audit record keeps header names, not the signature | Gateway audit record stores the request's signature, signer AID, credential SAID, request digest and audience, so the record itself can be re-verified offline; `scripts/verify-audit.py` re-checks a record. No personal data beyond what is already logged. |
| B | p10 / p13 "Labour system … no new code", "back end — no new code" | Sim reads `x-vlei-*` headers (refuses without them), serves `/.well-known/vlei`, declares `_meta` itself | Make the back end vLEI-agnostic: it runs as a plain MCP server and accepts calls whether or not identity headers are present (headers only enrich the receipt); `/.well-known/vlei` and per-tool `requires` are published by the gateway side from its own `policy.json`. Only if agentgateway / vlei-authz can do it without a fork; otherwise document the exact residue. |
| D | p28 / p31 "2 of 3 witnesses agree" | Three witnesses in one container | Three containers, one witness each, same AIDs, ports and quorum; `bootstrap` and acceptance unchanged. Live-tested before push. |
| E | p27 MCP spec quote | Paraphrased in docs/PROBLEM.md | Check the quote against the official 2026-07-28 schema; put the verbatim text and link in the repo. |

Not changeable in code (historical or simplification): p29's grouping of check numbers to codes;
p18/p30 "first time" (a past experiment, `examples/skill-server/REPORT.md` stays as written).

## Order and isolation
A+A2 (package, spec, scripts) · C+B (examples/regulator, deploy) · D (scripts/docker-compose) run in
separate worktrees; merged in that order; full CI suites + `count-tests.py` + live container
acceptance after merge; independent review before push. Then mirror into the private repo.

## Review outcome (adversarial review, 2026-11-21)
Do: **A** (narrowed: withdrawal seal with its own shape `{"i": agent, "d": <dip SAID>, "withdrawn": true}` — never `(i, s, d)`, which collides with `drt` approvals; checked only when revocation is established from witnesses, otherwise *not established*; caller side only; paired `scripts/issue-agent.sh` / `scripts/revoke-agent.sh`; live acceptance on a second agent AID, never the demo one), **C**, **E**, and `docs/DECK_CLAIMS.md` (deck claim → file / test / command, with proposal / not-done column), linked from README.
Not done: **A2** (the ECR role already gives filing-not-payroll: `policy.json`), **B** (moving `requires` off the tool contradicts p29; README states "no new code = no verification code"), **D** (witnesses have no data volume: splitting re-bootstraps every SAID and breaks the recorded demo).
