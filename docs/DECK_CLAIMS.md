# What the panel deck says, and where it is in this repository

The panel introduction *Who Vouches for Your AI?* (Trustworthy AI, 23 November 2026) links here.
Each claim it makes about this code is listed with the file that does it and the test that holds
it. **Status** says how far it goes: *implemented*, *proposal* (implemented, but no vLEI or KERI
standard defines it yet), or *limit* (true, with the limit stated). Page numbers are the deck's.

Re-run everything here with the commands in [Running it](#running-it).

| Deck says | Where | Held by | Status |
|---|---|---|---|
| The gateway checks every call, **8 checks in order**, stopping at the first failure (p18, p26, p29) | `packages/mcp-vlei/src/mcp_vlei/report.py` (`CHECK_ORDER`: credential present, freshness, digest, signature, delegation, chain, revocation, authority); the gateway calls it through `examples/regulator/vlei-authz/service.py` | `packages/mcp-vlei/tests/`, `examples/regulator/tests/test_vlei_authz.py` | implemented |
| **11 named refusals** (p18, p30) | `packages/mcp-vlei/src/mcp_vlei/errors.py` (`FailureLayer`); the agent's table in `skills/vlei-identity/SKILL.md` | `packages/mcp-vlei/tests/` | implemented |
| *No papers? Refused.* (p10) | check 1 refuses `missing_credential` | `examples/regulator/tests/test_vlei_authz.py` | implemented |
| *Take away Bob's role, and his agent is refused on its next call* (p10, p11, p22, p28) | revoking the ECR is read from the issuer's key event log on every call, no cache: `packages/mcp-vlei/src/mcp_vlei/revocation.py` | `test_vlei_authz.py`, `examples/credential-proxy/tests/test_proxy.py`, `examples/console/tests/test_scenes.py` | implemented |
| *Cancel it any time* (p9) · the handler *issues the agent its own key; cancels it when the role changes* (p13) | `scripts/issue-agent.sh` creates an agent AID delegated by the ECR holder; `scripts/revoke-agent.sh` withdraws that one agent's delegation, leaving the holder's ECR and every other agent working; check 7 refuses it as `revoked`. Design: [`spec/SPEC.md`](../spec/SPEC.md), "Withdrawing an agent's delegation (proposal)" | `packages/mcp-vlei/tests/test_delegation_withdrawal.py` (16), `test_vlei_authz.py::test_a_withdrawn_agent_is_refused_and_not_mistaken_for_a_revoked_credential`; [`docs/CONFORMANCE.md`](CONFORMANCE.md) row 33 | **proposal**: KERI has no delegator-side withdrawal; the standard direction (an agent-authorisation ACDC revoked in a TEL) is in SPEC. A withdrawal is irreversible; a new agent gets a new AID |
| *Its own card, never the handler's ID and password* (p9) | the agent signs with its own delegated AID, never the person's key: `scripts/bootstrap-credentials.sh`, `examples/credential-proxy/proxy.py` | `test_proxy.py` | implemented |
| *Its own limit: filing, yes; payroll, no* (p9, p11, p25) | the limit is the ECR's role, enforced at check 8: `examples/regulator/vlei-authz/policy.json` requires `labor-insurance-payroll` for `adjust_insured_salary` | `test_vlei_authz.py` (`role_mismatch`) | **limit**: the agent carries its handler's role; narrowing one agent below it is an open question (p15) |
| *A signed record names who is accountable* (p11) | every decision record and receipt carries the signed request (`signedRequest`: the signed statement, signature, signer's key state); `scripts/verify-audit.py` re-verifies a record offline, names the signer and its credential, and prints the LEI and role the gateway recorded | `examples/regulator/tests/test_signed_audit.py` (7, including tampering and key rotation) | implemented. The caller's signature covers the statement, digests, signer and credential; `tool`, `lei`, `role` and the decision are the gateway's own statement. Offline re-verification trusts the stored key state; compare `eventSaid`@`sn` with the witnesses to confirm it |
| *Anyone can verify them — no platform in the middle* (p10, p11) | the chain is verified locally against the root of trust (`OfflineVerifier`); no service is asked | `packages/mcp-vlei/tests/` | implemented; the demo's root of trust is self-hosted (GLEIF's in production) |
| The labour system: *no new code* (p10, p13); *verifies nothing* (p26, p29) | `examples/regulator/labor-insurance-sim/server.py` has no credential parsing and no dependency on `mcp_vlei`; it reads the identity headers the gateway sets, as a back end reads `X-Forwarded-User` | `test_labor_insurance_sim.py` | **limit**: "no new code" means no verification code; it still declares each tool's requirement (p29) and reads the gateway's headers |
| *Each tool declares, in its own schema* `org.gleif.vlei/requires` (p29) | `server.py` `_meta`; `policy.json` (`enroll_employee` also limits the start date) | `test_labor_insurance_sim.py` | implemented; the namespace is provisional, not endorsed by GLEIF |
| *Each signature is for one agency, and works once* (p29, p30, p31) | `vlei-sig/0.3`: recipient-bound, 30-second expiry, one-time nonce — `packages/mcp-vlei/src/mcp_vlei/signing.py`, `replay.py` | `docs/CONFORMANCE.md` rows on nonce and audience | implemented; the replay store is shared by processes on one host only (CONFORMANCE) |
| The proxy *checks the office before it sends anything*: proof of possession (p18, p31) | `examples/credential-proxy/proxy.py` verifies the gateway operator's LE chain, revocation and `vlei-pop` | `test_proxy.py`, `packages/mcp-vlei/tests/test_client_v03.py` | implemented |
| *2 of 3 witnesses agree* (p28, p31) | quorum 2 of 3 witness AIDs: `scripts/keri-config/incept-witnesses.json` (`toad: 2`), `client.py` | `test_client_v03.py`, `test_witness_copies.py` | **limit**: the demo runs the three witnesses in one container (`scripts/docker-compose.yml`); separate operators are a deployment choice |
| *The agent itself — Claude Code — is unchanged* (p13, p18, p26) | the proxy is a STDIO MCP server Claude Code launches: `examples/credential-proxy/proxy.py` | `test_proxy.py` | implemented |
| *Public registry: `/.well-known/vlei`* (p32) | `labor-insurance-sim/server.py`, `deploy/agentgateway/config.yaml` | `test_labor_insurance_sim.py` | implemented |
| *Confirmation letter — proposed, not in the demo* (p32) | `packages/mcp-vlei/src/mcp_vlei/attest.py` | `test_attest.py` | implemented in the package, not used by the demo |
| *Two skills*: one to build it, one for the agent (p15, p18, p30); `workflow.md` 8 stages, 11 refusal layers | `skills/implementing-vlei/`, `skills/vlei-identity/` | — | implemented |
| *Given only the first skill, a fresh AI session got the core security right first time — our tests, not an audit* (p18, p30) | `examples/skill-server/REPORT.md` | `examples/skill-server/tests/` | **limit**: the report records that the core signature check held first time *and* that following the skill literally left gaps, fixed afterwards; both are self-assessed |
| *Over 900 tests* (p12 notes, p18) | the six suites CI runs; the total is in the README and recounted by `scripts/count-tests.py --check` in CI | `.github/workflows/test.yml` | implemented |
| *The value is self-reported by the client …* — the MCP specification, schema 2026-07-28 (p27) | quoted verbatim with a permalink in [`docs/PROBLEM.md`](PROBLEM.md) | `docs/evidence/observatory-2026-09-29.json` (a real call and its replay, same `clientInfo`) | implemented |
| *Drafted as an MCP extension for standardisation* (p12, p18) | `spec/SPEC.md`, `spec/schema.ts` — additive, through `extensions` and `_meta` | — | draft; not yet submitted |

## Running it

```sh
pip install -e "packages/mcp-vlei[dev]"
pytest packages/mcp-vlei/tests examples/regulator/tests -q     # no containers
python scripts/count-tests.py --check                          # every stated count, recounted
python scripts/verify-audit.py <audit.jsonl>                   # re-verify a gateway's decision log

docker compose -f scripts/docker-compose.yml up -d             # the credential environment
bash scripts/bootstrap-credentials.sh
bash scripts/issue-agent.sh agent2                             # a second agent under Bob's ECR
bash scripts/revoke-agent.sh agent2                            # withdraw it; its next call is refused
```
