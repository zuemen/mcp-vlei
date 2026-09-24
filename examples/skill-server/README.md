# skill-server — an org.gleif.vlei/identity server written from the skill

This directory is the output of a **conformance experiment**: a fresh implementer, given only
`skills/implementing-vlei/SKILL.md`, writes an MCP server that conforms to the
`org.gleif.vlei/identity` extension. It is what scene 5 of the talk ("A server written from the
skill") runs.

What the skill did not say, and what had to be guessed or invented, is in [`REPORT.md`](REPORT.md);
what was done about it is in
[`skills/implementing-vlei/CONFORMANCE.md`](../../skills/implementing-vlei/CONFORMANCE.md), *Second run*.
That file is the actual result of the experiment.

## Provenance

| | |
|---|---|
| Date | 2026-09-24 |
| Written by | Claude Opus 5.5 (`claude-opus-5-5[1m]`), running as a Claude Code subagent, in one session |
| Repository state | `HEAD` 6ddda17 (2026-09-23 23:27 +0800) **plus uncommitted working-tree changes**, including to `SKILL.md` and to several `mcp_vlei` modules; hashes below |
| SDK | `mcp` 2.2.0 (MCP protocol 2026-07-28), httpx 0.28.1, pytest 9.1.1, Python 3.10 |

**Read — the specification source**

- `skills/implementing-vlei/SKILL.md`, in full (sha256 `15be5f6b4505639f…` of the working-tree copy).

**Read — as library documentation** (the components the skill names, plus their error and report
types and the test world). These files were read in full, since their docstrings and bodies are the
API reference; none of them contains the extension's interceptor.

| file | sha256 (prefix) |
|---|---|
| `packages/mcp-vlei/src/mcp_vlei/kel.py` | `a63be0d65f4a054a` |
| `packages/mcp-vlei/src/mcp_vlei/signing.py` | `d0b00d63b617fca1` |
| `packages/mcp-vlei/src/mcp_vlei/verifier.py` | `b2f7420adac8a487` |
| `packages/mcp-vlei/src/mcp_vlei/chain.py` | `c3c9ec51ab4cd085` |
| `packages/mcp-vlei/src/mcp_vlei/revocation.py` | `ef183cc23883edf2` |
| `packages/mcp-vlei/src/mcp_vlei/errors.py` | `a4db4019b036abde` |
| `packages/mcp-vlei/src/mcp_vlei/report.py` | `9dafbd6b8e7ca309` |
| `packages/mcp-vlei/src/mcp_vlei/testing.py` | `2d09bacf57479f2e` |

- The installed `mcp` 2.2.0 SDK source: `mcp/server/extension.py`, `mcp/server/mcpserver/server.py`,
  `mcp/server/context.py`, `mcp/server/runner.py`, `mcp/server/session.py`, `mcp/client/client.py`,
  `mcp/shared/exceptions.py`, plus the `mcp_types` models, and a throwaway prototype to observe what
  an interceptor actually receives.

**Not read** (reading any of them would have been copying the answer):

- `spec/` (including `spec/SPEC.md` and `spec/schema.ts`, which the skill points to)
- `docs/`
- `examples/` other than this directory (including `examples/README.md`, which the skill points to)
- `packages/mcp-vlei/tests/`
- `packages/mcp-vlei/src/mcp_vlei/extension.py` and `packages/mcp-vlei/src/mcp_vlei/client.py`
- `packages/mcp-vlei/src/mcp_vlei/__init__.py`
- `skills/implementing-vlei/CONFORMANCE.md`
- `skills/vlei-identity/`

`server.py` does not import `mcp_vlei.extension` or `mcp_vlei.client`. Note that importing *any*
`mcp_vlei.*` submodule runs the package `__init__`, which loads those two modules into
`sys.modules` as a side effect; nothing here references them.

## What it is

- `server.py` — `MCPServer` (streamable HTTP, `127.0.0.1`, `PORT` default 8082) with one
  hand-written `Extension` subclass, `VleiIdentity`. It declares the capability, publishes
  `GET /.well-known/vlei`, stamps `org.gleif.vlei/requires` on the protected tool's `_meta`, runs
  checks 0–10 of SKILL.md section 4 in order, and refuses in the two shapes of section 5. Every
  protected call's result — allowed or refused — carries
  `_meta["org.gleif.vlei/report"] = VerificationReport(...).as_dict()`.
  - `list_events` — public; served to clients that never declared the extension.
  - `submit_filing(form, period, payload)` — requires `{"credential": "ECR", "role": $VLEI_ROLE}`.
- `tests/test_server.py` — 31 tests through the real SDK (in-process `mcp.Client` → `MCPServer`)
  against `mcp_vlei.testing.World`. Every refusal test asserts the failure layer **and** the report
  check it stopped at.

The verification pipeline is assembled from `mcp_vlei` components: `kel.WitnessKeyStates` +
`kel.verify_kel` (check 3 and the delegation evidence for 5), `signing.precheck_request` /
`verify_request` / `ReplayCache` (1–4), `chain.parse_stream` / `recompute_said` / `verify_issuance`
(6–8), `revocation.TelRevocationChecker` (9). `verifier.OfflineVerifier` is deliberately **not**
used — see REPORT.md, gap 6.

## Run

```bash
# from the repository root
export VLEI_LE_CREDENTIAL=path/to/le.cesr          # kli vc export --full of this server's LE credential
export VLEI_ACCEPTED_ROOTS=E...                     # root AID(s), comma-separated; empty refuses to start
export VLEI_WITNESS_URL=http://localhost:5642       # keripy witness: KELs and TELs are read here
export VLEI_ROLE=regulatory-filing                  # optional, this is the default
export PORT=8082                                    # optional, this is the default
# export VLEI_PUBLIC_URL=http://127.0.0.1:8082      # optional: base of discovery.wellKnown
python examples/skill-server/server.py
```

- MCP endpoint: `http://127.0.0.1:8082/mcp`
- Well-known: `http://127.0.0.1:8082/.well-known/vlei`

`mcp_vlei` is not installed as a distribution in this repository; `server.py` falls back to
`packages/mcp-vlei/src` on `sys.path` when the import fails. `pip install -e packages/mcp-vlei`
works too.

The server refuses to start without `VLEI_LE_CREDENTIAL`, a non-empty `VLEI_ACCEPTED_ROOTS`, or
`VLEI_WITNESS_URL`. Logs carry the LEI, role, credential SAID and delegated AID — never the
credential.

## Test

```bash
python -m pytest examples/skill-server/tests -q
```

```
...............................                                          [100%]
31 passed in 2.30s
```

The security checks were also mutation-tested (in a scratch copy, not committed): removing check 5
fails the "someone else's credential, own key" and "delegated by someone else" tests; verifying
under a key the request carries fails the "claim the agent's AID with your own key" test; removing
the issuance-anchoring check fails the forged-credential test; checking revocation for the leaf only
fails the revoked-LE test; recording replay before the signature check fails the replay tests.
Before the LE-binding rule (REPORT.md, gap 1) was added, an ECR issued by a QVI straight off its
own QVI credential, naming an arbitrary LEI, was confirmed to pass every check the skill lists.

An HTTP self-test was also run once: `python server.py` as a subprocess on a spare port, a
temporary witness serving a `World` over real HTTP, and the SDK's HTTP client — capability,
well-known, `list_events`, an allowed filing, `digest_mismatch`, `missing_credential`, `revoked`
after a live revocation, and `-32021` for a client without the extension. Both processes were
stopped afterwards.
