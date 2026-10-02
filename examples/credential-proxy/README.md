# Credential proxy — Claude talks to the gateway with a vLEI identity

Claude Desktop and Claude Code start local MCP servers over STDIO and know nothing about vLEI. This
proxy is one of those servers. Claude sees the labour-insurance gateway's tools through it, and
every call Claude makes reaches the gateway signed and carrying an ECR credential.

The labour-insurance system is **simulated**: it is not connected to the Bureau of Labor Insurance.
**All identities are fictional. The root of trust is self-hosted for demonstration.**

```
Claude Desktop / Claude Code ──STDIO──► proxy.py ──HTTP (MCP 2026-07-28)──► agentgateway :3000
                                           │                                   │ extAuthz
                                           │ kli sign (key stays in            ▼
                                           │ the keri-cli keystore)        vlei-authz ── witness
                                           ▼                                   │
                                     relay.log (one line per call)             ▼
                                                                    labor-insurance-sim
```

## What it does, and nothing else

1. **Verifies the gateway before showing anything.** It reads the operator's LE credential from
   `/.well-known/vlei` at the gateway's origin. That is the *Simulated Labour Insurance Office
   (fictional)*, LEI `984500LABORSIM000054`, from `scripts/bootstrap-regulator.sh`. The proxy
   verifies the chain to an accepted root, then reads the issuers' transaction event logs from the
   witness for revocation. If any of that fails, Claude is shown **no tools**, nothing is signed or
   sent, and the reason is in the server's instructions and the log.
2. **Relays the tool list as it is.** Each tool's `_meta["org.gleif.vlei/requires"]` is kept. Each
   description gains one sentence in Chinese and English on the role required, e.g.
   `vLEI：需要 ECR 憑證，職務角色為 labor-insurance-filing… / vLEI: Requires an ECR credential with
   the role labor-insurance-filing…`.
3. **Signs every call** with `kli sign` in the `keri-cli` keystore, as the agent's delegated AID.
   The private key is never read by this process. Each call carries the `credential`,
   `credentialSaid`, `delegatedAid` and `signature` keys under the extension's namespace. It is the
   package's own `VleiClient` doing the signing.
4. **Returns what the gateway answered.** An allowed call comes back as the simulator sent it, with
   the gateway's verification report in `_meta`. A refusal's first line is its failure layer, in
   the gateway's words:

   ```
   revoked: credential E… was revoked by its issuer E… (TEL …)
   ```

Which identity it presents is fixed when it starts, by `VLEI_PROFILE`. **No tool switches it**:
the model cannot choose whose credential it acts under. If the same profile's credential is
re-issued after a revocation, the new one is used without a restart. The profile's name never
changes.

## Profiles

| `VLEI_PROFILE` | Presents | Made by | Expected |
|---|---|---|---|
| `demo` (default) | Demo Staffing Co., Ltd. (fictional), ECR `labor-insurance-filing`, Wang Xiao-Ming (fictional) | `scripts/bootstrap-credentials.sh` | enrol passes; salary adjustment `role_mismatch`; a start date 15 days out `scope_exceeded` |
| `forged` | Large Semiconductor Corp. (fictional), the same role, Zhang San (fictional) — a chain from a second self-made root | `scripts/bootstrap-forged.sh` | every call `unknown_root` |

## Configure Claude

Prerequisites: the stack is running (`scripts/reset-demo.sh`), the operator's LE has been issued
(`scripts/bootstrap-regulator.sh`; `reset-demo.sh` runs it), and, for `forged`,
`scripts/bootstrap-forged.sh` has been run.

The Python that runs the proxy needs `mcp==2.2.0` and this repository's `packages/mcp-vlei`
(`pip install -e packages/mcp-vlei`). Docker Desktop must be running: `kli sign` runs in the
`keri-cli` container.

### Claude Desktop

Add this to `claude_desktop_config.json` (Settings → Developer → Edit Config), then restart Claude
Desktop:

```json
{
  "mcpServers": {
    "labor-insurance-vlei": {
      "command": "python",
      "args": ["<repo>\\examples\\credential-proxy\\proxy.py"],
      "env": { "VLEI_PROFILE": "demo" }
    }
  }
}
```

Use the full path to `python.exe` if `python` is not on the PATH Claude Desktop starts with.

### Claude Code

```bash
claude mcp add labor-insurance-vlei --env VLEI_PROFILE=demo -- python <repo>/examples/credential-proxy/proxy.py
claude mcp list        # labor-insurance-vlei: ✓ Connected
```

### Switching profiles

Change `VLEI_PROFILE` and restart the server; nothing inside a conversation can do it.

- **Claude Desktop:** edit the `env` value and restart the app.
- **Claude Code:** remove the server and add it again with the other profile:

  ```bash
  claude mcp remove labor-insurance-vlei
  claude mcp add labor-insurance-vlei --env VLEI_PROFILE=forged -- python <repo>/examples/credential-proxy/proxy.py
  ```

Keep one profile configured at a time. Two entries would list the same tools twice, and Claude
would pick one.

### The `vlei-identity` skill

[`skills/vlei-identity/`](../../skills/vlei-identity/) tells the model how to read `requires`, when
to present a credential, and how to explain a refusal by its layer.

- **Claude Code:** copy the folder to `~/.claude/skills/vlei-identity/` (every project) or to
  `.claude/skills/vlei-identity/` in a project.
- **Claude Desktop:** zip the folder and upload it under Settings → Capabilities → Skills.

## Configuration

| Variable | Default | |
|---|---|---|
| `VLEI_PROFILE` | `demo` | `demo` or `forged`; anything else stops the proxy at start |
| `VLEI_GATEWAY_URL` | `http://localhost:3000/mcp` | the gateway's MCP endpoint; `/.well-known/vlei` is read at its origin |
| `VLEI_WITNESS_URL` | from `scripts/.env`, else `http://localhost:5642` | where the issuers' logs are read for revocation |
| `VLEI_ACCEPTED_ROOTS` | `credentials/env.json` `acceptedRoots` | roots the gateway's LE must chain to |
| `VLEI_PROXY_LOG` | `examples/credential-proxy/relay.log` | one line per relayed call |

## The log

One line per relayed call, to the log file and to stderr. Claude Desktop shows stderr in its MCP
log.

```
2026-10-01T14:02:11+08:00 profile=demo tool=enroll_employee result=allowed reason=-
2026-10-01T14:02:40+08:00 profile=demo tool=adjust_insured_salary result=refused reason=role_mismatch
2026-10-01T14:05:02+08:00 profile=forged tool=enroll_employee result=refused reason=unknown_root
```

- **What each line holds:** time, profile, tool, and result (`allowed`, `refused`, `system` when
  the system refused after verification passed, or `unavailable`), plus the failure layer.
- **What is never logged:** the credential and the arguments.
- **Hardening:** fields are restricted to `[A-Za-z0-9_.:-]`, so a tool name cannot forge a line.

A start-up line also records whether the gateway was verified: its LEI, its root, and whether
revocation was checked.

## Tests

```bash
pytest examples/credential-proxy/tests -q                       # no Docker
VLEI_LIVE=1 pytest examples/credential-proxy/tests/test_live.py -v           # the running stack
VLEI_LIVE=1 VLEI_LIVE_REVOKE=1 pytest examples/credential-proxy/tests/test_live.py -v
```

`test_proxy.py` runs the whole relay against the regulator scenario's stand-in gateway, which
makes vlei-authz's real decision over an in-process KERI world. It covers the five outcomes
(passes, `role_mismatch`, `scope_exceeded`, `unknown_root`, `revoked`) and also checks:

- what goes over the wire;
- that an unverifiable gateway gets nothing;
- that Claude sees exactly the gateway's tools and no other;
- that the profile is fixed at start;
- that the log never holds the credential or the arguments.

`test_live.py` starts the proxy as a STDIO subprocess, as Claude does, against agentgateway on
:3000. The revocation test revokes the demo ECR, waits for `revoked`, then re-issues it and checks
that the new credential is presented. That changes the shared environment, hence the second flag.
