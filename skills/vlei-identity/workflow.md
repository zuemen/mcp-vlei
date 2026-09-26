# vLEI Identity Workflow

A staged procedure for a session with an MCP server that declares `org.gleif.vlei/identity`.

Each stage is self-contained: it takes defined input, performs its own checks against its own source
of truth, and has an explicit pass condition. A stage is entered only when the previous stage passed.
Nothing is deferred to "we'll find out when the call fails" — the design goal is that every failure is
detected at the earliest stage where the information to detect it exists.

Read `SKILL.md` in this directory for the rules each stage enforces and for the response to each
failure layer.

---

## Stage 0 — Load credentials and keys

**Input:** configured credential path, key store, accepted roots, verifier URL.

**Checks**
- The ECR credential file exists and parses as a CESR-encoded ACDC.
- A signer is available for the AID you will sign with — a keystore you sign *through* (`kli sign`
  in the reference agent, Signify in production), so the private key is never in your process — and
  that AID is either the ECR holder's AID or a delegated AID under that holder's KEL. The server
  checks exactly this, against the key event logs at a witness.
- `acceptedRoots` is non-empty.
- The verifier is reachable, or offline verification is configured — knowing that offline
  verification does not establish revocation (Stage 2).

**Pass condition:** all four — a usable credential, a usable signer, at least one accepted root, and
a verification route for the server's credential.

**On failure:** stop before connecting. Report which of the four is missing. An empty
`acceptedRoots` is a configuration error, not a default-to-accept-anything condition.

---

## Stage 1 — `server/discover`

**Input:** server URL.

**Checks**
- Read `capabilities.extensions["org.gleif.vlei/identity"]` — the server's `ServerCapabilities`,
  not `serverInfo`, which has no `extensions` member. It is empty unless protocol 2026-07-28 was
  negotiated.
- Obtain the server's LE credential from the result's `_meta["org.gleif.vlei/credential"]`, or, if
  absent, fetch `discovery.wellKnown`.
- Record which source the credential came from — it appears in the audit record.

**Pass condition:** an LE credential has been obtained, or the server has been established to present
none.

**On failure (no extension declared, no credential anywhere):** the server is **unverified**. Do not
call it verified. Apply the configured policy: warn and continue, or stop. Skip to Stage 3 only if
policy permits continuing.

---

## Stage 2 — Verify the LE credential

**Input:** the LE credential from Stage 1, `acceptedRoots`.

**Checks**, in the order the package runs them, because each one makes the next meaningful:
1. **Recompute each SAID** and confirm it matches the one presented → otherwise `chain_invalid`.
   Nothing below means anything until the document is the document it claims to be.
2. **Walk the chain** along the `e` edges — LE → QVI → root — requiring each link's issuer to be the
   previous link's issuee, until an issuer in `acceptedRoots` → otherwise `chain_invalid` for a
   broken link, `unknown_root` for a chain that ends at a root you do not accept. Steps 1 and 2
   interleave: each link is re-hashed as the walk reaches it.
3. **Verify each issuance**: every credential was issued by the identifier it names, anchored in
   that issuer's key event log as carried in the stream → otherwise `chain_invalid`.
4. **Check the vLEI shape**: each edge points at a credential of the schema it declares, the LE
   credential sits under a QVI credential, and an LEI is present → otherwise `chain_invalid`.
5. **Check revocation** for every credential in the chain, in its issuer's live TEL → otherwise
   `revoked`, or `chain_invalid` when a log cannot be read or records no issuance. The reference
   `VleiClient` does this through its `witness_url`, and by default refuses a server whose logs it
   cannot read. Only a client constructed with `on_unchecked_revocation="warn"` connects without the
   check; its result carries `revocation_checked=False`. Then the server is verified *except for
   revocation*: say so, and never report its revocation as checked.
6. If the discover result carried a signature, verify it under the server AID's current key state
   and check freshness. The specification does not define this signature yet, and the reference
   client does not check one.

**Pass condition:** 1–4; 5 whenever the live logs can be reached (otherwise, record that revocation
was not established); 6 whenever a signature is present.

**On failure:** **stop.** Report the failure layer by name. Do not call any tool on this server,
including public ones. An organization that cannot prove it is who it claims is not one to send a
member's email address to.

Cache the result per the configured `ttlMs`. Note that a revocation takes effect no later than cache
expiry; for high-value tools the TTL should be zero.

---

## Stage 3 — `tools/list`

**Input:** a verified (or explicitly-unverified-and-permitted) session.

**Checks**
- For each tool, read `_meta["org.gleif.vlei/requires"]`.
- Build the set of tools that need a credential and, for each, the required `role` and `scope`.
- Tools without that key are public.

**Pass condition:** the requirement map is built. This stage does not fail; a server with no
protected tools yields an empty map.

---

## Stage 4 — Entitlement check before choosing a tool

**Input:** the requirement map from Stage 3; the role and scope carried by your own ECR.

**Checks**, for the tool the model intends to call:
- Does the tool require a credential at all? If not, go to Stage 5 without presenting one.
- Does your ECR role satisfy the required `role`?
- Do the arguments you intend to send fall inside the tool's declared `scope`?

**Pass condition:** role satisfied and arguments within scope.

**On failure:** **do not call.** Tell the user which role or limit is required, which you hold, and
that a new ECR must be issued by their legal entity. This is the stage that makes the permission
useful — it is declared in the schema precisely so the decision can be made here rather than by
attempting the call.

---

## Stage 5 — Sign and call

**Input:** the tool name, the arguments, the ECR credential, the delegated AID, the signer.

**Actions**
1. Canonicalize `params` with RFC 8785, **excluding `_meta`**.
2. `digest = base64url(sha256(canonical))`.
3. `ts` = now, RFC 3339, UTC.
4. Sign `method + "\n" + ts + "\n" + digest` through the signer — the keystore returns a signature;
   you never hold the key.
5. Attach to `params._meta` four members: the ECR credential (`org.gleif.vlei/credential`), the
   signature (`org.gleif.vlei/signature`), the delegated AID (`org.gleif.vlei/delegatedAid`, equal
   to `signature.aid`), and which credential in the stream is being presented
   (`org.gleif.vlei/credentialSaid`). The first two are required — without either the server answers
   `missing_credential`; the last two are optional in the schema, and the reference agent sends both.
6. Send.

**Pass condition:** the request is sent with the credential and the signature present, and with the
delegated AID and credential SAID wherever you have them — all four, in the reference deployment.

The package also sends `org.gleif.vlei/verkey`. It is informational and never used for verification:
the server reads the signer's key state from its key event log, never from the request.

**Note:** arguments must not change between step 1 and step 6. Any change produces
`digest_mismatch` at the counterparty, which is the intended behavior and is not retryable.

---

## Stage 6 — Handle the response

**Input:** the tool result.

**Checks**
- `isError: false` → the call succeeded. Record the LEI, role, delegated AID, and credential SAID
  that were presented, for the audit trail.
- `isError: true` → read the named failure layer and apply the response from the table under
  *When a call is rejected* in `SKILL.md`:
  - `stale_signature` → return to Stage 5 and retry **once**.
  - `scope_exceeded` → you may offer the user a retry with in-scope arguments; ask first.
  - `missing_credential` → nothing was presented. Return to Stage 4: if your credential covers the
    tool, present it in Stage 5; if not, explain what is needed. This is a first presentation, not
    a retry.
  - every other layer → stop and report. That includes `invalid_signature` and `chain_invalid`,
    whether the message names a failed check or a key state or revocation that could not be
    established.
- JSON-RPC error `-32021` → the extension was not declared at `initialize`. This is a configuration
  problem; reconnect with the capability declared.

**Pass condition:** the result was either consumed or the failure was reported with its layer named.

---

## Stage 7 — Attestation handling (mode (b))

**Entered when** a result carries `_meta["org.gleif.vlei/attestation"]`.

**Checks**
1. Verify the attesting party's own identity under Stages 1–2 — an attestation from an unverified
   party is worth nothing.
2. Verify the attestation's signature under `verifierAid`'s key state.
3. Check `verifiedAt` against the configured acceptable age for attestations.
4. Confirm `subjectAid` is the party the attestation was requested about.

**Pass condition:** all four.

**On success:** accept the statement, and record **whose** attestation it was. The user is trusting
that party's verification, not one you performed.

**On failure:** discard the attestation. Do not fall back to accepting the claim unverified.

---

## Stage map

```mermaid
flowchart TD
    S0["Stage 0<br/>load ECR, delegated AID key,<br/>accepted roots"]
    S1["Stage 1<br/>server/discover<br/>or /.well-known/vlei"]
    S2{"Stage 2<br/>verify server LE<br/>SAID → chain → root<br/>→ issuance → vLEI shape<br/>→ revocation (if reachable)"}
    S3["Stage 3<br/>tools/list<br/>read org.gleif.vlei/requires"]
    S4{"Stage 4<br/>does my role and scope<br/>cover this tool?"}
    S5["Stage 5<br/>digest → sign<br/>method + ts + digest<br/>→ tools/call"]
    S6{"Stage 6<br/>isError?"}
    S7["Stage 7<br/>attestation present:<br/>verify attester first"]
    STOP["STOP<br/>report the failure layer"]
    EXPLAIN["DO NOT CALL<br/>explain the role or scope needed"]
    DONE["Result accepted<br/>record LEI, role, delegated AID, SAID"]

    S0 --> S1 --> S2
    S2 -->|"pass"| S3
    S2 -->|"chain_invalid / revoked / unknown_root"| STOP
    S3 --> S4
    S4 -->|"covered"| S5
    S4 -->|"not covered"| EXPLAIN
    S5 --> S6
    S6 -->|"no"| S7 --> DONE
    S6 -->|"stale_signature"| S5
    S6 -->|"missing_credential"| S4
    S6 -->|"any other layer"| STOP
```

The loop back from stage 6 to stage 5 is the only retry in the whole procedure. The one from
`missing_credential` to stage 4 is not a retry — nothing was presented the first time. Every other
failure is a state of the world that a retry cannot change.
