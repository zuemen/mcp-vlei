# Conformance: every normative statement, and where it lives

One row per normative statement in [`spec/SPEC.md`](../spec/SPEC.md), with the code that implements
it and the test that holds it. A specification whose requirements cannot be traced to running code
is a document; this table is the difference.

Reviewed against the repository at v0.2. Where a row says **gap**, it says so.

| # | Section | Requirement | Implementation | Test |
|---|---|---|---|---|
| 1 | Motivation | `clientInfo` / `serverInfo` **MUST NOT** be used for trust decisions | Nothing in the package reads either; identity comes only from `_meta` credentials — `extension.py::_verify` | Absence is the property. `test_extension.py::test_missing_credential_is_refused` shows a caller with a name and no credential is refused |
| 2 | Design principles | A deployment **MAY** require both OAuth and vLEI | `VleiIdentity` sits in `extensions`, leaving the SDK's auth untouched | `test_extension.py::test_public_tool_needs_nothing` |
| 3 | Two verification modes | An implementation **MUST** support mode (a) and **SHOULD** support mode (b) | (a) `chain.py` + `verifier.OfflineVerifier`, published by `VleiIdentity.well_known_document()`; (b) `attest.py` | `test_chain.py` (12 tests); `test_attest.py` (6 tests) |
| 4 | Two verification modes | A relying party checking a counterparty's credential **MUST** verify the chain itself | `client.py::VleiClient.connect` uses `OfflineVerifier`, never `/presentations` | `test_acceptance.py::test_1` prints the established root; `test_chain.py::test_walks_to_the_root` |
| 5 | Two verification modes | A verifier **MUST** validate the attesting party's own identity before accepting an attestation | `client.py::_maybe_accept_attestation` raises when `server_identity` is `None` or no verkey was established | `test_attest.py::test_a_key_the_attester_chose_for_itself_does_not_help` |
| 6 | Delegation | A verifier **MUST** establish the holder from the credential | `extension.py::_issuee_of`, anchored on the presented SAID | `test_chain.py::test_walks_to_the_root` asserts the issuee chain |
| 7 | Delegation | An implementation **MUST** read the issuee out of the credential | same as 6 — the value is parsed, never taken from `_meta` | same as 6 |
| 8 | Delegation | An implementation **MUST NOT** accept a caller's assertion of whose record to consult | `_verify` uses `_issuee_of(credential, said)`; the caller's `delegatedAid` only labels who acted | `test_extension.py::test_valid_credential_is_allowed` records holder and delegate separately |
| 9 | Request signing | A verifier **MUST** reject a signature outside the freshness window | `signing.py::verify_request` step 1 | `test_signing.py::test_expired_signature_is_stale`, `::test_freshness_window_is_configurable` |
| 10 | Request signing | A verifier **MUST** cache `(aid, digest, ts)` for at least the freshness window | `signing.py::ReplayCache`, evicting at `window_seconds * 2` — deliberately longer than required | `test_signing.py::test_replay_is_rejected`, `test_report.py` ordering |
| 11 | Errors | The text **MUST** name the failure layer | `errors.py::VleiError.to_text`; every raise site passes a layer | Nine tests assert on the layer by name, not on "refused" |
| 12 | Security | A stricter deployment **SHOULD** shorten the window and **MAY** add a challenge | `freshness_seconds` is a constructor argument | `test_signing.py::test_freshness_window_is_configurable` |
| 13 | Security | High-value tools **SHOULD** set `ttlMs` to zero | `VleiVerifier(ttl_ms=…)`, advertised in `settings()` | `test_extension.py::test_settings_are_the_capability_value` |
| 14 | Security | A production deployment **SHOULD** use Signify so private keys stay with the holder | `signing.py::CommandSigner` — the agent never holds a key; `examples/my-agent/kli_signer.py` signs through the keystore | Exercised end to end by the acceptance suite, which signs every call this way |
| 15 | Security | An attestation **MUST NOT** be accepted from an unverified party | same as 5 | same as 5 |
| 16 | Security | A verifier **SHOULD** record which attesting party a decision rested on | `VerificationResult.attested_by`, set by `verify_attestation` | `test_attest.py::test_roundtrip` asserts `source == "attestation"`; `attested_by` carries the AID |

## What this review changed

Three statements had no implementation behind them when the table was first written.

**Mode (a) at the regulator (#3).** `examples/regulator/filing-server/` published nothing at
`/.well-known/vlei`. A regulator is exactly the party an agent should be able to identify *before*
filing a return with it, so the omission was the wrong way round. Added — and the endpoint serves
the credential as published, parsing nothing, which is the claim that example exists to make.

**Recording the attesting party (#16).** `verify_attestation` returned what the attestation
established but not who had established it, so a relying party could not say whose judgment a
decision rested on. `VerificationResult.attested_by` now carries the attesting AID, and the result
is additionally marked `revocation_checked=False` and `signatures_checked=False` — accepting an
attestation is trusting a party that says it checked, not checking.

**An empty accepted-roots set (#4).** Already refused, in both `VleiVerifier` and
`OfflineVerifier`, and worth calling out because the failure mode is silent: an empty list read as
"accept anything" would pass every test in this table while accepting every forged chain.

## What is deliberately not claimed

The table would be dishonest without these.

- **Issuer signatures are not verified offline.** `chain.py` establishes that a chain is internally
  sound and reaches an accepted root. Verifying each issuer's signature means replaying that
  issuer's key event log, which is keripy's job and is not reimplemented here. Every result says so
  (`signatures_checked=False`), and the report renders it as a caveat.
- **`-32021` is defined but not emitted.** `errors.ExtensionRequired` builds the error; no server in
  this repository refuses a connection for want of the capability, because all of them serve public
  tools to clients that never declare it. That is the additive property working as intended, and it
  means the code path is untested in anger.

  It was also **wrong** until a conformance test caught it: `data.requiredCapabilities` was a list
  of identifiers, where the 2026-07-28 revision defines a `ClientCapabilities` object. Untested and
  incorrect turned out to be the same path. See
  [`skills/implementing-vlei/CONFORMANCE.md`](../skills/implementing-vlei/CONFORMANCE.md).
- **Scope comparison is a default, not a standard.** `signing.scope_satisfied` implements one
  reasonable algebra. The specification fixes where scope lives and that it must be checked, not how
  — a deployment with different semantics replaces the function.

## Running the checks behind this table

```bash
pytest packages/mcp-vlei/tests          # 77 tests, no containers required
pytest examples/association-server/tests -s   # end to end; needs the credential environment
```
