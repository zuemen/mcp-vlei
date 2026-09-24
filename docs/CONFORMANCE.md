# Conformance: every normative statement, and where it lives

One row per normative statement in [`spec/SPEC.md`](../spec/SPEC.md), with the code that implements
it and the test that holds it. A specification whose requirements cannot be traced to running code
is a document; this table is the difference.

Reviewed against the repository at v0.2. Where a row says **gap**, it says so.

| # | Section | Requirement | Implementation | Test |
|---|---|---|---|---|
| 1 | Motivation | `clientInfo` / `serverInfo` **MUST NOT** be used for trust decisions | Nothing in the package reads either; identity comes only from `_meta` credentials — `extension.py::_verify` | Absence is the property. `test_extension.py::test_missing_credential_is_refused` shows a caller with a name and no credential is refused |
| 2 | Design principles | A deployment **MAY** require both OAuth and vLEI | `VleiIdentity` sits in `extensions`, leaving the SDK's auth untouched | `test_extension.py::test_public_tool_needs_nothing` |
| 3 | Two verification modes | An implementation **MUST** support mode (a) and **SHOULD** support mode (b) | (a) `chain.py` + `verifier.OfflineVerifier`, published by `VleiIdentity.well_known_document()`; (b) `attest.py` | `test_chain.py` (15 tests), `test_issuance.py` (10); `test_attest.py` (8 tests) |
| 4 | Two verification modes | A relying party checking a counterparty's credential **MUST** verify the chain itself | `client.py::VleiClient.connect` uses `OfflineVerifier`, never `/presentations` | `test_acceptance.py::test_1` prints the established root; `test_chain.py::test_walks_to_the_root` |
| 5 | Two verification modes | A verifier **MUST** validate the attesting party's own identity before accepting an attestation | `client.py::_maybe_accept_attestation` raises when `server_identity` is `None`; otherwise the attester must be the verified server's AID or delegated by it, its key state is read from its key event log at a witness — never from what the server declares — and the attestation must be about this client | `test_attest.py::test_a_key_the_attester_chose_for_itself_does_not_help`; `test_client.py::test_an_attestation_is_not_checked_under_a_key_the_server_claims`, `::test_an_attestation_signed_by_someone_other_than_the_server_is_refused`, `::test_an_attestation_about_someone_else_is_refused` |
| 6 | Delegation | A verifier **MUST** establish the holder from the credential | `extension.py::_presented` — the issuee (`a.i`) of the named credential, or of the chain's leaf | `test_chain.py::test_walks_to_the_root` asserts the issuee chain |
| 7 | Delegation | An implementation **MUST** read the issuee out of the credential | same as 6 — the value is parsed, never taken from `_meta` | same as 6 |
| 8 | Delegation | An implementation **MUST NOT** accept a caller's assertion of whose record to consult | `_verify` reads the holder from the parsed credential and never falls back to `signature.aid`; `delegatedAid` must equal the signer | `test_extension.py::test_an_agent_the_holder_delegated_to_is_allowed` records holder and delegate separately; `::test_a_delegated_aid_claim_must_match_the_signer` |
| 9 | Request signing | A verifier **MUST** reject a signature outside the freshness window | `signing.py::verify_request` step 1 | `test_signing.py::test_expired_signature_is_stale`, `::test_freshness_window_is_configurable` |
| 10 | Request signing | A verifier **MUST** cache `(aid, digest, ts)` for at least the freshness window | `signing.py::ReplayCache`, evicting at `window_seconds * 2` — deliberately longer than required | `test_signing.py::test_replay_is_rejected`, `test_report.py` ordering |
| 11 | Errors | The text **MUST** name the failure layer | `errors.py::VleiError.to_text`; every raise site passes a layer | Nine tests assert on the layer by name, not on "refused" |
| 12 | Security | A stricter deployment **SHOULD** shorten the window and **MAY** add a challenge | `freshness_seconds` is a constructor argument | `test_signing.py::test_freshness_window_is_configurable` |
| 13 | Security | High-value tools **SHOULD** set `ttlMs` to zero | `VleiVerifier(ttl_ms=…)`, advertised in `settings()` | `test_extension.py::test_settings_are_the_capability_value` |
| 14 | Security | A production deployment **SHOULD** use Signify so private keys stay with the holder | `signing.py::CommandSigner` — the agent never holds a key; `examples/my-agent/kli_signer.py` signs through the keystore | Exercised end to end by the acceptance suite, which signs every call this way |
| 15 | Security | An attestation **MUST NOT** be accepted from an unverified party | same as 5 | same as 5 |
| 17 | Whose key | A verifier **MUST** verify under the signer's current key state from its key event log, **MUST NOT** use a key the request carries, and **MUST** refuse a request it cannot check | `kel.py::WitnessKeyStates` + `verify_kel`; `extension.py::_key_state`; `signing.py::verify_request` takes the key state, never `_meta` | `test_extension.py::test_someone_elses_credential_with_your_own_key_is_refused`, `::test_the_key_a_caller_supplies_is_not_the_key_that_counts`, `::test_a_request_without_a_verifiable_signature_is_refused`, `::test_a_key_rotated_away_no_longer_verifies`; `test_kel.py` (20); live: `test_acceptance.py::test_2c` |
| 18 | Whose key | The signer **MUST** be the holder, or delegated by the holder in the holder's key event log | `extension.py::_authorized`; the delegation anchor is checked in `kel.py::verify_kel` | `test_extension.py::test_a_delegate_of_someone_else_is_refused`, `::test_a_delegation_the_holder_never_approved_is_refused`; `test_kel.py::test_a_delegation_the_delegator_never_approved_is_refused` |
| 19 | Whose key | Every credential **MUST** be shown to have been issued by the identifier it names | `chain.py::verify_issuance`, called by `OfflineVerifier` for every link | `test_issuance.py` (10, one against a real `kli` export); `test_extension.py::test_a_credential_written_by_the_caller_is_refused` |
| 20 | Whose key | Revocation **MUST** be established for every credential in the chain, and a log without the issuance is *not established* | `extension.py::_verify` checks each of `result.chain_saids`; `revocation.py` requires an `iss` | `test_extension.py::test_a_revoked_link_above_the_ecr_refuses_the_call`, `::test_a_live_log_that_never_saw_the_issuance_is_not_read_as_valid` |
| 22 | Whose key | An ECR or OOR **MUST** be issued under an LE credential naming the same LEI, an LE credential under a QVI credential, and every edge **MUST** point at the schema it declares | `chain.py::verify_vlei_chain`, called by `OfflineVerifier` | `test_issuance.py::test_an_ecr_a_qvi_issued_without_any_le_is_refused`, `::test_an_ecr_naming_another_entitys_lei_is_refused`, `::test_an_edge_must_point_at_the_type_it_declares` |
| 21 | Request signing | A replay entry **MUST** be recorded only after the signature verified | `signing.py::verify_request` records last | `test_extension.py::test_a_forged_request_cannot_lock_out_the_real_one` |
| 16 | Security | A verifier **SHOULD** record which attesting party a decision rested on | `VerificationResult.attested_by`, set by `verify_attestation` | `test_attest.py::test_roundtrip` asserts `source == "attestation"`; `attested_by` carries the AID |

## The defect that every green test missed (2026-09-24)

Until this date the request signature was verified under **the key the request carried**
(`_meta["org.gleif.vlei/verkey"]`), and a request that carried no key skipped the signature checks
and was allowed. Delegation was recorded but never checked, and a credential's issuance was never
checked either — only that its SAIDs recomputed. A credential is sent with every call, so any
server that had ever been called by a holder, or anyone who had seen one of their requests, could
present that holder's ECR with a key of their own and be accepted as them. Or write an ECR naming a
real LE as issuer and themselves as holder: every SAID recomputes.

Every test passed, because every test signed with the right key. The fix is rows 17–22 above (22 was found afterwards, by the server that
`skills/implementing-vlei/` produced — `examples/skill-server/`); the
tests that would have caught it are named there, each written first and watched fail against the
old code. The console and the acceptance suite now sign with the agent's key inside the KERI
keystore — the console used to sign with a random key, which only worked because of this defect.

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

- **Duplicity is not detected.** `kel.py` verifies a key event log completely — self-addressing
  prefix, SAIDs, prior digests, signatures to threshold, witness receipts to threshold, pre-rotation
  commitments, delegation anchors — but it asks one witness. Two conflicting logs for one prefix,
  each internally valid, are what watchers exist to catch; this implementation has none.
- **The subset of KERI is `kli`'s.** Single-sig and numeric thresholds, Ed25519, Blake3-256. Weighted
  thresholds, other key or digest codes, and multi-sig signers of a single-pass request are refused,
  not guessed at.
- **"Revoke the delegation" is not implemented.** The specification describes two revocation
  switches; the ECR one works. Withdrawing one agent's delegation without touching the holder's
  credential needs a KERI mechanism — a delegator-side superseding rotation — that nothing here
  performs or checks.
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
pytest packages/mcp-vlei/tests          # 143 tests, no containers required
pytest examples/association-server/tests -s   # end to end; needs the credential environment
```
