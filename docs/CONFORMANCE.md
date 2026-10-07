# Conformance: every normative statement, and where it lives

One row per normative statement in [`spec/SPEC.md`](../spec/SPEC.md), with the code that implements
it and the test that holds it. A specification whose requirements cannot be traced to running code
is a document; this table is the difference.

Reviewed against the repository at v0.3. Where a row says **gap**, it says so.

| # | Section | Requirement | Implementation | Test |
|---|---|---|---|---|
| 1 | Motivation | `clientInfo` / `serverInfo` are self-reported, not verified by the protocol, and **SHOULD NOT** be relied on for security decisions | Nothing in the package reads either; identity comes only from `_meta` credentials — `extension.py::_verify` | Absence is the property. `test_extension.py::test_missing_credential_is_refused` shows a caller with a name and no credential is refused |
| 2 | Design principles | A deployment **MAY** require both OAuth and vLEI | `VleiIdentity` sits in `extensions`, leaving the SDK's auth untouched | `test_extension.py::test_public_tool_needs_nothing` |
| 3 | Two verification modes | An implementation **MUST** support mode (a) and **SHOULD** support mode (b) | (a) `chain.py` + `verifier.OfflineVerifier`, published by `VleiIdentity.well_known_document()`; (b) `attest.py` | `test_chain.py` (15 tests), `test_issuance.py` (10); `test_attest.py` (8 tests) |
| 4 | Two verification modes | A relying party checking a counterparty's credential **MUST** verify the chain itself | `client.py::VleiClient.connect` uses `OfflineVerifier`, never `/presentations` | `test_acceptance.py::test_1` prints the established root; `test_chain.py::test_walks_to_the_root` |
| 5 | Two verification modes | A verifier **MUST** validate the attesting party's own identity before accepting an attestation | `client.py::_maybe_accept_attestation` raises when `server_identity` is `None`; otherwise the attester must be the verified server's AID or delegated by it, its key state is read from its key event log at a witness — never from what the server declares — and the attestation must be about this client | `test_attest.py::test_a_key_the_attester_chose_for_itself_does_not_help`; `test_client.py::test_an_attestation_is_not_checked_under_a_key_the_server_claims`, `::test_an_attestation_signed_by_someone_other_than_the_server_is_refused`, `::test_an_attestation_about_someone_else_is_refused` |
| 6 | Delegation | A verifier **MUST** establish the holder from the credential | `extension.py::_presented` — the issuee (`a.i`) of the named credential, or of the chain's leaf | `test_chain.py::test_walks_to_the_root` asserts the issuee chain |
| 7 | Delegation | An implementation **MUST** read the issuee out of the credential | same as 6 — the value is parsed, never taken from `_meta` | same as 6 |
| 8 | Delegation | An implementation **MUST NOT** accept a caller's assertion of whose record to consult | `_verify` reads the holder from the parsed credential and never falls back to `signature.aid`; `delegatedAid` must equal the signer | `test_extension.py::test_an_agent_the_holder_delegated_to_is_allowed` records holder and delegate separately; `::test_a_delegated_aid_claim_must_match_the_signer` |
| 9 | Request signing | A verifier **MUST** refuse `exp ≤ ts`, a lifetime beyond its limit, `ts > now + skew` and `now > exp + skew` | `signing.py::_check_time`, called by `precheck_request` / `verify_request` | `test_signing.py::test_outside_the_window_is_stale`, `::test_a_signature_cannot_ask_for_a_long_life`, `::test_a_signature_that_expires_before_it_was_made_is_stale`, `::test_the_clock_tolerance_is_configurable` |
| 10 | Request signing | A verifier **MUST** claim `(aid, nonce)` atomically and refuse a repeat, keeping the claim until at least `exp + 2 × skew` (one skew past the last instant the time check accepts, so a copy checked just before it and claimed just after is still a repeat) | `replay.py::MemoryReplayStore`, `::SqliteReplayStore`; `signing.py::verify_request` claims last | `test_signing.py::test_replay_is_rejected`, `::test_the_claim_lasts_until_the_signature_can_no_longer_verify`, `::test_a_copy_checked_at_the_expiry_boundary_and_claimed_after_it_is_a_replay`; `test_replay.py::test_processes_sharing_one_file_let_exactly_one_claim_through` |
| 11 | Errors | The text **MUST** name the failure layer | `errors.py::VleiError.to_text`; every raise site passes a layer | Nine tests assert on the layer by name, not on "refused" |
| 12 | Security | A deployment **MAY** narrow the window | `freshness_seconds`, `max_lifetime_seconds` are constructor arguments | `test_signing.py::test_the_clock_tolerance_is_configurable` |
| 13 | Security | High-value tools **SHOULD** set `ttlMs` to zero | `VleiVerifier(ttl_ms=…)`, advertised in `settings()` | `test_extension.py::test_settings_are_the_capability_value` |
| 14 | Security | A production deployment **SHOULD** use Signify so private keys stay with the holder | `signing.py::CommandSigner` — the agent never holds a key; `examples/my-agent/kli_signer.py` signs through the keystore | Exercised end to end by the acceptance suite, which signs every call this way |
| 15 | Security | An attestation **MUST NOT** be accepted from an unverified party | same as 5 | same as 5 |
| 17 | Whose key | A verifier **MUST** verify under the signer's current key state from its key event log, **MUST NOT** use a key the request carries, and **MUST** refuse a request it cannot check | `kel.py::WitnessKeyStates` + `verify_kel`; `extension.py::_key_state`; `signing.py::verify_request` takes the key state, never `_meta` | `test_extension.py::test_someone_elses_credential_with_your_own_key_is_refused`, `::test_the_key_a_caller_supplies_is_not_the_key_that_counts`, `::test_a_request_without_a_verifiable_signature_is_refused`, `::test_a_key_rotated_away_no_longer_verifies`; `test_kel.py` (20); live: `test_acceptance.py::test_2c` |
| 18 | Whose key | The signer **MUST** be the holder, or delegated by the holder in the holder's key event log | `extension.py::_authorized`; the delegation anchor is checked in `kel.py::verify_kel` | `test_extension.py::test_a_delegate_of_someone_else_is_refused`, `::test_a_delegation_the_holder_never_approved_is_refused`; `test_kel.py::test_a_delegation_the_delegator_never_approved_is_refused` |
| 19 | Whose key | Every credential **MUST** be shown to have been issued by the identifier it names | `chain.py::verify_issuance`, called by `OfflineVerifier` for every link | `test_issuance.py` (10, one against a real `kli` export); `test_extension.py::test_a_credential_written_by_the_caller_is_refused` |
| 20 | Whose key | Revocation **MUST** be established for every credential in the chain, and a log without the issuance is *not established* | `extension.py::_verify` checks each of `result.chain_saids` with its issuer; given a key-state resolver (the extension and the client always give one), `revocation.py` reads issuance and withdrawal from the anchors in the issuer's key event log, resolved from the witnesses, and refuses a link whose issuer is unknown | `test_extension.py::test_a_revoked_link_above_the_ecr_refuses_the_call`, `::test_a_live_log_that_never_saw_the_issuance_is_not_read_as_valid`, `test_anchored_revocation.py::test_a_witness_that_leaves_out_the_withdrawal_does_not_hide_it`, `::test_an_unknown_issuer_is_not_a_reason_to_fall_back_to_the_witness_copy`, `::test_several_witnesses_given_to_the_client_are_compared` |
| 23 | Whose key | Given several witnesses, a signer's key event log that differs between them (duplicity) **MUST** be refused, and fewer answers than the quorum is *not established* | `kel.py::WitnessKeyStates.resolve` compares copies event by event; `VleiIdentity(witness_urls=…)` | `test_kel.py::test_a_controller_showing_two_witnesses_two_logs_is_refused`, `::test_a_witness_that_is_behind_is_not_duplicity`, `::test_too_few_witnesses_answering_is_refused`; `test_extension.py::test_a_signer_whose_log_is_forked_across_witnesses_is_refused`; live: all five AIDs agree across wan/wil/wes |
| 22 | Whose key | An ECR or OOR **MUST** be issued under an LE credential naming the same LEI, an LE credential under a QVI credential, and every edge **MUST** point at the schema it declares | `chain.py::verify_vlei_chain`, called by `OfflineVerifier` | `test_issuance.py::test_an_ecr_a_qvi_issued_without_any_le_is_refused`, `::test_an_ecr_naming_another_entitys_lei_is_refused`, `::test_an_edge_must_point_at_the_type_it_declares` |
| 21 | Request signing | A nonce **MUST** be claimed only after the signature verified | `signing.py::verify_request` claims last | `test_extension.py::test_a_forged_request_cannot_lock_out_the_real_one`; `test_signing.py::test_a_forged_signature_does_not_spend_the_nonce` |
| 24 | Request signing | A verifier **MUST** refuse a signature made for another LE AID or another endpoint URL (`audience_mismatch`), and **MUST NOT** verify v0.3 requests without knowing its URLs | `audience.py::Recipient.check`; `VleiIdentity(audience_urls=…)` raises without them | `test_audience.py`; `test_extension.py::test_a_call_signed_for_another_server_is_refused_before_it_runs`, `::test_a_server_without_audience_urls_is_a_configuration_error`; `test_replay_across_gateways.py` |
| 25 | Request signing | The signature **MUST** cover the signer, the recipient, the credential named and the method, rebuilt by the verifier | `signing.py::statement`, `verify_request` | `test_signing.py::test_the_signature_speaks_for_one_credential`, `::test_the_signer_is_inside_the_signed_bytes`, `::test_tampered_method_reports_invalid_signature`; `test_vectors.py::test_signature_vector` |
| 26 | Request signing | The canonical form **MUST** be RFC 8785 over I-JSON: ECMAScript numbers, no integer beyond ±(2⁵³−1), no repeated member name | `signing.py::_jcs_number`, `loads_strict`, `reject_duplicate_members`; vlei-authz parses with the latter | `test_canonical.py`; `test_vlei_authz_v03.py::test_a_body_with_a_repeated_member_name_is_digest_mismatch` |
| 27 | Request signing | A verifier **MUST** refuse any signature made before its replay memory began (`ts < memory_since + skew`) | `ReplayStore.memory_since`; `signing.py::_check_time` | `test_signing.py::test_a_signature_from_before_the_memory_began_is_stale`; `test_extension.py::test_a_replay_across_a_restart_is_refused_by_the_memory_horizon`, `::test_a_replay_across_a_restart_is_refused_by_the_persistent_store` |
| 28 | Request signing | A v0.3 verifier **MUST** refuse a signature of another format as `unsupported_version`, and `credentialSaid` is **required** | `signing.py::unsupported_version`; `extension.py::_verify` row 1 | `test_signing.py::test_a_v02_signature_is_unsupported_version_not_invalid`; `test_extension.py::test_a_v02_signature_is_unsupported_version`, `::test_a_call_that_names_no_credential_is_missing_credential` |
| 29 | Proof of possession | A client **MUST NOT** present anything to a server that has not proven it holds the key of its LE or of an AID the LE delegated to | `pop.py::prove_server`; `client.py::_verify_server_identity` | `test_pop.py` (accepted and refused cases); `test_client_v03.py::test_nothing_is_presented_to_a_server_that_cannot_prove_its_key` |
| 30 | Proof of possession | A server **MUST** sign only for its own endpoint URLs | `pop.py::PopResponder.respond` | `test_pop.py::test_the_responder_signs_only_for_its_own_endpoints`; `test_vlei_pop.py::test_it_proves_nothing_for_someone_elses_url` |
| 31 | Proof of possession | A client **MUST** verify the server again once its verification is older than `ttlMs` or its own limit, and after `audience_mismatch` | `client.py::recheck_due`, `call_tool` | `test_client_v03.py::test_the_server_is_verified_again_when_it_is_due`, `::test_the_servers_ttl_shortens_the_recheck`, `::test_after_audience_mismatch_the_server_is_verified_again` |
| 32 | Whose key | A client reads key states from several witnesses, a majority agreeing, as a verifier does | `client.py` (`witness_url=[…]`, `witness_quorum`); `kel.py::KeyState.agreeing` | `test_client_v03.py::test_key_states_come_from_a_quorum_of_witnesses`, `::test_one_witness_of_three_is_not_enough`; `test_witness_copies.py::test_two_of_three_is_a_quorum_and_says_so` |
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

**Mode (a) at the regulator (#3).** The regulator example's server (then `filing-server`, now
`examples/regulator/labor-insurance-sim/`) published nothing at `/.well-known/vlei`. A regulator is
exactly the party an agent should be able to identify *before* filing with it, so the omission was
the wrong way round. Added — and the endpoint serves
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

- **Duplicity is detected only across the witnesses you configure.** `kel.py` verifies a key event
  log completely — self-addressing prefix, SAIDs, prior digests, signatures to threshold, witness
  receipts to threshold, pre-rotation commitments, delegation anchors — and, given several
  witnesses (`witness_urls`, `VLEI_WITNESS_URLS`), compares their copies and refuses a prefix they
  disagree about. Given one, nothing is compared. Witnesses run by one operator — the demo's three
  are one container — can be made to agree; independent witnesses or watchers are what make the
  check mean something, and this implementation runs no watcher.

  **Every configured witness must witness every identifier resolved.** A witness that answers with
  no copy of a log is not counted, so an identifier held by fewer configured witnesses than the
  quorum (a majority by default) is *not established*. That is deliberate — counting empty answers
  let one copy be verified alone while the record said several had agreed — but it means a
  deployment resolving identifiers with different witness sets must configure one witness, or a
  quorum that fits. Finding each identifier's own witnesses (from its OOBIs) is not implemented.

  **Revocation is read from the issuers' key event logs, so those must be on the configured
  witnesses too** — the LE's, the QVI's and the root's, for the extension and the client alike. A
  deployment whose witnesses do not hold them gets *not established*, never a quiet fallback to a
  witness's unauthenticated copy of the registry. And with a single witness there is nothing to
  compare: a copy of an issuer's log from before a withdrawal was anchored is valid, and would be
  believed. Several witnesses (the client takes a list too) are what make a hidden withdrawal
  visible; a watcher that checks freshness is not implemented.
- **The subset of KERI is `kli`'s.** Single-sig and numeric thresholds, Ed25519, Blake3-256. Weighted
  thresholds, other key or digest codes, and multi-sig signers of a single-pass request are refused,
  not guessed at.
- **"Revoke the delegation" is not implemented.** The specification describes two revocation
  switches; the ECR one works. Withdrawing one agent's delegation without touching the holder's
  credential needs a KERI mechanism — a delegator-side superseding rotation — that nothing here
  performs or checks.
- **`-32021` is emitted for protected tools only.** `VleiIdentity` answers a call to a tool that
  declares a requirement with the SDK's own `-32021` when the client did not declare the extension
  under the server's namespace (`test_namespace.py`); public tools are served to anyone, which is the
  additive property. No server refuses a *connection* for want of the capability.

  It was also **wrong** until a conformance test caught it: `data.requiredCapabilities` was a list
  of identifiers, where the 2026-07-28 revision defines a `ClientCapabilities` object. Untested and
  incorrect turned out to be the same path. See
  [`skills/implementing-vlei/CONFORMANCE.md`](../skills/implementing-vlei/CONFORMANCE.md).
- **Claims are shared by one host at most.** `SqliteReplayStore` survives restarts and is shared by
  processes on one host; several gateway hosts must share a store with an atomic insert-if-absent
  (Redis, a database), which this package does not ship. A restart with `MemoryReplayStore` refuses
  calls for a minute rather than forget a claim.
- **The proof of possession is not channel binding.** It shows who answers at a URL when
  challenged; TLS is what keeps anyone from sitting in front of it.
- **Business idempotency is the tool's.** A nonce makes a signature single-use, not an operation;
  no idempotency key is implemented.
- **Scope comparison is a default, not a standard.** `signing.scope_satisfied` implements one
  reasonable algebra. The specification fixes where scope lives and that it must be checked, not how
  — a deployment with different semantics replaces the function.

## Running the checks behind this table

```bash
pytest packages/mcp-vlei/tests          # 572 tests, no containers required
pytest examples/association-server/tests -s   # end to end; needs the credential environment
```
