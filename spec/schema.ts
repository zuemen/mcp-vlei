/**
 * vLEI Identity Extension for MCP — type definitions.
 *
 * Namespace.
 * This draft uses org.gleif.vlei/identity as a provisional, demonstration namespace. It has not
 * been reviewed or endorsed by GLEIF. Reverse-domain prefixes conventionally belong to the domain's
 * owner, so the final name is expected to follow GLEIF's view — it may stay as is, or move to
 * another prefix. Implementations should treat the namespace as configuration (MCP_VLEI_NAMESPACE),
 * not as a constant.
 * The string literals below show the provisional default; each is `<namespace>/<name>`.
 *
 * Extension identifier: "org.gleif.vlei/identity" (provisional)
 * Base specification:   MCP 2026-07-28
 *
 * These types are ADDITIVE. Nothing in modelcontextprotocol/modelcontextprotocol's schema.ts is
 * modified, redefined, or re-exported here. Every type below travels inside a field the core
 * specification already reserves for extensions:
 *
 *   VleiIdentityCapability  -> ClientCapabilities.extensions["org.gleif.vlei/identity"]  (client, at initialize)
 *                              ServerCapabilities.extensions["org.gleif.vlei/identity"]  (server: initialize or server/discover result)
 *   VleiIdentityMeta        -> RequestMetaObject / ResultMetaObject  (i.e. params._meta, result._meta)
 *   VleiToolRequirement     -> Tool._meta
 *
 * Not `Implementation.extensions`: `Implementation` (clientInfo / serverInfo) has no such member,
 * and the MCP Python SDK 2.2.0 types agree.
 *
 * An implementation that does not understand these keys ignores them, per core MCP.
 */

/** The extension identifier. Second label is `gleif`, outside the reserved mcp/modelcontextprotocol range. */
export const VLEI_EXTENSION_ID = "org.gleif.vlei/identity" as const;

/** _meta keys defined by this extension. */
export const VLEI_META_KEYS = {
  credential: "org.gleif.vlei/credential",
  credentialSaid: "org.gleif.vlei/credentialSaid",
  delegatedAid: "org.gleif.vlei/delegatedAid",
  signature: "org.gleif.vlei/signature",
  attestation: "org.gleif.vlei/attestation",
  requires: "org.gleif.vlei/requires",
  failure: "org.gleif.vlei/failure",
  report: "org.gleif.vlei/report",
} as const;

/** The request-signature format of this revision (SPEC.md "Request signing"). */
export const VLEI_SIGNATURE_FORMAT = "vlei-sig/0.3" as const;

/** The proof-of-possession format of this revision (SPEC.md "Proof of possession"). */
export const VLEI_POP_FORMAT = "vlei-pop/0.3" as const;

/** vLEI credential types used by this extension. LE = Legal Entity, ECR = Engagement Context Role. */
export type VleiCredentialType = "LE" | "ECR";

/** Signature suites. Ed25519 is the only suite defined in this revision. */
export type VleiSignatureAlg = "Ed25519";

/**
 * A KERI Autonomic Identifier, CESR-encoded (e.g. "EJ7F9X...", 44 chars for a 256-bit digest).
 * Kept as a distinct alias so it reads as an identifier rather than free text.
 */
export type Aid = string;

/** A Self-Addressing Identifier — the SAID of an ACDC or a KERI event. */
export type Said = string;

/* -------------------------------------------------------------------------------------------- *
 * Capability — declared in ClientCapabilities.extensions / ServerCapabilities.extensions
 * -------------------------------------------------------------------------------------------- */

/**
 * Declared by either party in the `extensions` member of its capabilities: a client in
 * `ClientCapabilities.extensions["org.gleif.vlei/identity"]` at `initialize`, a server in
 * `ServerCapabilities.extensions["org.gleif.vlei/identity"]` of its `initialize` or
 * `server/discover` result. Declaring the capability is what makes a party extension-aware; a party
 * that omits it behaves exactly as core MCP specifies.
 */
export interface VleiIdentityCapability {
  /** Credential types this party is able to present. A server typically presents ["LE"]. */
  presents?: VleiCredentialType[];

  /**
   * Credential type this party requires of its counterparty for protected operations.
   * A server that sets `requires: "ECR"` will refuse protected tools to unverified callers.
   */
  requires?: VleiCredentialType;

  /**
   * AIDs of roots of trust this party accepts. A chain that does not terminate at one of these
   * fails with `unknown_root`. In production this is GLEIF's root; in the demo environment it is a
   * self-configured root.
   */
  acceptedRoots?: Aid[];

  /** Signature suites this party accepts. Defaults to ["Ed25519"] when omitted. */
  signatureAlgs?: VleiSignatureAlg[];

  /**
   * Request-signature formats this party produces or verifies: `["vlei-sig/0.3"]`. A v0.3 client
   * refuses a server that does not declare it (`unsupported_version`), before presenting anything.
   */
  signatureFormats?: (typeof VLEI_SIGNATURE_FORMAT)[];

  /**
   * Where this party answers a proof-of-possession challenge: an absolute URL, or a path resolved
   * against its MCP endpoint's origin — conventionally "/.well-known/vlei/pop".
   */
  pop?: string;

  /**
   * How long, in milliseconds, a counterparty SHOULD cache a verification result for this party.
   * A deployment that revokes frequently states a short value here rather than hoping clients
   * guessed one; `0` means do not cache, at the cost of a round trip per call.
   */
  ttlMs?: number;

  /** Where this party publishes its credential for passive verification — mode (a) of SPEC.md. */
  discovery?: {
    /** Absolute URL, conventionally `https://<host>/.well-known/vlei`. */
    wellKnown?: string;
  };
}

/* -------------------------------------------------------------------------------------------- *
 * Signature — vlei-sig/0.3, see SPEC.md "Request signing"
 * -------------------------------------------------------------------------------------------- */

/** Who a request is for: the recipient's LE AID and the endpoint URL, normalised. */
export interface VleiAudience {
  /** The issuee of the LE credential the client verified for this server. */
  aid: Aid;
  /** The endpoint URL the call is sent to: lower-case scheme and host, no default port, no query. */
  url: string;
}

/**
 * Signature over `UTF-8(JCS(statement))`, where statement is
 * `{aid, aud: {aid, url}, cred, digest, exp, method, nonce, ts, v}` and `cred` is the request's
 * `org.gleif.vlei/credentialSaid`. A verifier rebuilds the statement; it never takes it from here.
 * Still single-pass: the nonce is the client's, and a verifier claims it once.
 */
export interface VleiSignature {
  /** The format: "vlei-sig/0.3". Without it, a vlei-sig/0.2 signature: refused as unsupported_version. */
  v: typeof VLEI_SIGNATURE_FORMAT;

  /**
   * AID whose current key state signed this. The delegated agent AID when one is in use. A verifier
   * reads that key state from the AID's key event log at a witness — never from the request — and
   * requires the AID to be the credential's holder, or delegated by the holder.
   */
  aid: Aid;

  /** The recipient. A signature for any other is refused as audience_mismatch. */
  aud: VleiAudience;

  /** RFC 3339 timestamp, UTC, at signing time. */
  ts: string;

  /** RFC 3339 timestamp, UTC: valid until. The reference client signs for 30 s; verifiers accept 60 s at most. */
  exp: string;

  /** 128 random bits, base64url, unpadded (22 characters; 22-64 accepted). Claimed once by the verifier. */
  nonce: string;

  /**
   * `base64url(sha256(canonical))` where `canonical` is the RFC 8785 (JCS) canonicalization of the
   * request `params` with the `_meta` member removed. `_meta` is excluded because it carries this
   * signature.
   */
  digest: string;

  /** CESR-encoded Ed25519 signature over the statement, indexed (`A…`) or not (`0B…`). */
  sig: string;

  /** Suite used. Defaults to "Ed25519" when omitted. */
  alg?: VleiSignatureAlg;
}

/* -------------------------------------------------------------------------------------------- *
 * Attestation — mode (b), "letter of confirmation"
 * -------------------------------------------------------------------------------------------- */

/**
 * A signed statement by one party that it has verified another party's identity.
 * The verifier of an attestation MUST have verified `verifierAid` under mode (a) before accepting
 * this; accepting an attestation is trusting the attesting party's judgment.
 */
export interface VleiAttestation {
  /** Who performed the verification and signed this statement. */
  verifierAid: Aid;

  /** Whose identity was verified. */
  subjectAid: Aid;

  /** The LEI of the legal entity established for `subjectAid`. */
  lei: string;

  /** The ECR role established, when a role was in scope of the verification. */
  role?: string;

  /** RFC 3339 timestamp of when `verifierAid` performed the verification. */
  verifiedAt: string;

  /** SAID of the credential that was verified, so the statement can be traced to a specific ACDC. */
  credentialSaid?: Said;

  /** CESR-encoded signature by `verifierAid` over the canonicalized fields above. */
  sig: string;
}

/* -------------------------------------------------------------------------------------------- *
 * Request / result _meta
 * -------------------------------------------------------------------------------------------- */

/**
 * Keys this extension contributes to `RequestMetaObject` and `ResultMetaObject`
 * (i.e. `params._meta` on a request, `result._meta` on a response).
 *
 * All members are optional: presence is what signals participation, and a party that presents
 * nothing is simply unverified rather than malformed.
 */
export interface VleiIdentityMeta {
  /** CESR-encoded ACDC. An ECR on a request from an agent; an LE on a server's discover result. */
  "org.gleif.vlei/credential"?: string;

  /**
   * Which credential in the presented stream is the one being presented; its issuee is the holder.
   * A `--full` export carries the whole chain, so this selects the credential — never whose it is.
   * Required with a vlei-sig/0.3 signature, which speaks for it (statement field `cred`).
   */
  "org.gleif.vlei/credentialSaid"?: Said;

  /**
   * The agent's delegated AID, created under the ECR holder's KEL. Omitted when the deployment
   * signs directly with the ECR holder's AID. When present it MUST equal `signature.aid`.
   */
  "org.gleif.vlei/delegatedAid"?: Aid;

  /** Signature over this request — see VleiSignature. */
  "org.gleif.vlei/signature"?: VleiSignature;

  /** Mode (b) reply: a signed confirmation of a verification performed by another party. */
  "org.gleif.vlei/attestation"?: VleiAttestation;

  /** On a refusal's result: the failure layer again, structured, for anything that parses. */
  "org.gleif.vlei/failure"?: VleiFailureDetail;

  /** On a result: the ordered record of every check — see VleiVerificationReport. */
  "org.gleif.vlei/report"?: VleiVerificationReport;

  /**
   * Informational, never used for verification. The reference `VleiClient` still sends the
   * signer's current public key here; a verifier ignores it and reads the signer's key state from
   * its key event log. Verifying under a key the request carries is exactly what SPEC.md
   * "Whose key, and who may sign" rules out.
   */
  "org.gleif.vlei/verkey"?: string;
}

/* -------------------------------------------------------------------------------------------- *
 * Proof of possession — POST <pop>, see SPEC.md "Proof of possession"
 * -------------------------------------------------------------------------------------------- */

/** What a client sends before presenting anything to a server. */
export interface VleiPopChallenge {
  v: typeof VLEI_POP_FORMAT;
  /** 128 random bits, base64url, unpadded. */
  nonce: string;
  /** The endpoint URL the client is about to call. A server signs only for its own. */
  url: string;
}

/**
 * The server's answer: a statement signed by its LE's issuee, or by an AID the LE delegated to
 * (anchored in the LE's key event log). `sig` is over `UTF-8(JCS({aid, exp, nonce, ts, url, v}))`.
 */
export interface VleiPopResponse {
  v: typeof VLEI_POP_FORMAT;
  aid: Aid;
  nonce: string;
  url: string;
  ts: string;
  exp: string;
  sig: string;
}

/* -------------------------------------------------------------------------------------------- *
 * Tool requirement — declared in Tool._meta
 * -------------------------------------------------------------------------------------------- */

/**
 * Declared in `Tool._meta`. This is how a permission becomes part of the schema the client already
 * reads: an agent can determine, before calling, whether it is entitled to call.
 */
export interface VleiToolRequirement {
  "org.gleif.vlei/requires"?: {
    /** Credential type the caller must present. */
    credential: "ECR";

    /** Required ECR role, drawn from the legal entity's own vocabulary, e.g. "labor-insurance-filing". */
    role?: string;

    /**
     * Constraints the caller's credential scope must cover, e.g. `{ "maxAmount": 1000000 }`.
     * Comparison semantics are defined by the deployment; the extension specifies where scope lives
     * and that it must be checked, not a universal scope algebra.
     */
    scope?: Record<string, unknown>;

    /**
     * Rules on the call's own arguments, keyed by argument name, checked at the authority stage;
     * a broken rule is `scope_exceeded`. One rule is defined: `dateWithinDays: [lo, hi]`, an ISO
     * 8601 date between `lo` and `hi` days from the verifier's current date, inclusive. A rule the
     * verifier does not implement refuses the call.
     */
    arguments?: Record<string, { dateWithinDays?: [number, number] }>;
  };
}

/* -------------------------------------------------------------------------------------------- *
 * Errors
 * -------------------------------------------------------------------------------------------- */

/** JSON-RPC error code returned when a server requires this extension and the client did not declare it. */
export const VLEI_ERROR_EXTENSION_REQUIRED = -32021 as const;

/** `error.data` accompanying VLEI_ERROR_EXTENSION_REQUIRED. */
export interface VleiExtensionRequiredData {
  /**
   * A core `ClientCapabilities` object — not a list of identifiers: the same shape the client sends
   * at `initialize`, so it reads as "declare this and try again". The MCP Python SDK types it as
   * `MissingRequiredClientCapabilityErrorData`. The reference implementation
   * (`mcp_vlei.errors.ExtensionRequired.to_error`) sends
   * `{"extensions": {"org.gleif.vlei/identity": {}}}`.
   */
  requiredCapabilities: {
    extensions: {
      "org.gleif.vlei/identity": Record<string, unknown>;
    };
  };
}

/**
 * Failure layer, named in the text of a tool result with `isError: true`.
 * Naming the layer is normative: the skill's recovery behavior differs per layer.
 *
 * Nine are verification failures. `missing_credential` is not — the caller presented no credential,
 * no signature or no `credentialSaid`, and the fix is to attach one — and neither is
 * `unsupported_version`: one side does not speak vlei-sig/0.3. Only `stale_signature` is worth
 * retrying, and only once. Listed in the order of the check that raises each.
 */
export type VleiFailureLayer =
  | "missing_credential"
  | "unsupported_version"
  | "stale_signature"
  | "audience_mismatch"
  | "digest_mismatch"
  | "invalid_signature"
  | "chain_invalid"
  | "unknown_root"
  | "revoked"
  | "role_mismatch"
  | "scope_exceeded";

/**
 * Not a failure layer, and not one of the eleven: a gateway-local condition. The verifier itself
 * failed while deciding — its replay store, a client it uses, anything it defines no layer for —
 * and refused rather than answer with an unlabelled error (the reference gateway answers HTTP 503).
 * It says nothing about the credential, the signature or the call. Retryable: send the call again
 * after a moment, re-signed. It stands where a layer would: the result text's first word and
 * `VleiFailureDetail.layer`.
 */
export type VleiGatewayCondition = "verifier_error";

/**
 * Structured detail a server MAY include alongside the human-readable failure text, in
 * `result._meta["org.gleif.vlei/failure"]`.
 */
export interface VleiFailureDetail {
  layer: VleiFailureLayer | VleiGatewayCondition;
  message: string;
  /** Which AID the failure concerned, when applicable. */
  aid?: Aid;
  /** Which credential the failure concerned, when applicable. */
  credentialSaid?: Said;
}

/* -------------------------------------------------------------------------------------------- *
 * Verification report — result._meta["org.gleif.vlei/report"]
 * -------------------------------------------------------------------------------------------- */

/**
 * The checks, in the order they run (reference: `mcp_vlei/report.py::CHECK_ORDER`). Everything
 * decidable from the request comes first; `signature` and `revocation` read from a witness; and
 * `authority` comes after `revocation`, so revocation is not the last check. Verification stops at
 * the first failure, and the report still lists all eight.
 */
export type VleiCheckName =
  | "credential_present"
  | "freshness"
  | "digest"
  | "signature"
  | "delegation"
  | "chain"
  | "revocation"
  | "authority";

export interface VleiCheck {
  name: VleiCheckName;
  label: string;
  /** `true` passed (or was skipped by choice — see `skipped`), `false` failed, `null` not reached. */
  passed: boolean | null;
  /** Did not run by choice — a public tool, a source the deployment turned off. */
  skipped: boolean;
  durationMs: number;
  /** The failure layer, when this check failed. */
  layer: VleiFailureLayer | null;
  detail: string;
}

/**
 * What was checked, in order, and what each check cost. Identifiers only, never the credential
 * itself: an ECR names a natural person.
 */
export interface VleiVerificationReport {
  tool: string;
  allowed: boolean;
  /** The failure layer, when a check failed. */
  layer: VleiFailureLayer | null;
  totalMs: number;
  identity: {
    lei: string | null;
    role: string | null;
    credentialSaid: Said | null;
    holderAid: Aid | null;
    delegateAid: Aid | null;
  };
  /** What was checked but not established, or skipped by choice. */
  caveats: string[];
  checks: VleiCheck[];
}
