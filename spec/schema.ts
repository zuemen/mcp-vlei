/**
 * vLEI Identity Extension for MCP — type definitions.
 *
 * Extension identifier: "org.gleif.vlei/identity"
 * Base specification:   MCP 2026-07-28
 *
 * These types are ADDITIVE. Nothing in modelcontextprotocol/modelcontextprotocol's schema.ts is
 * modified, redefined, or re-exported here. Every type below travels inside a field the core
 * specification already reserves for extensions:
 *
 *   VleiIdentityCapability  -> Implementation.extensions["org.gleif.vlei/identity"]
 *   VleiIdentityMeta        -> RequestMetaObject / ResultMetaObject  (i.e. params._meta, result._meta)
 *   VleiToolRequirement     -> Tool._meta
 *
 * An implementation that does not understand these keys ignores them, per core MCP.
 */

/** The extension identifier. Second label is `gleif`, outside the reserved mcp/modelcontextprotocol range. */
export const VLEI_EXTENSION_ID = "org.gleif.vlei/identity" as const;

/** _meta keys defined by this extension. */
export const VLEI_META_KEYS = {
  credential: "org.gleif.vlei/credential",
  delegatedAid: "org.gleif.vlei/delegatedAid",
  signature: "org.gleif.vlei/signature",
  attestation: "org.gleif.vlei/attestation",
  requires: "org.gleif.vlei/requires",
} as const;

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
 * Capability — declared in Implementation.extensions
 * -------------------------------------------------------------------------------------------- */

/**
 * Declared by either party in `Implementation.extensions["org.gleif.vlei/identity"]` during
 * `initialize`. Declaring the capability is what makes a party extension-aware; a party that omits
 * it behaves exactly as core MCP specifies.
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
 * Signature — single-pass, see SPEC.md "Request signing"
 * -------------------------------------------------------------------------------------------- */

/**
 * Signature over `method + "\n" + ts + "\n" + digest`.
 * Single-pass by design: a stateless gateway can decide from one message, with no challenge round
 * trip. Replay is bounded by freshness window plus replay cache, not by a nonce.
 */
export interface VleiSignature {
  /** AID whose current key state signed this. The delegated agent AID when one is in use. */
  aid: Aid;

  /** RFC 3339 timestamp, UTC, at signing time. Verifiers enforce a freshness window (default 60s). */
  ts: string;

  /**
   * `base64url(sha256(canonical))` where `canonical` is the RFC 8785 (JCS) canonicalization of the
   * request `params` with the `_meta` member removed. `_meta` is excluded because it carries this
   * signature.
   */
  digest: string;

  /** CESR-encoded signature over `method + "\n" + ts + "\n" + digest`. */
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
   * The agent's delegated AID, created under the ECR holder's KEL. Omitted when the deployment
   * signs directly with the ECR holder's AID.
   */
  "org.gleif.vlei/delegatedAid"?: Aid;

  /** Signature over this request — see VleiSignature. */
  "org.gleif.vlei/signature"?: VleiSignature;

  /** Mode (b) reply: a signed confirmation of a verification performed by another party. */
  "org.gleif.vlei/attestation"?: VleiAttestation;
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

    /** Required ECR role, drawn from the legal entity's own vocabulary, e.g. "regulatory-filing". */
    role?: string;

    /**
     * Constraints the caller's credential scope must cover, e.g. `{ "maxAmount": 1000000 }`.
     * Comparison semantics are defined by the deployment; the extension specifies where scope lives
     * and that it must be checked, not a universal scope algebra.
     */
    scope?: Record<string, unknown>;
  };
}

/* -------------------------------------------------------------------------------------------- *
 * Errors
 * -------------------------------------------------------------------------------------------- */

/** JSON-RPC error code returned when a server requires this extension and the client did not declare it. */
export const VLEI_ERROR_EXTENSION_REQUIRED = -32021 as const;

/** `error.data` accompanying VLEI_ERROR_EXTENSION_REQUIRED. */
export interface VleiExtensionRequiredData {
  /** Contains "org.gleif.vlei/identity". */
  requiredCapabilities: string[];
}

/**
 * Failure layer, named in the text of a tool result with `isError: true`.
 * Naming the layer is normative: the skill's recovery behavior differs per layer.
 */
export type VleiFailureLayer =
  | "invalid_signature"
  | "stale_signature"
  | "digest_mismatch"
  | "chain_invalid"
  | "revoked"
  | "role_mismatch"
  | "scope_exceeded"
  | "unknown_root";

/** Structured detail a server MAY include alongside the human-readable failure text. */
export interface VleiFailureDetail {
  layer: VleiFailureLayer;
  message: string;
  /** Which AID the failure concerned, when applicable. */
  aid?: Aid;
  /** Which credential the failure concerned, when applicable. */
  credentialSaid?: Said;
}
