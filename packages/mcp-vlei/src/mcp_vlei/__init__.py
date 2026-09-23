"""mcp-vlei — verifiable organizational identity for MCP, using GLEIF vLEI.

Extension identifier: ``org.gleif.vlei/identity``. Specification: ``spec/SPEC.md``.

Nothing here modifies MCP. Every field this package puts on the wire travels in ``extensions`` or
``_meta``, which core MCP already reserves for extensions, so a party that does not understand the
keys ignores them and behaves exactly as core MCP specifies.
"""

from .attest import make_attestation, verify_attestation
from .client import Entitlement, VleiCapability, VleiClient
from .errors import (
    EXTENSION_REQUIRED_CODE,
    ChainInvalid,
    DigestMismatch,
    ExtensionRequired,
    FailureLayer,
    InvalidSignature,
    MissingCredential,
    Revoked,
    RoleMismatch,
    ScopeExceeded,
    StaleSignature,
    UnknownRoot,
    VleiError,
)
from .chain import Acdc, parse_stream, recompute_said, walk_chain
from .extension import EXTENSION_ID, VleiIdentity
from .signing import ReplayCache, Signer, canonicalize, digest_params, sign_request, verify_request
from .revocation import TelRevocationChecker
from .verifier import OfflineVerifier, VerificationResult, VleiVerifier

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EXTENSION_ID",
    "EXTENSION_REQUIRED_CODE",
    "VleiIdentity",
    "VleiClient",
    "VleiCapability",
    "Entitlement",
    "VleiVerifier",
    "OfflineVerifier",
    "TelRevocationChecker",
    "Acdc",
    "parse_stream",
    "recompute_said",
    "walk_chain",
    "VerificationResult",
    "Signer",
    "ReplayCache",
    "canonicalize",
    "digest_params",
    "sign_request",
    "verify_request",
    "make_attestation",
    "verify_attestation",
    "FailureLayer",
    "VleiError",
    "ExtensionRequired",
    "InvalidSignature",
    "StaleSignature",
    "DigestMismatch",
    "ChainInvalid",
    "Revoked",
    "RoleMismatch",
    "ScopeExceeded",
    "UnknownRoot",
    "MissingCredential",
]
