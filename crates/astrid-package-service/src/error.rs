//! Typed package-service failures.

use thiserror::Error;

/// Failures returned by the pure package state model.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum PackageServiceError {
    /// A required opaque value or digest was zero.
    #[error("a required package-service value is zero")]
    ZeroValue,
    /// The request used an unsupported private contract version.
    #[error("unsupported package-service protocol version")]
    ProtocolVersion,
    /// The authority decision expired at or before the supplied instant.
    #[error("package-service authority expired")]
    AuthorityExpired,
    /// Ed25519 verification rejected the authority decision.
    #[error("package-service authority signature is invalid")]
    InvalidAuthoritySignature,
    /// The authority was signed for a different context or issuer.
    #[error("authority does not bind the exact package-service context")]
    AuthorityMismatch,
    /// The operation nonce already has a durable record.
    #[error("package-service nonce replay")]
    NonceReplay,
    /// The actual canonical state differed from the exact expected state.
    #[error("package-service expected state mismatch")]
    ExpectedStateMismatch,
    /// The operation is invalid for the current lifecycle state.
    #[error("package-service lifecycle transition is invalid")]
    InvalidTransition,
    /// Content, authority, service, or owner bindings disagree.
    #[error("package-service binding mismatch")]
    BindingMismatch,
    /// The artifact exceeds the bound operation budget.
    #[error("package-service budget exceeded")]
    BudgetExceeded,
    /// Retaining another intent would exceed bounded journal policy.
    #[error("package-service journal capacity exceeded")]
    JournalFull,
    /// The referenced operation is absent or not available in this state.
    #[error("package-service operation record is unavailable")]
    RecordUnavailable,
    /// A drain deadline, proof, or destination is invalid.
    #[error("package-service drain is invalid")]
    InvalidDrain,
    /// A checked lifecycle generation would overflow.
    #[error("package-service generation exhausted")]
    GenerationExhausted,
    /// Replay found a terminal outcome that does not authorize the request.
    #[error("package-service terminal receipt does not authorize replay")]
    TerminalReplayRejected,
}

/// Convenience result used by the private package-service API.
pub type PackageServiceResult<T> = Result<T, PackageServiceError>;
