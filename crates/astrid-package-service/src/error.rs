use std::num::TryFromIntError;

/// Typed failures for the pure package-lifecycle model.
#[derive(Debug, thiserror::Error)]
pub enum PackageServiceError {
    /// The request uses a protocol version this model does not understand.
    #[error("unsupported package protocol version")]
    ProtocolVersion,
    /// An identifier or bounded text failed validation.
    #[error("invalid package value: {0}")]
    InvalidValue(&'static str),
    /// An integer did not fit its bounded contract representation.
    #[error("package value is outside its bounded representation")]
    IntegerBounds(#[from] TryFromIntError),
    /// A canonical generation counter refused overflow.
    #[error("canonical generation overflow")]
    GenerationOverflow,
    /// Authenticated ingress and the canonical context disagree.
    #[error("authenticated ingress does not match the operation context")]
    StampedIdentityMismatch,
    /// Admitted service identity or generation does not match the context.
    #[error("admitted service does not match the operation context")]
    ServiceAdmissionMismatch,
    /// An authority decision was not bound to the exact context.
    #[error("authority decision is not bound to this operation context")]
    AuthorityContextMismatch,
    /// An authority issuer or channel is not permitted for its decision class.
    #[error("authority issuer is not permitted for this decision class")]
    AuthorityIssuerRejected,
    /// A nonce or authority decision was replayed for a different effect.
    #[error("authority or nonce replay detected")]
    ReplayRejected,
    /// The operation context expired before admission or work.
    #[error("operation authority has expired")]
    AuthorityExpired,
    /// The operation is not valid for the expected canonical state.
    #[error("canonical state expectation was not met")]
    ExpectedStateMismatch,
    /// The lifecycle state cannot make the requested transition.
    #[error("package lifecycle transition is invalid")]
    LifecycleTransition,
    /// Exact artifact, manifest, plan, or budget bindings disagree.
    #[error("validated operation binding does not match the canonical context")]
    BindingMismatch,
    /// A bounded drain still has live leases at its deadline.
    #[error("drain is blocked because live leases remain")]
    DrainBlocked,
    /// Recovery evidence did not prove an exact old or new outcome.
    #[error("recovery evidence does not resolve the unknown outcome")]
    RecoveryUnresolved,
    /// The requested nonce has no authoritative owner/package record.
    #[error("operation record is absent")]
    RecordMissing,
    /// Recovery addressed a record that is not currently unknown.
    #[error("operation record is not available for reconciliation")]
    RecordNotReconcilable,
    /// Capacity policy refused work before any budgeted effect.
    #[error("journal capacity or retention policy refused the operation")]
    QuotaExhausted,
    /// Canonical slot occupancy is inconsistent.
    #[error("package slot occupancy invariant failed")]
    OccupancyCorruption,
}

/// Convenient result alias for this private crate.
pub type PackageServiceResult<T> = Result<T, PackageServiceError>;
