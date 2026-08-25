//! Fail-closed reasons for generation parsing and admission.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationError {
    Missing,
    WrongLength,
    Malformed,
    NonCanonical,
    UnknownFlags,
    InvalidContentId,
    InvalidComponentSet,
    InvalidFloor,
    InvalidSigner,
    UntrustedSigner,
    SignatureInvalid,
    Stale,
    Expired,
    Revoked,
    KernelMismatch,
    PlanMismatch,
    ComponentsMismatch,
    ObjectRootMismatch,
    ClosureRootMismatch,
    SizeMismatch,
}

impl GenerationError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::WrongLength => "wrong_length",
            Self::Malformed => "malformed",
            Self::NonCanonical => "non_canonical",
            Self::UnknownFlags => "unknown_flags",
            Self::InvalidContentId => "invalid_content_id",
            Self::InvalidComponentSet => "invalid_component_set",
            Self::InvalidFloor => "invalid_floor",
            Self::InvalidSigner => "invalid_signer",
            Self::UntrustedSigner => "untrusted_signer",
            Self::SignatureInvalid => "signature",
            Self::Stale => "stale",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::KernelMismatch => "kernel_mismatch",
            Self::PlanMismatch => "plan_mismatch",
            Self::ComponentsMismatch => "components_mismatch",
            Self::ObjectRootMismatch => "object_root_mismatch",
            Self::ClosureRootMismatch => "closure_root_mismatch",
            Self::SizeMismatch => "size_mismatch",
        }
    }
}
