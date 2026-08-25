//! Fail-closed dual-closure errors. Reasons are stable serial tokens.

/// Why a dual-closure table was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureError {
    Missing,
    Truncated,
    Malformed,
    Unmapped,
    Swapped,
    Stale,
    CrossBound,
    SignatureInvalid,
    SameKey,
    Collision,
    NotEmpty,
    RootKeyMismatch,
    RootSignatureInvalid,
    PolicyGenerationStale,
    BindingMismatch,
}

impl ClosureError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::Unmapped => "unmapped",
            Self::Swapped => "swapped",
            Self::Stale => "stale",
            Self::CrossBound => "cross_bound",
            Self::SignatureInvalid => "signature",
            Self::SameKey => "same_key",
            Self::Collision => "collision",
            Self::NotEmpty => "not_empty",
            Self::RootKeyMismatch => "root_key",
            Self::RootSignatureInvalid => "root_signature",
            Self::PolicyGenerationStale => "policy_generation_stale",
            Self::BindingMismatch => "binding",
        }
    }
}
