//! Stable fail-closed journal and selection reasons.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    WrongLength,
    InteriorCorrupt,
    Full,
    InvalidTransition,
    SequenceOverflow,
    BootSequenceNotMonotonic,
    PendingExists,
    AttemptsExhausted,
    TokenMismatch,
    Ineligible,
}

impl JournalError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::WrongLength => "wrong_length",
            Self::InteriorCorrupt => "interior_corrupt",
            Self::Full => "full",
            Self::InvalidTransition => "invalid_transition",
            Self::SequenceOverflow => "sequence_overflow",
            Self::BootSequenceNotMonotonic => "boot_sequence_not_monotonic",
            Self::PendingExists => "pending_exists",
            Self::AttemptsExhausted => "attempts_exhausted",
            Self::TokenMismatch => "token_mismatch",
            Self::Ineligible => "ineligible",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionError {
    Recovery,
    Journal(JournalError),
}

impl SelectionError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::Journal(reason) => reason.as_reason(),
        }
    }
}
