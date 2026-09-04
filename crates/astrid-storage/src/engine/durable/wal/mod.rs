//! Bounded streaming ASTWAL2 transaction records.
//!
//! Complete transactions are durable publication authority until recovery or
//! checkpoint folds them into the canonical object arena and root journal.

mod codec;
mod overlay;
mod replay;
mod scan;
mod types;
mod writer;

#[allow(unused_imports)]
pub(super) use overlay::{PendingWalOverlay, PendingWalRoot};
pub(crate) use replay::{recover_wal, wal_root_owners_without_repair};
#[allow(unused_imports)]
pub(super) use scan::{ScannedWal, WalScanner};
#[allow(unused_imports)]
pub(super) use types::{
    WalBeginDescriptor, WalBeginHints, WalCommitDescriptor, WalCount, WalDigest, WalError,
    WalEvent, WalLength, WalLimits, WalObjectDescriptor, WalOffset, WalOrdinal, WalRecordKind,
    WalRootDescriptor, WalRootTransition, WalScanTail, WalSequence, WalTailKind,
    WalTransactionDescriptor,
};
#[allow(unused_imports)]
pub(super) use writer::{WalSink, WalWriter};

use super::{DurableError, WAL_FILE, io_error};

/// Convert the private WAL grammar error into the durable engine's stable
/// public error surface without discarding underlying I/O failures.
pub(super) fn durable_error(error: WalError) -> DurableError {
    match error {
        WalError::Io { operation, source } => io_error(operation, source),
        WalError::FrameTooLarge {
            offset,
            declared,
            limit,
        } => DurableError::FrameTooLarge {
            file: WAL_FILE,
            offset: offset.get(),
            declared: declared.get(),
            limit: limit.get(),
        },
        WalError::Corrupt { offset, detail } | WalError::InteriorCorruption { offset, detail } => {
            DurableError::Corrupt {
                file: WAL_FILE,
                offset: offset.get(),
                detail,
            }
        },
        WalError::LengthOverflow { .. }
        | WalError::CountOverflow { .. }
        | WalError::Encoding(_) => DurableError::EncodingOverflow,
        WalError::ObjectIdentityMismatch { .. } => DurableError::Corrupt {
            file: WAL_FILE,
            offset: 0,
            detail: "WAL object identity mismatch",
        },
        WalError::PrincipalMismatch => DurableError::Corrupt {
            file: WAL_FILE,
            offset: 0,
            detail: "WAL principal encoding is not canonical",
        },
        WalError::IdentitySchemeMismatch => DurableError::Corrupt {
            file: WAL_FILE,
            offset: 0,
            detail: "WAL identity scheme mismatch",
        },
        WalError::SequenceRegression { .. }
        | WalError::SequenceMismatch { .. }
        | WalError::OrdinalMismatch { .. }
        | WalError::CommitSequenceMismatch { .. }
        | WalError::CommitCountMismatch { .. }
        | WalError::DigestMismatch
        | WalError::OrderingViolation
        | WalError::ZeroRoots
        | WalError::InvalidTransaction(_) => DurableError::Corrupt {
            file: WAL_FILE,
            offset: 0,
            detail: "WAL transaction violates canonical grammar",
        },
    }
}

#[cfg(test)]
mod lz4_compat_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod volume_crash_tests;
