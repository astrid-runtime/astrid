//! Fail-closed A/B boot selection over a fixed, integrity-checked journal.
//!
//! This is a placement-only selector. `Slot::A` and `Slot::B` are journal
//! locations, never labels, paths, principals, or authority. The selector
//! consumes opaque [`CandidateFacts`] that a later adapter may construct only
//! after descriptor and dual-closure verification. It never parses descriptor
//! bytes, payloads, guest input, or media paths.
//!
//! The checksum detects torn or modified journal bytes but is deliberately not
//! authentication. A trusted signer/loader policy remains a separate gate.
//! The caller must durably persist every returned [`PendingTrial`] before it
//! executes the candidate; this crate cannot make an external medium durable.
#![no_std]

mod codec;
mod error;
mod journal;
mod policy;
mod selector;
mod types;

pub use codec::FRAME_LEN;
pub use error::{JournalError, SelectionError};
pub use journal::{FRAME_COUNT, JOURNAL_LEN, Journal};
pub use policy::{MAX_ATTEMPTS, SelectionPolicy};
pub use selector::{BootDecision, ConfirmedBoot, PendingTrial, Selector, VerifiedCandidates};
pub use types::{CandidateFacts, PendingToken, RecordState, Slot};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
