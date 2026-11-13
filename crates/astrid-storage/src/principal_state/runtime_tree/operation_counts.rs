//! Count actual synchronous operations independently of tracing callsite caches.
//!
//! Snapshot immediately around a synchronous call; never span an await. Each
//! test thread owns its counters, so parallel tests and reused threads require
//! neither global subscriber changes nor resets.

use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::principal_state) struct Counts {
    pub(in crate::principal_state) scans: usize,
    pub(in crate::principal_state) receipts: usize,
    pub(in crate::principal_state) publications: usize,
}

thread_local! {
    static COUNTS: Cell<Counts> = const { Cell::new(Counts {
        scans: 0,
        receipts: 0,
        publications: 0,
    }) };
}

pub(in crate::principal_state) fn snapshot() -> Counts {
    COUNTS.with(Cell::get)
}

#[cfg(test)]
impl Counts {
    pub(in crate::principal_state) fn since(self, before: Self) -> Self {
        Self {
            scans: self.scans.strict_sub(before.scans),
            receipts: self.receipts.strict_sub(before.receipts),
            publications: self.publications.strict_sub(before.publications),
        }
    }
}

pub(in crate::principal_state) fn record_scan() {
    COUNTS.with(|count| {
        count.update(|mut value| {
            value.scans = value.scans.strict_add(1);
            value
        });
    });
}

pub(in crate::principal_state) fn record_receipt_read() {
    COUNTS.with(|count| {
        count.update(|mut value| {
            value.receipts = value.receipts.strict_add(1);
            value
        });
    });
}

pub(in crate::principal_state) fn record_completed_publication() {
    COUNTS.with(|count| {
        count.update(|mut value| {
            value.publications = value.publications.strict_add(1);
            value
        });
    });
}

/// Immutable same-thread operation snapshot for cross-crate regression tests.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeTreeOperationCounts(Counts);

#[cfg(feature = "test-support")]
impl RuntimeTreeOperationCounts {
    /// Actual source-walk entries, including root-level survivor validation.
    #[must_use]
    pub const fn scans(self) -> usize {
        self.0.scans
    }

    /// Actual strict receipt-read attempts, including failed and absent reads.
    #[must_use]
    pub const fn receipts(self) -> usize {
        self.0.receipts
    }

    /// Projection publications that completed their explicit flush boundary.
    #[must_use]
    pub const fn publications(self) -> usize {
        self.0.publications
    }
}

/// Capture counters on this thread; compare only around a synchronous call.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub fn runtime_tree_operation_counts() -> RuntimeTreeOperationCounts {
    RuntimeTreeOperationCounts(snapshot())
}
