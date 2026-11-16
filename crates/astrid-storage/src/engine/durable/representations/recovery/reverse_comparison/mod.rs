//! Exact comparison with canonical reverse associations without a second index.

use std::collections::BTreeMap;

use super::super::{DurableError, ObjectId, RepresentationRecordId};

/// Observe the canonical representation-key order used by sealed-tip proofs.
///
/// Every direct association must occur once in the supplied index. Strictly
/// ordered nonempty lists plus equal cardinality establish the same ordered
/// map/list equality as collecting the validated stream and comparing it.
/// Record mismatches without returning early: the caller must finish semantic
/// validation and check cancellation before consulting `matches`.
pub(super) struct ReverseComparison<'a> {
    expected: &'a BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
    remaining: usize,
    previous: Option<RepresentationRecordId>,
    agrees: bool,
}

impl<'a> ReverseComparison<'a> {
    pub(super) fn new(
        expected: &'a BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
    ) -> Result<Self, DurableError> {
        let mut remaining = 0_usize;
        let mut agrees = true;
        for records in expected.values() {
            remaining = remaining
                .checked_add(records.len())
                .ok_or(DurableError::EncodingOverflow)?;
            agrees &= !records.is_empty() && records.windows(2).all(|pair| pair[0] < pair[1]);
        }
        Ok(Self {
            expected,
            remaining,
            previous: None,
            agrees,
        })
    }

    pub(super) fn observe(&mut self, object: ObjectId, record: RepresentationRecordId) {
        self.agrees &= self.previous.is_none_or(|previous| previous < record);
        self.previous = Some(record);
        self.agrees &= self
            .expected
            .get(&object)
            .is_some_and(|records| records.binary_search(&record).is_ok());
        if let Some(remaining) = self.remaining.checked_sub(1) {
            self.remaining = remaining;
        } else {
            self.agrees = false;
        }
    }

    pub(super) fn matches(&self) -> bool {
        self.agrees && self.remaining == 0
    }
}

#[cfg(test)]
mod tests;
