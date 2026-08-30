//! Stack-frugal runtime observation for the projection.

use super::{DomainToken, ProjectionError, ProjectionStore};

impl ProjectionStore {
    /// Compact same-lock runtime evidence. Full snapshot replay is exercised
    /// by host tests; this scan avoids staging large snapshot arrays on the
    /// kernel stack while validating the live fold's epoch chain and row count.
    pub(crate) fn runtime_evidence(
        &self,
        domain: DomainToken,
    ) -> Result<(u64, usize, u64, usize, bool), ProjectionError> {
        let lease = self.reader_lease(domain).ok_or(ProjectionError::Denied)?;
        let reader = self.reader_at(lease)?;
        if reader.deltas.overflowed() {
            return Err(ProjectionError::ResnapshotRequired);
        }

        let rows = self
            .rows
            .iter()
            .flatten()
            .filter(|relation| relation.key().scope() == lease.token)
            .count();
        let mut expected_epoch = 0u64;
        let mut fold_matches = true;
        for delta in reader.deltas.iter() {
            let epoch = delta.epoch();
            fold_matches &= epoch == expected_epoch.checked_add(1).unwrap_or(epoch)
                && delta.change().key().scope() == lease.token;
            expected_epoch = epoch;
        }
        fold_matches &= expected_epoch == reader.epoch;

        Ok((reader.epoch, rows, reader.epoch, rows, fold_matches))
    }
}
