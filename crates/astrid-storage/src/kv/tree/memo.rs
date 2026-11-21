//! One publication epoch invalidates pre-purge work without owner tombstones.
use super::KvValidationCache;
use crate::content::CatalogValidation;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoEpoch(u64);

#[derive(Clone, Copy)]
pub(super) struct MemoSnapshot {
    pub(super) root: crate::storage_model::RootState,
    pub(super) epoch: MemoEpoch,
}

impl<P: Ord> KvValidationCache<P> {
    pub(crate) fn memo_epoch(&self) -> MemoEpoch {
        MemoEpoch(self.epoch.load(Ordering::Acquire))
    }

    pub(super) fn epoch_is_current(&self, epoch: MemoEpoch) -> bool {
        // Exhaustion conservatively disables memo publication, never wraps to
        // a ticket held by old work. Authoritative reads remain unaffected.
        epoch.0 != u64::MAX && self.memo_epoch() == epoch
    }

    pub(crate) fn forget_owner(&self, owner: &P, catalogs: &Mutex<BTreeMap<P, CatalogValidation>>) {
        // Same guard/order as every publisher; a no-op purge also invalidates
        // already-admitted work even though its immutable root did not change.
        let mut projections = self.projections.lock();
        self.epoch.store(
            self.epoch.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Release,
        );
        self.trees.lock().remove(owner);
        projections.remove(owner);
        catalogs.lock().remove(owner);
    }
}

impl<P: Clone + Ord> KvValidationCache<P> {
    /// Check the captured root while holding the purge/publication guard.
    /// The callback may query currency only, never validate or commit a graph.
    pub(crate) fn publish_catalog_if_current(
        &self,
        catalogs: &Mutex<BTreeMap<P, CatalogValidation>>,
        owner: &P,
        epoch: MemoEpoch,
        validation: CatalogValidation,
        is_current: impl FnOnce() -> bool,
    ) -> bool {
        let _publication = self.projections.lock();
        if !self.epoch_is_current(epoch) || !is_current() {
            return false;
        }
        catalogs.lock().insert(owner.clone(), validation);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_epoch_never_wraps_or_admits_a_stale_memo() {
        let cache = KvValidationCache::<String>::default();
        let catalogs = Mutex::new(BTreeMap::new());
        let owner = "retiring".to_owned();
        cache.epoch.store(u64::MAX - 1, Ordering::Release);
        let old = cache.memo_epoch();
        cache.forget_owner(&owner, &catalogs);
        assert!(!cache.epoch_is_current(old));
        assert!(!cache.epoch_is_current(cache.memo_epoch()));
        cache.forget_owner(&owner, &catalogs);
        assert_eq!(cache.epoch.load(Ordering::Acquire), u64::MAX);
    }
}
