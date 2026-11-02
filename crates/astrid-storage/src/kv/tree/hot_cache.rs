//! Bounded, root-scoped point-read acceleration.
//!
//! The cache is deliberately not recovery state. Every entry is namespaced by
//! the exact committed principal root that produced it, so publication of a
//! new root makes old values unreachable without an eager invalidation pass.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

use arc_swap::ArcSwap;
use imbl::{HashMap as PersistentHashMap, Vector};
use parking_lot::Mutex;

use crate::storage_model::RootState;

const ENTRY_ACCOUNTING_BYTES: usize = 128;

const fn nonzero_or_min(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => NonZeroUsize::MIN,
    }
}

const DEFAULT_CACHE_BYTES: NonZeroUsize = nonzero_or_min(64 * 1024 * 1024);
const DEFAULT_OWNER_BYTES: NonZeroUsize = nonzero_or_min(4 * 1024 * 1024);
const DEFAULT_OWNER_LIMIT: NonZeroUsize = nonzero_or_min(4_096);
const DEFAULT_ENTRIES_PER_OWNER: NonZeroUsize = nonzero_or_min(4_096);

/// Explicit charged-retention bounds for disposable, root-scoped point-read
/// acceleration.
///
/// The cache never participates in recovery, persistent quota, object
/// accounting, or garbage-collection reachability. Existing constructors keep
/// it disabled; an embedding must opt in and reserve memory for the configured
/// charge. The charge includes explicit key/value bytes plus a fixed retention
/// allowance. It is a policy metric, not an exact allocator or process-RSS
/// measurement: generic owner heap storage, allocator slack, and short-lived
/// read-copy-update snapshots remain the embedding's safety margin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvReadCacheCapacity {
    /// Do not retain point reads.
    Disabled,
    /// Retain within these total and per-owner charged-byte ceilings.
    Bounded {
        /// Total charged-byte ceiling.
        total: NonZeroUsize,
        /// Per-owner charged-byte ceiling.
        per_owner: NonZeroUsize,
    },
}

/// Admission authority for one read cache.
///
/// An embedding that lowers capacity under memory pressure must also call the
/// store's explicit reclaim method. This keeps ordinary cache hits independent
/// of authority locks or callbacks.
pub trait KvReadCacheBudget<P>: Send + Sync {
    /// Attempt to cover a prospective total and owner charge.
    fn ensure_capacity(
        &self,
        owner: &P,
        requested_total: usize,
        requested_owner: usize,
    ) -> KvReadCacheCapacity;

    /// Reconcile the complete current charge ledger after admission or
    /// eviction. Owners absent from `resident_by_owner` have no retained
    /// charge and must not keep a reservation.
    fn reconcile(&self, resident_total: usize, resident_by_owner: &BTreeMap<P, usize>);

    /// Release every reservation associated with one removed owner.
    fn release_owner(&self, owner: &P);

    /// Release every cache reservation after explicit reclamation or close.
    fn release(&self);
}

struct DisabledReadCacheBudget;

impl<P> KvReadCacheBudget<P> for DisabledReadCacheBudget {
    fn ensure_capacity(
        &self,
        _owner: &P,
        _requested_total: usize,
        _requested_owner: usize,
    ) -> KvReadCacheCapacity {
        KvReadCacheCapacity::Disabled
    }

    fn reconcile(&self, _resident_total: usize, _resident_by_owner: &BTreeMap<P, usize>) {}

    fn release_owner(&self, _owner: &P) {}

    fn release(&self) {}
}

struct FixedReadCacheBudget {
    capacity_bytes: NonZeroUsize,
    owner_capacity_bytes: NonZeroUsize,
}

impl<P> KvReadCacheBudget<P> for FixedReadCacheBudget {
    fn ensure_capacity(
        &self,
        _owner: &P,
        _requested_total: usize,
        _requested_owner: usize,
    ) -> KvReadCacheCapacity {
        KvReadCacheCapacity::Bounded {
            total: self.capacity_bytes,
            per_owner: self.owner_capacity_bytes,
        }
    }

    fn reconcile(&self, _resident_total: usize, _resident_by_owner: &BTreeMap<P, usize>) {}

    fn release_owner(&self, _owner: &P) {}

    fn release(&self) {}
}

/// Complete admission and cardinality policy for one read cache.
pub struct KvReadCacheConfig<P> {
    budget: Arc<dyn KvReadCacheBudget<P>>,
    owner_limit: NonZeroUsize,
    entries_per_owner: NonZeroUsize,
}

impl<P> Clone for KvReadCacheConfig<P> {
    fn clone(&self) -> Self {
        Self {
            budget: Arc::clone(&self.budget),
            owner_limit: self.owner_limit,
            entries_per_owner: self.entries_per_owner,
        }
    }
}

impl<P> fmt::Debug for KvReadCacheConfig<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KvReadCacheConfig")
            .field("owner_limit", &self.owner_limit)
            .field("entries_per_owner", &self.entries_per_owner)
            .finish_non_exhaustive()
    }
}

impl<P> KvReadCacheConfig<P> {
    /// Construct a fixed bounded policy.
    #[must_use]
    pub fn bounded(
        capacity_bytes: NonZeroUsize,
        owner_capacity_bytes: NonZeroUsize,
        owner_limit: NonZeroUsize,
        entries_per_owner: NonZeroUsize,
    ) -> Self {
        Self {
            budget: Arc::new(FixedReadCacheBudget {
                capacity_bytes,
                owner_capacity_bytes,
            }),
            owner_limit,
            entries_per_owner,
        }
    }

    /// Construct a policy backed by a live embedding-owned memory authority.
    #[must_use]
    pub fn governed(
        budget: Arc<dyn KvReadCacheBudget<P>>,
        owner_limit: NonZeroUsize,
        entries_per_owner: NonZeroUsize,
    ) -> Self {
        Self {
            budget,
            owner_limit,
            entries_per_owner,
        }
    }

    /// Do not retain point reads until a bounded or governed budget is supplied.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            budget: Arc::new(DisabledReadCacheBudget),
            owner_limit: NonZeroUsize::MIN,
            entries_per_owner: NonZeroUsize::MIN,
        }
    }

    /// Opt-in fixed budget using the documented 64 `MiB` / 4 `MiB`-per-owner
    /// ceilings.
    ///
    /// Callers must reserve that memory. [`Default`] never selects this budget.
    #[must_use]
    pub fn reserved_64_mib() -> Self {
        Self::bounded(
            DEFAULT_CACHE_BYTES,
            DEFAULT_OWNER_BYTES,
            DEFAULT_OWNER_LIMIT,
            DEFAULT_ENTRIES_PER_OWNER,
        )
    }
}

impl<P> Default for KvReadCacheConfig<P> {
    fn default() -> Self {
        Self::disabled()
    }
}

pub(super) enum HotRead {
    Hit(Option<Vec<u8>>),
    Miss,
}

#[cfg_attr(not(test), derive(Clone))]
enum CachedValue {
    Present(Arc<[u8]>),
    Missing,
}

#[cfg(test)]
thread_local! {
    static COPIED_CACHE_VALUES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
impl Clone for CachedValue {
    fn clone(&self) -> Self {
        COPIED_CACHE_VALUES.with(|copies| copies.set(copies.get().strict_add(1)));
        match self {
            Self::Present(value) => Self::Present(Arc::clone(value)),
            Self::Missing => Self::Missing,
        }
    }
}

impl CachedValue {
    fn to_vec(&self) -> Option<Vec<u8>> {
        match self {
            Self::Present(value) => Some(value.to_vec()),
            Self::Missing => None,
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Present(value) => value.len(),
            Self::Missing => 0,
        }
    }
}

struct OwnerSnapshot {
    root: Option<RootState>,
    entries: PersistentHashMap<Vec<u8>, CachedValue>,
    insertion_order: Vector<Vec<u8>>,
    resident_bytes: usize,
}

impl OwnerSnapshot {
    fn empty(root: Option<RootState>) -> Self {
        Self {
            root,
            entries: PersistentHashMap::new(),
            insertion_order: Vector::new(),
            resident_bytes: 0,
        }
    }

    fn entry_bytes(key: &[u8], value: &CachedValue) -> usize {
        ENTRY_ACCOUNTING_BYTES
            // The entry map and FIFO each own one key allocation.
            .saturating_add(key.len().saturating_mul(2))
            .saturating_add(value.bytes())
    }

    fn remove_oldest(&mut self) -> bool {
        let Some(key) = self.insertion_order.pop_front() else {
            return false;
        };
        if let Some(value) = self.entries.remove(&key) {
            self.resident_bytes = self
                .resident_bytes
                .saturating_sub(Self::entry_bytes(&key, &value));
        }
        true
    }
}

struct OwnerCache {
    snapshot: ArcSwap<OwnerSnapshot>,
}

impl OwnerCache {
    fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(OwnerSnapshot::empty(None)),
        }
    }
}

struct CacheWriter<P> {
    owner_order: VecDeque<P>,
    resident_bytes: usize,
}

struct AdmissionSnapshot<P> {
    requested_total: usize,
    requested_owner: usize,
    resident_total: usize,
    resident_by_owner: BTreeMap<P, usize>,
}

#[derive(Clone, Copy)]
struct CacheBounds {
    total: NonZeroUsize,
    per_owner: NonZeroUsize,
}

/// Lock-free-on-hit cache with serialized, infrequent admission and eviction.
pub(super) struct KvHotCache<P: Ord> {
    owners: ArcSwap<BTreeMap<P, Arc<OwnerCache>>>,
    accounting: Mutex<()>,
    writer: Mutex<CacheWriter<P>>,
    budget: Arc<dyn KvReadCacheBudget<P>>,
    owner_limit: NonZeroUsize,
    entries_per_owner: NonZeroUsize,
}

impl<P: Ord> KvHotCache<P> {
    pub(super) fn new(config: KvReadCacheConfig<P>) -> Self {
        Self {
            owners: ArcSwap::from_pointee(BTreeMap::new()),
            accounting: Mutex::new(()),
            writer: Mutex::new(CacheWriter {
                owner_order: VecDeque::new(),
                resident_bytes: 0,
            }),
            budget: config.budget,
            owner_limit: config.owner_limit,
            entries_per_owner: config.entries_per_owner,
        }
    }
}

impl<P> KvHotCache<P>
where
    P: Clone + Ord,
{
    pub(super) fn clear(&self) {
        let _accounting = self.accounting.lock();
        let mut writer = self.writer.lock();
        writer.owner_order.clear();
        writer.resident_bytes = 0;
        self.owners.store(Arc::new(BTreeMap::new()));
        drop(writer);
        self.budget.release();
    }

    pub(super) fn remove_owner(&self, owner: &P) {
        let _accounting = self.accounting.lock();
        let mut writer = self.writer.lock();
        let mut owners = self.owners.load_full();
        if !owners.contains_key(owner) {
            return;
        }
        let Some(removed) = Arc::make_mut(&mut owners).remove(owner) else {
            return;
        };
        writer.resident_bytes = writer
            .resident_bytes
            .saturating_sub(removed.snapshot.load().resident_bytes);
        writer.owner_order.retain(|candidate| candidate != owner);
        self.owners.store(owners);
        let resident_total = writer.resident_bytes;
        let resident_by_owner = self
            .owners
            .load()
            .iter()
            .map(|(principal, cache)| (principal.clone(), cache.snapshot.load().resident_bytes))
            .collect();
        drop(writer);
        self.budget.release_owner(owner);
        self.budget.reconcile(resident_total, &resident_by_owner);
    }

    #[cfg(test)]
    fn with_limits(
        capacity_bytes: usize,
        owner_capacity_bytes: usize,
        owner_limit: usize,
        entries_per_owner: usize,
    ) -> Self {
        Self::new(KvReadCacheConfig::bounded(
            nonzero_or_min(capacity_bytes),
            nonzero_or_min(owner_capacity_bytes),
            nonzero_or_min(owner_limit),
            nonzero_or_min(entries_per_owner),
        ))
    }

    pub(super) fn get(&self, owner: &P, root: Option<RootState>, key: &[u8]) -> HotRead {
        let owners = self.owners.load();
        let Some(owner_cache) = owners.get(owner) else {
            return HotRead::Miss;
        };
        let snapshot = owner_cache.snapshot.load();
        if snapshot.root != root {
            return HotRead::Miss;
        }
        let value = if snapshot.entries.len() == 1 {
            snapshot
                .entries
                .iter()
                .next()
                .and_then(|(entry_key, value)| (entry_key.as_slice() == key).then_some(value))
        } else {
            snapshot.entries.get(key)
        };
        value.map_or(HotRead::Miss, |value| HotRead::Hit(value.to_vec()))
    }

    pub(super) fn insert(
        &self,
        owner: &P,
        root: Option<RootState>,
        key: Vec<u8>,
        value: Option<&[u8]>,
    ) {
        // Authority callbacks and their resulting cache mutation form one
        // ordered accounting transaction. The writer lock is still released
        // before invoking external reconciliation code.
        let _accounting = self.accounting.lock();
        let value = value.map_or(CachedValue::Missing, |bytes| {
            CachedValue::Present(Arc::from(bytes))
        });
        let entry_bytes = OwnerSnapshot::entry_bytes(&key, &value);
        let admission = self.admission_snapshot(owner, root, entry_bytes);
        let KvReadCacheCapacity::Bounded {
            total: capacity_bytes,
            per_owner: owner_capacity_bytes,
        } = self.budget.ensure_capacity(
            owner,
            admission.requested_total,
            admission.requested_owner,
        )
        else {
            self.budget
                .reconcile(admission.resident_total, &admission.resident_by_owner);
            return;
        };
        if entry_bytes > capacity_bytes.get() || entry_bytes > owner_capacity_bytes.get() {
            self.budget
                .reconcile(admission.resident_total, &admission.resident_by_owner);
            return;
        }

        self.insert_bounded(
            owner,
            root,
            key,
            value,
            entry_bytes,
            CacheBounds {
                total: capacity_bytes,
                per_owner: owner_capacity_bytes,
            },
        );
    }

    fn admission_snapshot(
        &self,
        owner: &P,
        root: Option<RootState>,
        entry_bytes: usize,
    ) -> AdmissionSnapshot<P> {
        let writer = self.writer.lock();
        let owners = self.owners.load();
        let previous = owners.get(owner).map(|cache| cache.snapshot.load());
        let previous_bytes = previous
            .as_ref()
            .map_or(0, |snapshot| snapshot.resident_bytes);
        let requested_owner = previous.as_ref().map_or(entry_bytes, |snapshot| {
            if snapshot.root == root {
                previous_bytes.saturating_add(entry_bytes)
            } else {
                entry_bytes
            }
        });
        AdmissionSnapshot {
            requested_total: writer
                .resident_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(requested_owner),
            requested_owner,
            resident_total: writer.resident_bytes,
            resident_by_owner: owners
                .iter()
                .map(|(principal, cache)| (principal.clone(), cache.snapshot.load().resident_bytes))
                .collect(),
        }
    }

    fn insert_bounded(
        &self,
        owner: &P,
        root: Option<RootState>,
        key: Vec<u8>,
        value: CachedValue,
        entry_bytes: usize,
        bounds: CacheBounds,
    ) {
        let mut writer = self.writer.lock();
        let mut owners = self.owners.load_full();
        let mut owners_changed = false;
        let mut evicted_owners = Vec::new();
        let owner_cache = if let Some(existing) = owners.get(owner) {
            Arc::clone(existing)
        } else {
            while owners.len() >= self.owner_limit.get() {
                let Some(evicted_owner) = writer.owner_order.pop_front() else {
                    break;
                };
                if let Some(evicted) = Arc::make_mut(&mut owners).remove(&evicted_owner) {
                    evicted_owners.push(evicted_owner);
                    writer.resident_bytes = writer
                        .resident_bytes
                        .saturating_sub(evicted.snapshot.load().resident_bytes);
                }
            }
            let created = Arc::new(OwnerCache::new());
            Arc::make_mut(&mut owners).insert(owner.clone(), Arc::clone(&created));
            writer.owner_order.push_back(owner.clone());
            owners_changed = true;
            created
        };

        let previous = owner_cache.snapshot.load_full();
        let mut next = if previous.root == root {
            OwnerSnapshot {
                root,
                entries: previous.entries.clone(),
                insertion_order: previous.insertion_order.clone(),
                resident_bytes: previous.resident_bytes,
            }
        } else {
            OwnerSnapshot::empty(root)
        };

        if let Some(replaced) = next.entries.remove(&key) {
            next.resident_bytes = next
                .resident_bytes
                .saturating_sub(OwnerSnapshot::entry_bytes(&key, &replaced));
            next.insertion_order.retain(|candidate| candidate != &key);
        }
        next.resident_bytes = next.resident_bytes.saturating_add(entry_bytes);
        next.entries.insert(key.clone(), value);
        next.insertion_order.push_back(key);

        let mut previous_global = writer
            .resident_bytes
            .saturating_sub(previous.resident_bytes);
        while (next.entries.len() > self.entries_per_owner.get()
            || next.resident_bytes > bounds.per_owner.get())
            && next.remove_oldest()
        {}

        if previous_global.saturating_add(next.resident_bytes) > bounds.total.get() {
            let mut retained_order = VecDeque::with_capacity(writer.owner_order.len());
            while let Some(candidate) = writer.owner_order.pop_front() {
                if &candidate == owner {
                    retained_order.push_back(candidate);
                    continue;
                }
                if previous_global.saturating_add(next.resident_bytes) <= bounds.total.get() {
                    retained_order.push_back(candidate);
                    continue;
                }
                if let Some(evicted) = Arc::make_mut(&mut owners).remove(&candidate) {
                    evicted_owners.push(candidate);
                    owners_changed = true;
                    previous_global =
                        previous_global.saturating_sub(evicted.snapshot.load().resident_bytes);
                }
            }
            writer.owner_order = retained_order;
        }
        while previous_global.saturating_add(next.resident_bytes) > bounds.total.get()
            && next.remove_oldest()
        {}
        writer.resident_bytes = previous_global.saturating_add(next.resident_bytes);
        owner_cache.snapshot.store(Arc::new(next));
        if owners_changed {
            self.owners.store(owners);
        }
        let resident_total = writer.resident_bytes;
        let resident_by_owner = self
            .owners
            .load()
            .iter()
            .map(|(principal, cache)| (principal.clone(), cache.snapshot.load().resident_bytes))
            .collect();
        drop(writer);
        for evicted_owner in &evicted_owners {
            self.budget.release_owner(evicted_owner);
        }
        self.budget.reconcile(resident_total, &resident_by_owner);
    }
}

#[cfg(test)]
mod tests {
    use crate::storage_model::{ObjectId, RootGeneration};

    use super::*;

    struct DisabledBudget;

    impl KvReadCacheBudget<&'static str> for DisabledBudget {
        fn ensure_capacity(
            &self,
            _owner: &&'static str,
            _requested_total: usize,
            _requested_owner: usize,
        ) -> KvReadCacheCapacity {
            KvReadCacheCapacity::Disabled
        }

        fn reconcile(
            &self,
            _resident_total: usize,
            _resident_by_owner: &BTreeMap<&'static str, usize>,
        ) {
        }

        fn release(&self) {}

        fn release_owner(&self, _owner: &&'static str) {}
    }

    fn root(generation: u8) -> RootState {
        RootState {
            generation: RootGeneration::new(u64::from(generation)),
            commit: ObjectId::new([generation; 32]),
        }
    }

    #[test]
    fn existing_owner_admission_does_not_copy_the_owner_index() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Eq, PartialEq, Ord, PartialOrd)]
        struct Owner(u32);
        static CLONES: AtomicUsize = AtomicUsize::new(0);
        impl Clone for Owner {
            fn clone(&self) -> Self {
                CLONES.fetch_add(1, Ordering::Relaxed);
                Self(self.0)
            }
        }
        let cache = KvHotCache::with_limits(1_000_000, 10_000, 128, 8);
        for owner in 0..128 {
            cache.insert(&Owner(owner), Some(root(1)), b"key".to_vec(), Some(b"old"));
        }
        CLONES.store(0, Ordering::Relaxed);
        cache.remove_owner(&Owner(128));
        assert_eq!(CLONES.load(Ordering::Relaxed), 0);
        cache.insert(&Owner(64), Some(root(2)), b"key".to_vec(), Some(b"new"));
        // Admission and final reconciliation each provide the budget authority
        // with a complete owner ledger. Updating a known owner needs no third
        // copy of all owner identities for the unchanged lookup index.
        assert!(CLONES.load(Ordering::Relaxed) <= 2 * 128);
        assert!(matches!(
            cache.get(&Owner(64), Some(root(2)), b"key"),
            HotRead::Hit(Some(value)) if value == b"new"
        ));
        assert!(matches!(
            cache.get(&Owner(64), Some(root(1)), b"key"),
            HotRead::Miss
        ));
        assert!(matches!(
            cache.get(&Owner(63), Some(root(1)), b"key"),
            HotRead::Hit(Some(value)) if value == b"old"
        ));
    }

    #[test]
    fn root_transition_makes_prior_values_unreachable() {
        let cache = KvHotCache::with_limits(1_024, 1_024, 4, 4);
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(b"old"));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Hit(Some(value)) if value == b"old"
        ));
        assert!(matches!(
            cache.get(&"alice", Some(root(2)), b"key"),
            HotRead::Miss
        ));

        cache.insert(&"alice", Some(root(2)), b"key".to_vec(), Some(b"new"));
        assert!(matches!(
            cache.get(&"alice", Some(root(2)), b"key"),
            HotRead::Hit(Some(value)) if value == b"new"
        ));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Miss
        ));
    }

    #[test]
    fn same_root_admission_shares_entries_with_retained_readers() {
        const ENTRIES: usize = 512;
        let cache = KvHotCache::with_limits(1_000_000, 1_000_000, 1, ENTRIES + 1);
        for index in 0..ENTRIES {
            cache.insert(
                &"alice",
                Some(root(1)),
                format!("key-{index:04}").into_bytes(),
                Some(b"value"),
            );
        }
        // Hold a real reader snapshot: an optimization that only works when
        // the old entry set is exclusively owned does not repair cold scans.
        let previous = cache
            .owners
            .load()
            .get(&"alice")
            .unwrap()
            .snapshot
            .load_full();
        COPIED_CACHE_VALUES.with(|copies| copies.set(0));
        cache.insert(&"alice", Some(root(1)), b"new".to_vec(), Some(b"new-value"));
        let copied = COPIED_CACHE_VALUES.with(std::cell::Cell::get);

        assert_eq!(previous.entries.len(), ENTRIES);
        assert!(!previous.entries.contains_key(b"new".as_slice()));
        for index in 0..ENTRIES {
            assert!(matches!(
                cache.get(&"alice", Some(root(1)), format!("key-{index:04}").as_bytes()),
                HotRead::Hit(Some(value)) if value == b"value"
            ));
        }
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"new"),
            HotRead::Hit(Some(value)) if value == b"new-value"
        ));
        assert!(
            copied < ENTRIES,
            "admitting one key copied {copied} values from the {ENTRIES}-entry reader snapshot"
        );
        COPIED_CACHE_VALUES.with(|copies| copies.set(0));
        cache.insert(
            &"alice",
            Some(root(1)),
            b"key-0000".to_vec(),
            Some(b"replacement"),
        );
        assert!(COPIED_CACHE_VALUES.with(std::cell::Cell::get) < ENTRIES);
        assert_eq!(
            previous
                .entries
                .get(b"key-0000".as_slice())
                .unwrap()
                .to_vec(),
            Some(b"value".to_vec())
        );
        assert!(
            matches!(cache.get(&"alice", Some(root(1)), b"key-0000"), HotRead::Hit(Some(value)) if value == b"replacement")
        );
    }

    #[test]
    fn replacing_an_entry_preserves_retained_snapshot_and_fifo_order() {
        let cache = KvHotCache::with_limits(1_000_000, 1_000_000, 1, 3);
        for key in [b"a", b"b", b"c"] {
            cache.insert(&"alice", Some(root(1)), key.to_vec(), Some(b"old"));
        }
        let previous = cache
            .owners
            .load()
            .get(&"alice")
            .unwrap()
            .snapshot
            .load_full();
        cache.insert(&"alice", Some(root(1)), b"b".to_vec(), Some(b"new"));
        assert_eq!(
            previous.entries.get(b"b".as_slice()).unwrap().to_vec(),
            Some(b"old".to_vec())
        );
        for key in [b"d", b"e"] {
            cache.insert(&"alice", Some(root(1)), key.to_vec(), Some(b"later"));
        }
        for key in [b"a", b"c"] {
            assert!(matches!(
                cache.get(&"alice", Some(root(1)), key),
                HotRead::Miss
            ));
        }
        assert!(
            matches!(cache.get(&"alice", Some(root(1)), b"b"), HotRead::Hit(Some(value)) if value == b"new")
        );
        for key in [b"d", b"e"] {
            assert!(
                matches!(cache.get(&"alice", Some(root(1)), key), HotRead::Hit(Some(value)) if value == b"later")
            );
        }
    }

    #[test]
    fn retained_reader_survives_root_publication_and_owner_retirement() {
        use std::sync::mpsc::channel;
        use std::time::Duration;

        let cache = KvHotCache::with_limits(1_000_000, 1_000_000, 1, 3);
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(b"old"));
        let (ready_tx, ready_rx) = channel();
        let (phase_tx, phase_rx) = channel();
        let (observed_tx, observed_rx) = channel();
        std::thread::scope(|scope| {
            let reader_cache = &cache;
            let reader = scope.spawn(move || {
                let previous = reader_cache
                    .owners
                    .load()
                    .get(&"alice")
                    .unwrap()
                    .snapshot
                    .load_full();
                ready_tx.send(()).unwrap();
                phase_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let old_value = previous.entries.get(b"key".as_slice()).unwrap().to_vec();
                let current = reader_cache.get(&"alice", Some(root(2)), b"key");
                observed_tx.send((old_value, current)).unwrap();
                phase_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                (
                    previous.entries.get(b"key".as_slice()).unwrap().to_vec(),
                    reader_cache.get(&"alice", Some(root(1)), b"key"),
                    reader_cache.get(&"alice", Some(root(2)), b"key"),
                )
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            cache.insert(&"alice", Some(root(2)), b"key".to_vec(), Some(b"new"));
            phase_tx.send(()).unwrap();
            let published = observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            cache.remove_owner(&"alice");
            phase_tx.send(()).unwrap();
            let retired = reader.join().unwrap();
            assert_eq!(published.0, Some(b"old".to_vec()));
            assert!(matches!(published.1, HotRead::Hit(Some(value)) if value == b"new"));
            assert_eq!(retired.0, Some(b"old".to_vec()));
            assert!(matches!(retired.1, HotRead::Miss));
            assert!(matches!(retired.2, HotRead::Miss));
        });
    }

    #[test]
    fn capacity_and_owner_limits_evict_without_affecting_results() {
        let cache = KvHotCache::with_limits(300, 300, 1, 8);
        cache.insert(&"alice", Some(root(1)), b"first".to_vec(), Some(&[1; 100]));
        cache.insert(&"alice", Some(root(1)), b"second".to_vec(), Some(&[2; 100]));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"first"),
            HotRead::Miss
        ));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"second"),
            HotRead::Hit(Some(value)) if value == vec![2; 100]
        ));

        cache.insert(&"bob", Some(root(1)), b"key".to_vec(), None);
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"second"),
            HotRead::Miss
        ));
        assert!(matches!(
            cache.get(&"bob", Some(root(1)), b"key"),
            HotRead::Hit(None)
        ));
    }

    #[test]
    fn global_capacity_evicts_other_owner_partitions() {
        let cache = KvHotCache::with_limits(300, 300, 4, 4);
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(&[1; 100]));
        cache.insert(&"bob", Some(root(1)), b"key".to_vec(), Some(&[2; 100]));

        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Miss
        ));
        assert!(matches!(
            cache.get(&"bob", Some(root(1)), b"key"),
            HotRead::Hit(Some(value)) if value == vec![2; 100]
        ));
    }

    #[test]
    fn default_config_retains_nothing_until_governed_capacity_is_supplied() {
        let cache = KvHotCache::new(KvReadCacheConfig::default());
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(b"value"));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Miss
        ));

        let cache = KvHotCache::new(KvReadCacheConfig::reserved_64_mib());
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(b"value"));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Hit(Some(value)) if value == b"value"
        ));
    }

    #[test]
    fn governed_admission_can_disable_retention_without_affecting_reads() {
        let cache = KvHotCache::new(KvReadCacheConfig::governed(
            Arc::new(DisabledBudget),
            NonZeroUsize::new(4).unwrap(),
            NonZeroUsize::new(4).unwrap(),
        ));
        cache.insert(&"alice", Some(root(1)), b"key".to_vec(), Some(b"value"));
        assert!(matches!(
            cache.get(&"alice", Some(root(1)), b"key"),
            HotRead::Miss
        ));
    }
}
