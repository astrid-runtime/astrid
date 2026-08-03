use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Live byte capacity selected by the embedding runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectCacheCapacity {
    /// Do not retain decoded objects.
    Disabled,
    /// Retain at most this many charged bytes.
    Bounded(NonZeroU64),
    /// Retain without an engine-local ceiling.
    ///
    /// This is intended for an embedding that enforces a shared external
    /// resident-memory budget or a controlled benchmark. It is never selected
    /// implicitly by the durable engine.
    Unbounded,
}

impl ObjectCacheCapacity {
    const fn encoded(self) -> u64 {
        match self {
            Self::Disabled => 0,
            Self::Bounded(bytes) => bytes.get(),
            Self::Unbounded => u64::MAX,
        }
    }

    const fn from_encoded(bytes: u64) -> Self {
        match bytes {
            0 => Self::Disabled,
            u64::MAX => Self::Unbounded,
            value => match NonZeroU64::new(value) {
                Some(value) => Self::Bounded(value),
                None => Self::Disabled,
            },
        }
    }

    pub(super) const fn accepts(self, bytes: u64) -> bool {
        match self {
            Self::Disabled => false,
            Self::Bounded(limit) => bytes <= limit.get(),
            Self::Unbounded => true,
        }
    }

    pub(super) const fn limit(self) -> Option<u64> {
        match self {
            Self::Disabled => Some(0),
            Self::Bounded(limit) => Some(limit.get()),
            Self::Unbounded => None,
        }
    }

    pub(super) const fn min(self, other: Self) -> Self {
        match (self.limit(), other.limit()) {
            (None, None) => Self::Unbounded,
            (Some(0), _) | (_, Some(0)) => Self::Disabled,
            (Some(left), Some(right)) => {
                match NonZeroU64::new(if left < right { left } else { right }) {
                    Some(limit) => Self::Bounded(limit),
                    None => Self::Disabled,
                }
            },
            (Some(limit), None) | (None, Some(limit)) => match NonZeroU64::new(limit) {
                Some(limit) => Self::Bounded(limit),
                None => Self::Disabled,
            },
        }
    }
}

/// External physical-memory lease behind the decoded-object cache.
///
/// Implementations may grow a coarse lease on admission and acknowledge
/// reclaim after eviction. Any refusal leaves the cache at its current target;
/// callers still execute the verified uncached read path.
///
/// Implementations must leave their internal state valid if a callback
/// unwinds. A callback panic is an implementation bug; the controller keeps
/// its historical unwind-safety contract for downstream callers.
pub trait ObjectCacheMemoryBudget: Send + Sync {
    /// Return the capacity the cache should currently honor.
    fn capacity(&self) -> ObjectCacheCapacity;

    /// Attempt to make `required` bytes available.
    fn ensure_capacity(&self, required: u64) -> ObjectCacheCapacity {
        let _ = required;
        self.capacity()
    }

    /// Reconcile live cache bytes after an eviction pass.
    fn reconcile(&self, resident_bytes: u64) {
        let _ = resident_bytes;
    }

    /// Return unused coarse-lease capacity during explicit reclaim.
    fn release_unused(&self, resident_bytes: u64) {
        self.reconcile(resident_bytes);
    }
}

/// Dynamically adjustable operator-owned total cache budget.
pub struct ObjectCacheController {
    capacity: Arc<AtomicU64>,
    governed: Option<AssertUnwindSafe<Arc<dyn ObjectCacheMemoryBudget>>>,
}

impl Clone for ObjectCacheController {
    fn clone(&self) -> Self {
        Self {
            capacity: Arc::clone(&self.capacity),
            governed: self
                .governed
                .as_ref()
                .map(|budget| AssertUnwindSafe(Arc::clone(&budget.0))),
        }
    }
}

impl fmt::Debug for ObjectCacheController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectCacheController")
            .field("capacity", &self.capacity())
            .field("governed", &self.governed.is_some())
            .finish()
    }
}

impl ObjectCacheController {
    /// Construct a live controller with an explicit initial capacity.
    #[must_use]
    pub fn new(capacity: ObjectCacheCapacity) -> Self {
        Self {
            capacity: Arc::new(AtomicU64::new(capacity.encoded())),
            governed: None,
        }
    }

    /// Construct a controller backed by an external coarse memory lease.
    ///
    /// The local ceiling starts unbounded; [`set_capacity`](Self::set_capacity)
    /// can still impose a tighter operator override.
    #[must_use]
    pub fn governed(budget: Arc<dyn ObjectCacheMemoryBudget>) -> Self {
        Self {
            capacity: Arc::new(AtomicU64::new(ObjectCacheCapacity::Unbounded.encoded())),
            governed: Some(AssertUnwindSafe(budget)),
        }
    }

    /// Disable retention.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(ObjectCacheCapacity::Disabled)
    }

    /// Return the current operator capacity.
    #[must_use]
    pub fn capacity(&self) -> ObjectCacheCapacity {
        let local = ObjectCacheCapacity::from_encoded(self.capacity.load(Ordering::Relaxed));
        self.governed
            .as_ref()
            .map_or(local, |budget| local.min(budget.0.capacity()))
    }

    /// Replace the capacity. Existing entries are evicted lazily on the next
    /// cache operation so policy changes do not block the control plane.
    pub fn set_capacity(&self, capacity: ObjectCacheCapacity) {
        self.capacity.store(capacity.encoded(), Ordering::Relaxed);
    }

    pub(super) fn ensure_capacity(&self, required: u64) -> ObjectCacheCapacity {
        let local = ObjectCacheCapacity::from_encoded(self.capacity.load(Ordering::Relaxed));
        self.governed.as_ref().map_or(local, |budget| {
            local.min(budget.0.ensure_capacity(required))
        })
    }

    pub(super) fn reconcile(&self, resident_bytes: u64) {
        if let Some(budget) = &self.governed {
            budget.0.reconcile(resident_bytes);
        }
    }

    pub(super) fn release_unused(&self, resident_bytes: u64) {
        if let Some(budget) = &self.governed {
            budget.0.release_unused(resident_bytes);
        }
    }
}

/// Resolves the current cache share for one principal.
///
/// Resolution happens outside the cache lock. Returning
/// [`ObjectCacheCapacity::Disabled`] bypasses retention without failing the
/// underlying read.
pub trait PrincipalObjectCacheBudget<P>: Send + Sync {
    /// Return the principal's current cache share.
    fn capacity(&self, principal: &P) -> ObjectCacheCapacity;

    /// Attempt to make `required` logical bytes available for `principal`.
    fn ensure_capacity(&self, principal: &P, required: u64) -> ObjectCacheCapacity {
        let _ = required;
        self.capacity(principal)
    }

    /// Reconcile the principal's live logical cache charge after eviction.
    fn reconcile(&self, principal: &P, charged_bytes: u64) {
        let _ = (principal, charged_bytes);
    }

    /// Return unused logical capacity during explicit reclaim.
    fn release_unused(&self, principal: &P, charged_bytes: u64) {
        self.reconcile(principal, charged_bytes);
    }

    /// Return unused capacity across every principal known to this budget.
    ///
    /// `charged_bytes` is the cache's complete live logical ledger. Budget
    /// implementations that retain per-principal pools must also release
    /// pools absent from this map; a global eviction can remove a partition
    /// before explicit reclaim runs.
    fn release_unused_all(&self, charged_bytes: &BTreeMap<P, u64>) {
        for (principal, charged_bytes) in charged_bytes {
            self.release_unused(principal, *charged_bytes);
        }
    }
}

impl<P, F> PrincipalObjectCacheBudget<P> for F
where
    F: Fn(&P) -> ObjectCacheCapacity + Send + Sync,
{
    fn capacity(&self, principal: &P) -> ObjectCacheCapacity {
        self(principal)
    }
}

struct DisabledPrincipalBudget;

impl<P> PrincipalObjectCacheBudget<P> for DisabledPrincipalBudget {
    fn capacity(&self, _principal: &P) -> ObjectCacheCapacity {
        ObjectCacheCapacity::Disabled
    }
}

/// Complete injected cache policy for decoded objects and projection-owned
/// accelerators.
pub struct ObjectCacheConfig<P> {
    pub(super) controller: ObjectCacheController,
    pub(super) principal_budget: Arc<dyn PrincipalObjectCacheBudget<P>>,
}

impl<P> ObjectCacheConfig<P> {
    /// Construct an explicitly governed cache.
    #[must_use]
    pub fn new(
        controller: ObjectCacheController,
        principal_budget: Arc<dyn PrincipalObjectCacheBudget<P>>,
    ) -> Self {
        Self {
            controller,
            principal_budget,
        }
    }

    /// Disable decoded-object retention.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(
            ObjectCacheController::disabled(),
            Arc::new(DisabledPrincipalBudget),
        )
    }
}

/// Privileged cache diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectCacheStats {
    /// Reads served from a physically shared decoded record.
    pub hits: u64,
    /// Governed reads that required arena access.
    pub misses: u64,
    /// Reads that bypassed retention because either budget was disabled.
    pub bypasses: u64,
    /// Physical records admitted.
    pub insertions: u64,
    /// Physical records evicted.
    pub evictions: u64,
    /// Current physical record count.
    pub resident_objects: u64,
    /// Current total charged bytes, including decoded records,
    /// principal-to-record association payloads, and projections.
    pub resident_bytes: u64,
    /// Current bytes charged for physically shared decoded records.
    pub resident_record_bytes: u64,
    /// Current bytes charged for principal-to-record association payloads.
    ///
    /// This scales with logical cache users even when they share one physical
    /// record, preventing sharing metadata from growing outside the cache
    /// budget.
    pub resident_association_bytes: u64,
    /// Current number of principal-to-record associations.
    pub resident_associations: u64,
    /// Projection-owned accelerator lookups served from governed memory.
    pub projection_hits: u64,
    /// Projection-owned accelerator lookups that were absent or evicted.
    pub projection_misses: u64,
    /// Projection-owned values accepted into governed memory.
    pub projection_insertions: u64,
    /// Projection-owned values discarded by replacement or cache eviction.
    pub projection_evictions: u64,
    /// Current bytes charged for projection-owned accelerator values.
    pub resident_projection_bytes: u64,
    /// Current number of projection-owned accelerator values.
    pub resident_projection_entries: u64,
}
