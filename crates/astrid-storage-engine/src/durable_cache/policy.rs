use std::num::NonZeroU64;
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
}

/// Dynamically adjustable operator-owned total cache budget.
#[derive(Clone, Debug)]
pub struct ObjectCacheController {
    capacity: Arc<AtomicU64>,
}

impl ObjectCacheController {
    /// Construct a live controller with an explicit initial capacity.
    #[must_use]
    pub fn new(capacity: ObjectCacheCapacity) -> Self {
        Self {
            capacity: Arc::new(AtomicU64::new(capacity.encoded())),
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
        ObjectCacheCapacity::from_encoded(self.capacity.load(Ordering::Relaxed))
    }

    /// Replace the capacity. Existing entries are evicted lazily on the next
    /// cache operation so policy changes do not block the control plane.
    pub fn set_capacity(&self, capacity: ObjectCacheCapacity) {
        self.capacity.store(capacity.encoded(), Ordering::Relaxed);
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

/// Complete injected cache policy.
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
    /// Current physical charged bytes.
    pub resident_bytes: u64,
}
