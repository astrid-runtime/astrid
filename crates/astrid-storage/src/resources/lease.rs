//! RAII handles for physical reservations and logical charges.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crate::resources::authority::AuthorityInner;
use crate::resources::{LeaseId, MemoryAuthorityError};

pub(crate) struct ReclaimSignal {
    current_bytes: AtomicU64,
    requested_bytes: AtomicU64,
}

impl ReclaimSignal {
    pub(crate) fn new(bytes: u64) -> Self {
        Self {
            current_bytes: AtomicU64::new(bytes),
            requested_bytes: AtomicU64::new(bytes),
        }
    }

    pub(crate) fn current(&self) -> u64 {
        self.current_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn requested(&self) -> u64 {
        self.requested_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn set_current(&self, bytes: u64) {
        self.current_bytes.store(bytes, Ordering::Release);
        self.requested_bytes.fetch_min(bytes, Ordering::AcqRel);
    }

    pub(crate) fn set_requested(&self, bytes: u64) {
        self.requested_bytes.store(bytes, Ordering::Release);
    }
}

struct PhysicalLeaseInner<P: Clone + Ord> {
    id: LeaseId,
    authority: Weak<AuthorityInner<P>>,
    signal: Arc<ReclaimSignal>,
}

impl<P: Clone + Ord> Drop for PhysicalLeaseInner<P> {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.upgrade() {
            authority.release_physical(self.id);
        }
    }
}

/// Cloneable RAII handle for one physical resident-memory reservation.
///
/// The reservation remains active until the last clone is dropped. Pressure
/// requests are advisory until the consumer has actually reclaimed bytes and
/// calls [`acknowledge_reclaim`](Self::acknowledge_reclaim).
pub struct PhysicalMemoryLease<P: Clone + Ord> {
    inner: Arc<PhysicalLeaseInner<P>>,
}

impl<P: Clone + Ord> Clone for PhysicalMemoryLease<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: Clone + Ord> fmt::Debug for PhysicalMemoryLease<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalMemoryLease")
            .field("id", &self.inner.id)
            .field("reserved_bytes", &self.reserved_bytes())
            .field("requested_bytes", &self.requested_bytes())
            .finish()
    }
}

impl<P: Clone + Ord> PhysicalMemoryLease<P> {
    pub(crate) fn new(
        id: LeaseId,
        authority: Weak<AuthorityInner<P>>,
        signal: Arc<ReclaimSignal>,
    ) -> Self {
        Self {
            inner: Arc::new(PhysicalLeaseInner {
                id,
                authority,
                signal,
            }),
        }
    }

    /// Return the process-local lease identifier.
    #[must_use]
    pub fn id(&self) -> LeaseId {
        self.inner.id
    }

    /// Return bytes still recorded as physically resident.
    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.inner.signal.current()
    }

    /// Return the latest target requested by memory pressure.
    ///
    /// The consumer should reclaim toward this value outside the authority
    /// lock, then acknowledge the actual resident amount.
    #[must_use]
    pub fn requested_bytes(&self) -> u64 {
        self.inner.signal.requested()
    }

    /// Reconcile the lease after bytes were actually reclaimed, or grow it
    /// after admission under the current operator pool.
    ///
    /// # Errors
    ///
    /// Returns an exhaustion error when growth would exceed the pool, or
    /// [`MemoryAuthorityError::LeaseReleased`] if the authority no longer
    /// tracks this lease.
    pub fn resize(&self, bytes: u64) -> Result<(), MemoryAuthorityError> {
        let authority = self
            .inner
            .authority
            .upgrade()
            .ok_or(MemoryAuthorityError::LeaseReleased)?;
        authority.resize_physical(self.inner.id, bytes, &self.inner.signal)
    }

    /// Acknowledge actual resident bytes after a reclaim request.
    ///
    /// This is an alias for [`resize`](Self::resize) that makes the pressure
    /// protocol explicit at call sites.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`resize`](Self::resize).
    pub fn acknowledge_reclaim(&self, bytes: u64) -> Result<(), MemoryAuthorityError> {
        self.resize(bytes)
    }
}

struct LogicalLeaseInner<P: Clone + Ord> {
    id: LeaseId,
    authority: Weak<AuthorityInner<P>>,
    signal: Arc<ReclaimSignal>,
}

impl<P: Clone + Ord> Drop for LogicalLeaseInner<P> {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.upgrade() {
            authority.release_logical(self.id);
        }
    }
}

/// Cloneable RAII handle for one principal's logical resident-memory charge.
///
/// Sharing physical bytes never reduces this charge. Every principal using a
/// shared resource holds its own logical lease.
pub struct LogicalMemoryLease<P: Clone + Ord> {
    inner: Arc<LogicalLeaseInner<P>>,
}

impl<P: Clone + Ord> Clone for LogicalMemoryLease<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: Clone + Ord> fmt::Debug for LogicalMemoryLease<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalMemoryLease")
            .field("id", &self.inner.id)
            .field("charged_bytes", &self.charged_bytes())
            .field("requested_bytes", &self.requested_bytes())
            .finish()
    }
}

impl<P: Clone + Ord> LogicalMemoryLease<P> {
    pub(crate) fn new(
        id: LeaseId,
        authority: Weak<AuthorityInner<P>>,
        signal: Arc<ReclaimSignal>,
    ) -> Self {
        Self {
            inner: Arc::new(LogicalLeaseInner {
                id,
                authority,
                signal,
            }),
        }
    }

    /// Return the process-local lease identifier.
    #[must_use]
    pub fn id(&self) -> LeaseId {
        self.inner.id
    }

    /// Return the principal's current direct logical charge.
    #[must_use]
    pub fn charged_bytes(&self) -> u64 {
        self.inner.signal.current()
    }

    /// Return the latest target requested by principal policy.
    #[must_use]
    pub fn requested_bytes(&self) -> u64 {
        self.inner.signal.requested()
    }

    /// Resize the principal's logical charge.
    ///
    /// # Errors
    ///
    /// Returns an exhaustion error when growth would exceed this principal or
    /// any ancestor, or [`MemoryAuthorityError::LeaseReleased`] if the
    /// authority no longer tracks the lease.
    pub fn resize(&self, bytes: u64) -> Result<(), MemoryAuthorityError> {
        let authority = self
            .inner
            .authority
            .upgrade()
            .ok_or(MemoryAuthorityError::LeaseReleased)?;
        authority.resize_logical(self.inner.id, bytes, &self.inner.signal)
    }

    /// Acknowledge logical bytes remaining after an evictable resource shrank.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`resize`](Self::resize).
    pub fn acknowledge_reclaim(&self, bytes: u64) -> Result<(), MemoryAuthorityError> {
        self.resize(bytes)
    }
}

/// Physical and logical leases acquired atomically for one non-shared
/// allocation.
#[derive(Debug)]
pub struct ResidentMemoryLease<P: Clone + Ord> {
    /// Actual host-resident bytes.
    pub physical: PhysicalMemoryLease<P>,
    /// Principal-visible logical bytes.
    pub logical: LogicalMemoryLease<P>,
}
