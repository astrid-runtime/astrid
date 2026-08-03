//! Elastic coarse leases for subsystem-local allocation pools.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::{
    LogicalMemoryLease, MemoryAuthorityError, MemoryClass, MemorySubsystem, PhysicalMemoryLease,
    ResidentMemoryAuthority,
};

struct PhysicalPoolState<P: Clone + Ord> {
    lease: Option<PhysicalMemoryLease<P>>,
}

struct PhysicalPoolInner<P: Clone + Ord> {
    authority: ResidentMemoryAuthority<P>,
    owner: Option<P>,
    subsystem: MemorySubsystem,
    class: MemoryClass,
    state: Mutex<PhysicalPoolState<P>>,
}

/// Elastic physical reservation used as a subsystem-local allocation pool.
///
/// Capacity grows geometrically. Most admissions compare against an existing
/// lease under this pool's local mutex; only growth crosses the global
/// authority. Pressure is observed as a lower requested capacity. The
/// consumer first discards memory, then calls [`reconcile_usage`](Self::reconcile_usage)
/// to acknowledge the bytes that actually remain resident.
#[derive(Clone)]
pub struct ElasticPhysicalMemoryPool<P: Clone + Ord> {
    inner: Arc<PhysicalPoolInner<P>>,
}

impl<P> ElasticPhysicalMemoryPool<P>
where
    P: Clone + Ord,
{
    /// Construct an empty pool. No authority capacity is consumed until the
    /// first successful admission.
    #[must_use]
    pub fn new(
        authority: ResidentMemoryAuthority<P>,
        owner: Option<P>,
        subsystem: MemorySubsystem,
        class: MemoryClass,
    ) -> Self {
        Self {
            inner: Arc::new(PhysicalPoolInner {
                authority,
                owner,
                subsystem,
                class,
                state: Mutex::new(PhysicalPoolState { lease: None }),
            }),
        }
    }

    /// Return bytes currently reserved from the operator pool.
    #[must_use]
    pub fn reserved_capacity(&self) -> u64 {
        self.inner
            .state
            .lock()
            .lease
            .as_ref()
            .map_or(0, PhysicalMemoryLease::reserved_bytes)
    }

    /// Return the capacity the consumer should currently honor.
    #[must_use]
    pub fn requested_capacity(&self) -> u64 {
        self.inner
            .state
            .lock()
            .lease
            .as_ref()
            .map_or(0, PhysicalMemoryLease::requested_bytes)
    }

    /// Ensure at least `required` bytes are available to the local pool.
    ///
    /// Growth doubles the prior lease where possible, so global authority
    /// admission occurs logarithmically rather than for every allocation.
    /// When a larger geometric request does not fit, the exact requirement is
    /// attempted before admission fails.
    ///
    /// # Errors
    ///
    /// Returns authority exhaustion, lifecycle, or pending-reclaim errors.
    pub fn ensure_capacity(&self, required: u64) -> Result<u64, MemoryAuthorityError> {
        if required == 0 {
            return Ok(self.requested_capacity());
        }
        let mut state = self.inner.state.lock();
        let Some(lease) = state.lease.as_ref() else {
            let lease = self.inner.authority.reserve_physical(
                self.inner.owner.clone(),
                self.inner.subsystem,
                self.inner.class,
                required,
            )?;
            state.lease = Some(lease);
            return Ok(required);
        };
        let reserved = lease.reserved_bytes();
        let requested = lease.requested_bytes();
        if requested < reserved {
            return if required <= requested {
                Ok(requested)
            } else {
                Err(MemoryAuthorityError::ReclaimPending {
                    requested_capacity: required,
                    target_capacity: requested,
                })
            };
        }
        if required <= reserved {
            return Ok(reserved);
        }
        let geometric = reserved.saturating_mul(2).max(required);
        if lease.resize(geometric).is_ok() {
            return Ok(geometric);
        }
        lease.resize(required)?;
        Ok(required)
    }

    /// Acknowledge actual live usage after honoring a pressure target.
    ///
    /// Slack is retained during ordinary operation. It is returned only when
    /// the authority has requested reclaim, preserving the coarse-lease hot
    /// path while making pressure accounting truthful.
    ///
    /// # Errors
    ///
    /// Returns when `used` exceeds the reservation or the lease was released.
    pub fn reconcile_usage(&self, used: u64) -> Result<(), MemoryAuthorityError> {
        let state = self.inner.state.lock();
        let Some(lease) = state.lease.as_ref() else {
            return if used == 0 {
                Ok(())
            } else {
                Err(MemoryAuthorityError::UsageExceedsReservation {
                    used_bytes: used,
                    reserved_bytes: 0,
                })
            };
        };
        let reserved = lease.reserved_bytes();
        if used > reserved {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: reserved,
            });
        }
        if lease.requested_bytes() < reserved && used <= lease.requested_bytes() {
            lease.acknowledge_reclaim(used)?;
        }
        Ok(())
    }

    /// Return all currently unused slab capacity to the authority.
    ///
    /// This is intended for explicit pressure passes rather than ordinary
    /// admissions, where retaining slack avoids global lock traffic.
    ///
    /// # Errors
    ///
    /// Returns when `used` exceeds the reservation or the lease was released.
    pub fn trim_to_usage(&self, used: u64) -> Result<(), MemoryAuthorityError> {
        let mut state = self.inner.state.lock();
        if used == 0 {
            let lease = state.lease.take();
            drop(state);
            drop(lease);
            return Ok(());
        }
        let Some(lease) = state.lease.as_ref() else {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: 0,
            });
        };
        let reserved = lease.reserved_bytes();
        if used > reserved {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: reserved,
            });
        }
        if used < reserved {
            lease.resize(used)?;
        }
        Ok(())
    }
}

struct LogicalPoolState<P: Clone + Ord> {
    lease: Option<LogicalMemoryLease<P>>,
}

struct LogicalPoolInner<P: Clone + Ord> {
    authority: ResidentMemoryAuthority<P>,
    principal: P,
    subsystem: MemorySubsystem,
    class: MemoryClass,
    state: Mutex<LogicalPoolState<P>>,
}

/// Elastic logical reservation for one principal's subsystem-local pool.
#[derive(Clone)]
pub struct ElasticLogicalMemoryPool<P: Clone + Ord> {
    inner: Arc<LogicalPoolInner<P>>,
}

impl<P> ElasticLogicalMemoryPool<P>
where
    P: Clone + Ord,
{
    /// Construct an empty logical pool for a registered principal.
    #[must_use]
    pub fn new(
        authority: ResidentMemoryAuthority<P>,
        principal: P,
        subsystem: MemorySubsystem,
        class: MemoryClass,
    ) -> Self {
        Self {
            inner: Arc::new(LogicalPoolInner {
                authority,
                principal,
                subsystem,
                class,
                state: Mutex::new(LogicalPoolState { lease: None }),
            }),
        }
    }

    /// Return bytes currently charged to the principal hierarchy.
    #[must_use]
    pub fn reserved_capacity(&self) -> u64 {
        self.inner
            .state
            .lock()
            .lease
            .as_ref()
            .map_or(0, LogicalMemoryLease::charged_bytes)
    }

    /// Return the logical capacity the consumer should currently honor.
    #[must_use]
    pub fn requested_capacity(&self) -> u64 {
        self.inner
            .state
            .lock()
            .lease
            .as_ref()
            .map_or(0, LogicalMemoryLease::requested_bytes)
    }

    /// Ensure at least `required` logical bytes are reserved.
    ///
    /// # Errors
    ///
    /// Returns authority exhaustion, lifecycle, or pending-reclaim errors.
    pub fn ensure_capacity(&self, required: u64) -> Result<u64, MemoryAuthorityError> {
        if required == 0 {
            return Ok(self.requested_capacity());
        }
        let mut state = self.inner.state.lock();
        let Some(lease) = state.lease.as_ref() else {
            let lease = self.inner.authority.reserve_logical(
                self.inner.principal.clone(),
                self.inner.subsystem,
                self.inner.class,
                required,
            )?;
            state.lease = Some(lease);
            return Ok(required);
        };
        let reserved = lease.charged_bytes();
        let requested = lease.requested_bytes();
        if requested < reserved {
            return if required <= requested {
                Ok(requested)
            } else {
                Err(MemoryAuthorityError::ReclaimPending {
                    requested_capacity: required,
                    target_capacity: requested,
                })
            };
        }
        if required <= reserved {
            return Ok(reserved);
        }
        let geometric = reserved.saturating_mul(2).max(required);
        if lease.resize(geometric).is_ok() {
            return Ok(geometric);
        }
        lease.resize(required)?;
        Ok(required)
    }

    /// Acknowledge actual logical usage after honoring a pressure target.
    ///
    /// # Errors
    ///
    /// Returns when `used` exceeds the reservation or the lease was released.
    pub fn reconcile_usage(&self, used: u64) -> Result<(), MemoryAuthorityError> {
        let state = self.inner.state.lock();
        let Some(lease) = state.lease.as_ref() else {
            return if used == 0 {
                Ok(())
            } else {
                Err(MemoryAuthorityError::UsageExceedsReservation {
                    used_bytes: used,
                    reserved_bytes: 0,
                })
            };
        };
        let reserved = lease.charged_bytes();
        if used > reserved {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: reserved,
            });
        }
        if lease.requested_bytes() < reserved && used <= lease.requested_bytes() {
            lease.acknowledge_reclaim(used)?;
        }
        Ok(())
    }

    /// Return all currently unused logical capacity to the authority.
    ///
    /// # Errors
    ///
    /// Returns when `used` exceeds the reservation or the lease was released.
    pub fn trim_to_usage(&self, used: u64) -> Result<(), MemoryAuthorityError> {
        let mut state = self.inner.state.lock();
        if used == 0 {
            let lease = state.lease.take();
            drop(state);
            drop(lease);
            return Ok(());
        }
        let Some(lease) = state.lease.as_ref() else {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: 0,
            });
        };
        let reserved = lease.charged_bytes();
        if used > reserved {
            return Err(MemoryAuthorityError::UsageExceedsReservation {
                used_bytes: used,
                reserved_bytes: reserved,
            });
        }
        if used < reserved {
            lease.resize(used)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> ResidentMemoryAuthority<String> {
        let authority = ResidentMemoryAuthority::new(100);
        authority
            .register_principal("alice".to_owned(), None, 100)
            .expect("register principal");
        authority
    }

    #[test]
    fn physical_pool_grows_geometrically_and_acks_pressure_after_reclaim() {
        let authority = authority();
        let pool = ElasticPhysicalMemoryPool::new(
            authority.clone(),
            None,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
        );
        assert_eq!(pool.ensure_capacity(10).expect("first slab"), 10);
        assert_eq!(pool.ensure_capacity(11).expect("second slab"), 20);
        assert_eq!(authority.snapshot().physical_leases.len(), 1);

        let _ = authority.set_physical_limit(5);
        assert_eq!(pool.requested_capacity(), 5);
        assert!(matches!(
            pool.ensure_capacity(6),
            Err(MemoryAuthorityError::ReclaimPending { .. })
        ));
        pool.reconcile_usage(5).expect("acknowledge reclaim");
        assert_eq!(pool.reserved_capacity(), 5);
        assert_eq!(authority.snapshot().physical_reserved_bytes, 5);
    }

    #[test]
    fn logical_pool_respects_ancestor_pressure_without_per_object_leases() {
        let authority = authority();
        let pool = ElasticLogicalMemoryPool::new(
            authority.clone(),
            "alice".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
        );
        assert_eq!(pool.ensure_capacity(10).expect("first slab"), 10);
        assert_eq!(pool.ensure_capacity(11).expect("second slab"), 20);
        assert_eq!(authority.snapshot().logical_leases.len(), 1);

        authority
            .set_principal_limit(&"alice".to_owned(), 4)
            .expect("lower limit");
        assert_eq!(pool.requested_capacity(), 4);
        pool.reconcile_usage(3).expect("acknowledge reclaim");
        assert_eq!(pool.reserved_capacity(), 3);
    }
}
