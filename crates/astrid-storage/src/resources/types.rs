//! Domain types for resident-memory policy and diagnostics.

use std::fmt;
use std::time::Duration;

/// Stable identifier for one process-local memory lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseId(pub(crate) u64);

impl fmt::Display for LeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Host subsystem responsible for a resident allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySubsystem {
    /// Wasm guest linear memories and pooled stores.
    Wasm,
    /// Linux Realm guest RAM.
    LinuxRealm,
    /// Immutable storage records and projection accelerators.
    StorageCache,
    /// Compiler and build workers.
    Compiler,
    /// Filesystem providers and I/O buffers.
    Filesystem,
    /// GPU command, texture, and model staging.
    Gpu,
    /// A host extension with a stable process-wide name.
    Extension(&'static str),
}

/// Whether memory can be reclaimed without invalidating a correct operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryClass {
    /// Accelerator memory can be discarded and reconstructed or streamed.
    Evictable,
    /// Execution state cannot be reclaimed without failing its owner.
    NonEvictable,
}

/// Why a resident-memory operation was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MemoryAuthorityError {
    /// A zero-byte lease has no ownership or accounting meaning.
    #[error("resident-memory reservations must be greater than zero")]
    ZeroReservation,
    /// The process-local lease identifier space was exhausted.
    #[error("resident-memory lease identifier space is exhausted")]
    LeaseIdExhausted,
    /// The requested principal has no registered memory policy.
    #[error("principal has no registered resident-memory policy")]
    UnknownPrincipal,
    /// The proposed principal ancestry contains a cycle.
    #[error("principal memory authority cannot contain an ancestry cycle")]
    PrincipalCycle,
    /// A principal with live descendants or reservations cannot move parents.
    #[error("principal memory authority is busy and cannot change parent")]
    PrincipalBusy,
    /// A principal with live children or reservations cannot be removed.
    #[error("principal memory authority is still in use")]
    PrincipalInUse,
    /// The operator-wide resident pool cannot admit the requested bytes.
    #[error(
        "resident-memory pool exhausted: requested {requested} bytes with {available} available"
    )]
    PhysicalExhausted {
        /// Bytes requested by the rejected operation.
        requested: u64,
        /// Bytes still available under the current pool limit.
        available: u64,
    },
    /// A principal or ancestor cannot admit the requested logical charge.
    #[error(
        "principal resident-memory authority exhausted: requested {requested} bytes with {available} available"
    )]
    LogicalExhausted {
        /// Bytes requested by the rejected operation.
        requested: u64,
        /// Bytes still available under the limiting authority.
        available: u64,
    },
    /// The lease was already released.
    #[error("resident-memory lease is no longer active")]
    LeaseReleased,
    /// An evictable pool is under pressure and cannot admit above its target.
    #[error(
        "resident-memory reclaim is pending: requested capacity {requested_capacity} bytes, target {target_capacity} bytes"
    )]
    ReclaimPending {
        /// Capacity required by the consumer.
        requested_capacity: u64,
        /// Current post-pressure target.
        target_capacity: u64,
    },
    /// A consumer reported more live bytes than its lease reserves.
    #[error(
        "resident-memory usage exceeds its reservation: {used_bytes} bytes used, {reserved_bytes} reserved"
    )]
    UsageExceedsReservation {
        /// Bytes reported live by the consumer.
        used_bytes: u64,
        /// Bytes reserved by the lease.
        reserved_bytes: u64,
    },
}

/// Result of applying a lower physical or logical limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryPressure {
    /// Bytes by which current reservations exceed the new pool limit.
    pub excess_bytes: u64,
    /// Bytes covered by reclaim requests sent to evictable leases.
    pub reclaim_requested_bytes: u64,
    /// Excess that cannot be covered by currently evictable reservations.
    pub unreclaimable_bytes: u64,
}

/// Operator-only snapshot of one physical lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalLeaseSnapshot<P> {
    /// Process-local lease identifier.
    pub id: LeaseId,
    /// Principal responsible for the allocation, or `None` for a shared
    /// operator pool.
    pub owner: Option<P>,
    /// Subsystem holding the allocation.
    pub subsystem: MemorySubsystem,
    /// Whether the allocation is reclaimable.
    pub class: MemoryClass,
    /// Bytes still physically reserved.
    pub reserved_bytes: u64,
    /// Target requested by the latest pressure pass.
    pub requested_bytes: u64,
    /// Time elapsed since the reservation was created.
    pub held_for: Duration,
}

/// Operator-only snapshot of one logical principal charge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalLeaseSnapshot<P> {
    /// Process-local lease identifier.
    pub id: LeaseId,
    /// Principal charged independently of physical sharing.
    pub principal: P,
    /// Subsystem responsible for the charge.
    pub subsystem: MemorySubsystem,
    /// Whether the charged resource can be reclaimed.
    pub class: MemoryClass,
    /// Direct logical bytes charged by this lease.
    pub charged_bytes: u64,
    /// Target requested by current principal policy.
    pub requested_bytes: u64,
    /// Time elapsed since the charge was created.
    pub held_for: Duration,
}

/// Operator-only snapshot of one principal's hierarchical authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalMemorySnapshot<P> {
    /// Principal represented by this account.
    pub principal: P,
    /// Parent authority, if this is an attenuated child.
    pub parent: Option<P>,
    /// Maximum bytes for this principal plus every descendant.
    pub logical_limit_bytes: u64,
    /// Bytes charged directly to this principal.
    pub direct_logical_bytes: u64,
    /// Bytes charged to this principal and all descendants.
    pub subtree_logical_bytes: u64,
    /// Target bytes after pending evictable reclaim in this subtree.
    pub requested_subtree_logical_bytes: u64,
}

/// Privileged, point-in-time reconciliation of the resident-memory authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryAuthoritySnapshot<P> {
    /// Operator-wide physical reservation ceiling.
    pub physical_limit_bytes: u64,
    /// Current physical bytes reserved by all subsystems.
    pub physical_reserved_bytes: u64,
    /// Registered principal accounts.
    pub principals: Vec<PrincipalMemorySnapshot<P>>,
    /// Active physical leases.
    pub physical_leases: Vec<PhysicalLeaseSnapshot<P>>,
    /// Active logical charges.
    pub logical_leases: Vec<LogicalLeaseSnapshot<P>>,
}
