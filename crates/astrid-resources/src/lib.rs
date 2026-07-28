#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::unwrap_used)]
#![deny(unreachable_pub)]

//! Kernel-owned authorities for host resources consumed on behalf of
//! principals.
//!
//! The first authority governs resident memory with separate physical and
//! logical ledgers. Subsystems reserve coarse leases and suballocate locally,
//! so a per-object or per-page global lock never enters their hot path.

mod authority;
mod lease;
mod types;

pub use authority::ResidentMemoryAuthority;
pub use lease::{LogicalMemoryLease, PhysicalMemoryLease, ResidentMemoryLease};
pub use types::{
    LeaseId, LogicalLeaseSnapshot, MemoryAuthorityError, MemoryAuthoritySnapshot, MemoryClass,
    MemoryPressure, MemorySubsystem, PhysicalLeaseSnapshot, PrincipalMemorySnapshot,
};
