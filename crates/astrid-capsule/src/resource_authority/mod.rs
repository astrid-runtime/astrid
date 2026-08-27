//! Host-owned authority for invocation-scoped semantic-object fixtures.
//!
//! The table is deliberately independent from the Wasmtime resource table. A
//! [`ResourceHandle`] only names a slot in this table; it is not useful as a
//! bearer value without the current host stamp and matching live entry.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "cleanup lifecycle is wired; fixture-specific lookup and delegation controls await the first admission caller"
    )
)]

mod scope;
mod table;

#[cfg(test)]
mod tests;

pub(crate) use scope::ResourceHandle;
#[cfg(test)]
pub(crate) use scope::{AdmissionOptions, Reservation, ResourceScope, RevocationSelector};
pub(crate) use table::ResourceAuthorityTable;
