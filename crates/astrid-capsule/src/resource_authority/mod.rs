//! Host-owned authority for invocation-scoped semantic-object fixtures.
//!
//! The table is deliberately independent from the Wasmtime resource table. A
//! [`ResourceHandle`] only names a slot in this table; it is not useful as a
//! bearer value without the current host stamp and matching live entry.

// This vertical slice is intentionally not wired into a host-state field yet;
// its crate-private API is exercised by the sibling regressions until an
// admission caller is selected.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "this staged host-only API is exercised by sibling tests before wiring"
    )
)]

mod scope;
mod table;

#[cfg(test)]
mod tests;

#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "crate-private re-exports reserve the staged table API for its future caller"
    )
)]
pub(crate) use scope::{
    AdmissionOptions, Reservation, ResourceHandle, ResourceScope, RevocationSelector,
};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "crate-private re-export reserves the staged table API for its future caller"
    )
)]
pub(crate) use table::ResourceAuthorityTable;
