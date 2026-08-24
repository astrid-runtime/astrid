//! Workload-neutral compatibility reference interpreter.
//!
//! This crate is a fixture/falsifier for a recoverable compatibility backend.
//! It is not OS identity, ABI, product sequencing, or a named guest runtime.
//! Named programs such as `true` and `echo` are non-normative argv tokens.
//!
//! Each execution receives a fresh [`EphemeralRamfs`] bound to an immutable
//! [`HostPrincipal`]. There is no shared unowned namespace, host path,
//! `home://`, volume, or directory fallback. Guest argv cannot select a
//! namespace. Two-principal isolation uses the [`HostPrincipal`] stamp seam;
//! this crate does not mint stamps or leases.
//!
//! Live authority stays on the host. Receipts cannot become live handles.

#![no_std]
#![forbid(unsafe_code)]

mod fixtures;
mod interpreter;
mod ramfs;

pub use astrid_provider::HostPrincipal;
pub use fixtures::{alice_principal, bob_principal, host_principal_from_stamp_uid};
pub use interpreter::{
    COMPAT_PROVIDER_GENERATION, COMPAT_PROVIDER_ID, ReferenceInterpreter, interpret_status,
};
pub use ramfs::EphemeralRamfs;
