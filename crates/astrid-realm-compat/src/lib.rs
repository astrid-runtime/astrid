//! Workload-neutral compatibility portable machine and reference interpreter.
//!
//! This crate is a fixture/falsifier for a recoverable compatibility backend.
//! It is not OS identity, ABI, product sequencing, or a named guest runtime.
//! Named programs such as `true` and `echo` are non-normative argv tokens.
//! Synthetic RV64 images execute real guest instructions; they are not Linux.
//!
//! Each execution receives a fresh owner-bound ephemeral state. There is no
//! shared unowned namespace, host path, `home://`, volume, or directory
//! fallback. Guest argv cannot select a namespace. Two-principal isolation uses
//! the [`HostPrincipal`] stamp seam; this crate does not mint stamps or leases.
//!
//! Live authority stays on the host. Receipts cannot become live handles.

#![no_std]
#![forbid(unsafe_code)]

mod fixtures;
mod image;
mod interpreter;
mod machine;
mod ramfs;

pub use astrid_provider::HostPrincipal;
pub use fixtures::{alice_principal, bob_principal, host_principal_from_stamp_uid};
pub use image::{
    GuestImage, GuestImageId, MAX_IMAGE_BYTES, SYNTHETIC_EXIT_SEVEN, SYNTHETIC_EXIT_ZERO,
    known_image,
};
pub use interpreter::{
    COMPAT_PROVIDER_GENERATION, COMPAT_PROVIDER_ID, ReferenceInterpreter, interpret_status,
};
pub use machine::{
    DEFAULT_INSTRUCTION_FUEL, DRAM_BASE, MAX_INSTRUCTION_FUEL, MachineError, PortableMachine,
    RAM_BYTES,
};
pub use ramfs::EphemeralRamfs;
