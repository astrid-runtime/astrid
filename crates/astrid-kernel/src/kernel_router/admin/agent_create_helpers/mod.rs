//! `admin.agent.create` provisioning + keypair-backfill helpers.
//!
//! Carved out of `handlers.rs` to keep that file under the per-file CI line
//! cap. `agent_create` stays a thin dispatcher there; this module owns the
//! heavy lifting:
//!
//! - [`provision_new_principal`] — build + register + provision a genuinely
//!   new principal (no profile on disk).
//! - [`backfill_keypair`] — surgically heal an EXISTING keyless principal by
//!   adding only its missing ed25519 credential.
//! - [`build_create_profile`] / [`mint_principal_keypair`] — shared by both.
//!
//! Everything here must run under the admin write lock held by the caller.

mod create;
mod derived;
mod rollback;

#[cfg(test)]
mod rollback_cleanup_tests;

pub(super) use create::{backfill_keypair, provision_new_principal};
pub(super) use derived::{DerivedPrincipalTarget, provision_derived_principal};
