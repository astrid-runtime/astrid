//! Dual-closure stub: kernel/bootstrap and empty System Generation artifacts.
//!
//! The loader (`kimage`) measures and signs two distinct artifacts. Ring 0
//! verifies the table against a compiled [`TrustedPolicy`] and binds the
//! measured identities. The untrusted table does not choose keys or floors.
//!
//! Authenticated loader handoff is not available: the emulator proof compiles
//! fixture *public* keys and independent minima. This is not firmware
//! authentication, self-measurement, first-owner enrollment, A/B persistence,
//! or a service generation. Fixture private keys stay host-only.

#![no_std]

mod codec;
mod error;
mod policy;
mod region;
mod types;
mod verify;

#[cfg(any(test, feature = "sign"))]
mod fixture;
#[cfg(any(test, feature = "sign"))]
mod sign;

pub use codec::{decode_table, encode_table};
pub use error::ClosureError;
pub use policy::{EMULATOR_KERNEL_VERIFY_KEY, EMULATOR_SYSGEN_VERIFY_KEY, TrustedPolicy};
pub use region::{ClosureTableRegion, PAGE_SIZE, prove_pages_readable};
pub use types::{
    BoundIdentities, CURRENT_FLOOR, ClosureArtifact, ClosureKind, DualClosureKeys,
    DualClosureTable, EMPTY_SYSGEN, GenerationFloor, MeasuredIdentity, TABLE_LEN,
};
pub use verify::verify_table;

#[cfg(any(test, feature = "sign"))]
pub use fixture::{FixtureRole, fixture_signing_key};
#[cfg(any(test, feature = "sign"))]
pub use sign::{sign_artifact, sign_empty_sysgen, sign_kernel_bootstrap, signed_table};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_region;
