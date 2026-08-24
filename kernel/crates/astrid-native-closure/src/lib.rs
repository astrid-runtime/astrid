//! Dual-closure stub: kernel/bootstrap and empty System Generation artifacts.
//!
//! The loader (`kimage`) measures and signs two distinct artifacts. Ring 0
//! verifies the table and binds the measured identities. This is not firmware
//! authentication, first-owner enrollment, A/B persistence, or a service
//! generation.

#![no_std]

mod codec;
mod error;
mod types;
mod verify;

#[cfg(any(test, feature = "sign"))]
mod fixture;
#[cfg(any(test, feature = "sign"))]
mod sign;

pub use codec::{decode_table, encode_table};
pub use error::ClosureError;
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
