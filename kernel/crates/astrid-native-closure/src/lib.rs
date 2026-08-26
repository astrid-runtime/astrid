//! Dual-closure handoff: kernel/bootstrap and signed System Generation artifacts.
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
mod handoff;
mod policy;
mod region;
mod root;
mod types;
mod verify;

#[cfg(any(test, feature = "sign"))]
mod fixture;
#[cfg(any(test, feature = "sign"))]
mod sign;

pub use codec::{decode_table, encode_table};
pub use error::ClosureError;
pub use handoff::{
    AuthenticatedPolicyHandoff, HANDOFF_BODY_LEN, HANDOFF_DOMAIN, HANDOFF_LEN, HANDOFF_MAGIC,
    HANDOFF_PREFIX_LEN, HANDOFF_SIGNED_LEN, HANDOFF_VERSION, HandoffContext, PolicyHandoff,
};
pub use policy::{EMULATOR_KERNEL_VERIFY_KEY, EMULATOR_SYSGEN_VERIFY_KEY, TrustedPolicy};
pub use region::{PAGE_SIZE, ReadableRange, prove_pages_readable, ranges_overlap};
pub use root::RootVerifier;
pub use types::{
    BootContextBinding, BoundIdentities, CURRENT_FLOOR, ClosureArtifact, ClosureKind,
    DualClosureKeys, DualClosureTable, EMPTY_SYSGEN, GenerationFloor, LoaderIdentity,
    LoaderMeasurement, MeasuredIdentity, PolicyGeneration, TABLE_LEN,
};
pub use verify::{verify_policy_handoff, verify_table};

#[cfg(any(test, feature = "sign"))]
pub use handoff::sign_policy_handoff;

#[cfg(any(test, feature = "sign"))]
pub use fixture::{FixtureRole, fixture_signing_key};
#[cfg(any(test, feature = "sign"))]
pub use sign::{sign_artifact, sign_empty_sysgen, sign_kernel_bootstrap, signed_table};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_handoff;
#[cfg(test)]
mod tests_region;
