//! Signed, bounded System Generation metadata for the native boot campaign.
//!
//! This crate describes *what* a generation contains: the measured kernel
//! closure, service-plan digest, component digests, CAS roots, generation
//! policy, and byte sizes. It deliberately contains no slot names, paths, or
//! deployment locations. Those are media details and cannot confer authority.
//!
//! Verification needs an explicit [`TrustedInput`]. A manifest's signer,
//! generation, roots, and component set are all checked against that input;
//! bytes that merely carry a plausible label or path are not an authority
//! source. Fixture signing is host-only and does not establish firmware trust,
//! first-owner enrollment, A/B persistence, or a service implementation.
#![no_std]

mod codec;
mod error;
mod policy;
mod types;
mod verify;

mod fixture;
#[cfg(any(test, feature = "sign"))]
mod sign;

pub use error::GenerationError;
pub use policy::{TrustedInput, TrustedInputData, VerifiedGeneration};
pub use types::{
    ComponentSet, ContentId, Expiration, Generation, MANIFEST_LEN, MAX_COMPONENTS,
    ManifestIdentity, ManifestInput, ManifestSizes, Revocation, RollbackFloor,
    SystemGenerationManifest,
};
pub use verify::verify_manifest;

/// Emulator-only values used to construct the canonical development fixture.
/// This module is available only when the explicitly named
/// `emulator-fixture` feature is enabled; the default production API contains
/// no raw fixture constants.
#[cfg(feature = "emulator-fixture")]
pub mod emulator_fixture {
    pub use super::fixture::{
        EMULATOR_CLOSURE_ROOT, EMULATOR_COMPONENTS, EMULATOR_GENERATION_FLOOR,
        EMULATOR_MANIFEST_SIZES, EMULATOR_NOW_UNIX_SECONDS, EMULATOR_OBJECT_ROOT,
        EMULATOR_PLAN_DIGEST,
    };
}

#[cfg(any(test, feature = "sign"))]
pub use fixture::fixture_signing_key;
#[cfg(any(test, feature = "sign"))]
pub use sign::signed_bytes;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
