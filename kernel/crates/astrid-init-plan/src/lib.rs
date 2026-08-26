//! Bounded init/recovery lifecycle for an already verified system generation.
//!
//! This crate is deliberately a neutral oracle. It accepts only a
//! verifier-owned [`VerifiedGeneration`] and opaque component identities. It
//! does not parse manifests, choose a slot, inspect storage, resolve paths, or
//! make service-authority decisions. A host supplies those decisions and a
//! [`ServiceDriver`] supplies the concrete start/readiness/publication actions.
#![no_std]

mod driver;
mod error;
mod plan;
mod types;

pub use astrid_system_generation::ManifestIdentity;
pub use driver::{Readiness, ServiceDriver};
pub use error::{LifecycleError, PlanError};
pub use plan::{InitPlan, PlanLimits};
pub use types::{ComponentId, ComponentIds, ComponentIdsIter, LifecycleState};

pub const MAX_SERVICES: usize = types::MAX_SERVICES;
pub const MAX_START_ATTEMPTS: usize = types::MAX_START_ATTEMPTS;
pub const MAX_READINESS_POLLS: usize = types::MAX_READINESS_POLLS;
pub const MAX_STEPS: usize = types::MAX_STEPS;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
