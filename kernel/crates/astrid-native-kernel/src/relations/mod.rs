//! Kernel- and harness-private typed object relations.

mod adapter;
mod delta;
mod projection;
mod types;

#[cfg(test)]
pub(crate) use adapter::ProjectionEvidence;
pub(crate) use adapter::{
    CapabilityFacts, capability_installed, capability_removed, domain_registered, domain_released,
    endpoint_created, endpoint_reclaimed,
};
#[cfg(test)]
pub(crate) use adapter::{projection_fold_evidence, projection_observation};
#[cfg(test)]
pub(crate) use delta::DeltaCursor;
pub(crate) use projection::ProjectionStore;
#[cfg(test)]
pub(crate) use projection::Snapshot;
pub(crate) use types::ProjectionError;

#[cfg(test)]
mod adapter_tests;
#[cfg(test)]
mod projection_tests;
