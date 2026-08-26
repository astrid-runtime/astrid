//! Neutral host-side operations used by the lifecycle oracle.

use astrid_system_generation::ManifestIdentity;

use crate::types::ComponentId;

/// Result of one bounded readiness observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    Pending,
    Ready,
}

impl Readiness {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// The only host operations the oracle can request.
///
/// Implementations own concrete process/domain/device details. The publication
/// callback is one atomic all-services commit: there is intentionally no
/// per-service publication method. A failed publication must leave the host's
/// published set unchanged.
pub trait ServiceDriver {
    type Error;

    fn start(&mut self, component: ComponentId) -> Result<(), Self::Error>;

    fn poll_readiness(&mut self, component: ComponentId) -> Result<Readiness, Self::Error>;

    fn publish_generation(&mut self, generation: ManifestIdentity) -> Result<(), Self::Error>;

    fn retire(&mut self, generation: ManifestIdentity) -> Result<(), Self::Error>;

    fn stop(&mut self, component: ComponentId) -> Result<(), Self::Error>;
}
