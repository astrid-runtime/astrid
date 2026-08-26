//! Support types split out of the large [`HostState`] module.

/// The lifecycle phase a capsule is currently executing in.
///
/// Set on [`HostState`](super::host_state::HostState) during `#[install]`
/// or `#[upgrade]` dispatch. The `astrid_elicit` host function checks this
/// field and rejects calls outside of a lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// First-time installation.
    Install,
    /// Upgrading from a previous version.
    Upgrade,
}
