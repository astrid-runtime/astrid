//! Restore the runtime fences implied by unfinished durable retirement.

use std::sync::Arc;

use astrid_approval::AllowanceStore;
use astrid_capabilities::CapabilityStore;
use astrid_storage::{OwnershipSnapshot, PrincipalDirectory};

/// Install local retirement fences before startup exposes either store.
///
/// The durable ownership reservation remains the authority to resume or finish
/// reclamation. Recovery only restores its admission consequences. The directory
/// read guard stays held across both store updates, and the callback does not
/// re-enter the directory.
///
/// # Errors
///
/// Returns an error if an allowance fence cannot be installed. The unpublished
/// stores are dropped with startup.
pub(super) fn restore_retirement_fences(
    ownership: &OwnershipSnapshot,
    principals: &PrincipalDirectory,
    mut capabilities: CapabilityStore,
    allowances: AllowanceStore,
) -> std::io::Result<(Arc<CapabilityStore>, Arc<AllowanceStore>)> {
    principals
        .replay_retirements(ownership, |alias| {
            capabilities.restore_principal_retirement(alias.clone());
            allowances.begin_principal_retirement(&alias)
        })
        .map_err(std::io::Error::other)?;
    Ok((Arc::new(capabilities), Arc::new(allowances)))
}
