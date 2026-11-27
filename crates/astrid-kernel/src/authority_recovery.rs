//! Restore the runtime fences implied by unfinished durable retirement.

use std::sync::Arc;

use astrid_approval::AllowanceStore;
use astrid_capabilities::CapabilityStore;
use astrid_storage::{OwnershipSnapshot, PrincipalDirectory};

/// Install local retirement fences before startup exposes either store.
/// The durable ownership reservation remains the authority to resume or
/// finish reclamation. Recovery only restores its admission consequences.
pub(super) fn restore_retirement_fences(
    ownership: &OwnershipSnapshot,
    principals: &PrincipalDirectory,
    mut capabilities: CapabilityStore,
    mut allowances: AllowanceStore,
) -> std::io::Result<(Arc<CapabilityStore>, Arc<AllowanceStore>)> {
    for alias in principals.pending_retirement_aliases(ownership) {
        let fence = capabilities.restore_principal_retirement(alias);
        allowances
            .restore_principal_retirement(fence)
            .map_err(std::io::Error::other)?;
    }
    Ok((Arc::new(capabilities), Arc::new(allowances)))
}
