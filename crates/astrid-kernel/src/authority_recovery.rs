//! Restore the runtime fences implied by unfinished durable retirement.

use std::sync::Arc;

use astrid_approval::AllowanceStore;
use astrid_capabilities::CapabilityStore;
use astrid_storage::{OwnershipSnapshot, PrincipalDirectory};

/// Install local retirement fences before startup exposes either store.
/// The durable ownership reservation remains the authority to resume or
/// finish reclamation. Recovery only restores its admission consequences.
pub(super) async fn restore_retirement_fences(
    ownership: &OwnershipSnapshot,
    principals: &PrincipalDirectory,
    capabilities: CapabilityStore,
    allowances: AllowanceStore,
) -> std::io::Result<(Arc<CapabilityStore>, Arc<AllowanceStore>)> {
    for (uid, retained_alias) in ownership.pending_principal_deletions() {
        for alias in principals.retirement_aliases(uid, retained_alias.cloned()) {
            capabilities.begin_principal_retirement(alias.clone()).await;
            allowances
                .begin_principal_retirement(&alias)
                .map_err(std::io::Error::other)?;
        }
    }
    Ok((Arc::new(capabilities), Arc::new(allowances)))
}
