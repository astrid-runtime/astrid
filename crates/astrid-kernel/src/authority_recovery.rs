//! Restore the runtime fences implied by unfinished durable retirement.

use astrid_approval::AllowanceStore;
use astrid_capabilities::CapabilityStore;
use astrid_storage::{OwnershipSnapshot, PrincipalDirectory};

/// Install local retirement fences before startup exposes either store.
/// The durable ownership reservation remains the authority to resume or
/// finish reclamation. Recovery only restores its admission consequences.
pub(super) async fn restore_retirement_fences(
    ownership: &OwnershipSnapshot,
    principals: &PrincipalDirectory,
    capabilities: &CapabilityStore,
    allowances: &AllowanceStore,
) -> std::io::Result<()> {
    for (uid, retained_alias) in ownership.pending_principal_deletions() {
        let live_alias = if principals.contains_uid(uid) {
            // Older reservations lack an alias. If the directory still
            // resolves the generation, fence that name as well.
            Some(principals.alias_for(uid).map_err(std::io::Error::other)?)
        } else {
            None
        };
        for alias in retained_alias.into_iter().chain(
            live_alias
                .as_ref()
                .filter(|alias| Some(*alias) != retained_alias),
        ) {
            capabilities.begin_principal_retirement(alias.clone()).await;
            allowances
                .begin_principal_retirement(alias)
                .map_err(std::io::Error::other)?;
        }
    }
    Ok(())
}
