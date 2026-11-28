//! Restore the runtime fences implied by unfinished durable retirement.

use std::sync::Arc;

use astrid_approval::{AllowanceStore, ApprovalError};
use astrid_capabilities::CapabilityStore;
use astrid_core::PrincipalId;
use astrid_storage::{OwnershipSnapshot, PrincipalDirectory, RetirementSink};

mod publication;

struct RecoveringStores {
    capabilities: CapabilityStore,
    allowances: AllowanceStore,
}

impl RetirementSink<PrincipalId> for RecoveringStores {
    type Error = ApprovalError;

    fn restore(&mut self, alias: PrincipalId) -> Result<(), Self::Error> {
        let fence = self.capabilities.restore_principal_retirement(alias);
        self.allowances.restore_principal_retirement(fence)
    }
}

/// Install local retirement fences before startup exposes either store.
/// The durable ownership reservation remains the authority to resume or
/// finish reclamation. Recovery only restores its admission consequences.
pub(super) fn restore_retirement_fences(
    ownership: std::io::Result<OwnershipSnapshot>,
    principals: &PrincipalDirectory,
    capabilities: CapabilityStore,
    allowances: AllowanceStore,
) -> std::io::Result<(Arc<CapabilityStore>, Arc<AllowanceStore>)> {
    let stores = RecoveringStores {
        capabilities,
        allowances,
    };
    publication::publish(ownership, stores, |graph, mut stores| {
        principals
            .replay_retirements(&graph, &mut stores)
            .map_err(std::io::Error::other)?;
        Ok((stores.capabilities, stores.allowances))
    })
}
