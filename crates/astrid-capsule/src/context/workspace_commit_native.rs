//! Native metadata and storage calls for the checked workspace finish path.
use super::{WorkspaceBranchService, workspace_commit};

pub(super) fn attachment(
    binding: &astrid_storage::WorkspaceBranchBinding<astrid_storage::StateOwner>,
) -> workspace_commit::Attachment<'_> {
    workspace_commit::Attachment {
        live: binding.lifecycle() == astrid_storage::WorkspaceBindingLifecycle::Live,
        uid: binding.binding_uid().map(|uid| *uid.as_bytes()),
        prefix: binding.target_prefix().map(|name| name.as_str().as_bytes()),
    }
}

impl workspace_commit::Writer<astrid_storage::StateOwner, astrid_core::WorkspaceUid>
    for &WorkspaceBranchService
{
    type Error = String;

    fn promote(
        &mut self,
        owner: astrid_storage::StateOwner,
        branch: astrid_core::WorkspaceUid,
    ) -> Result<(), String> {
        self.branches
            .promote(&owner, branch)
            .map(|_| ())
            .map_err(|error| format!("promote workspace branch: {error}"))
    }

    fn rollback(
        &mut self,
        owner: astrid_storage::StateOwner,
        branch: astrid_core::WorkspaceUid,
    ) -> Result<(), String> {
        self.branches
            .rollback(&owner, branch)
            .map_err(|error| format!("rollback workspace branch: {error}"))
    }
}
