//! True UID retirement, distinct from normal capsule unload.

use super::WorkspaceBranchService;

impl WorkspaceBranchService {
    pub(super) async fn confirm_new_binding(
        &self,
        uid: astrid_core::PrincipalUid,
        expected_owner: astrid_storage::StateOwner,
        branch: astrid_core::WorkspaceUid,
    ) -> Result<(), String> {
        let error = match self.owner_for(uid).await {
            Ok(owner) if owner == expected_owner => return Ok(()),
            Ok(_) => "principal workspace ownership changed during branch bind".to_owned(),
            Err(error) => error,
        };
        // A failed authority reload (including a new durable retirement
        // reservation) must not strand the branch created before that reload.
        self.branches
            .rollback(&expected_owner, branch)
            .map_err(|rollback| format!("{error}; discard unpublished workspace: {rollback}"))?;
        Err(error)
    }

    /// Reclaim one already-fenced immutable identity and forget its binding.
    /// Ordinary unload keeps durable workspaces; only true UID retirement
    /// removes them. The binding gate excludes concurrent branch construction.
    pub async fn retire_principal(&self, uid: astrid_core::PrincipalUid) -> Result<(), String> {
        let _bind_guard = self.bind_lock.lock().await;
        self.store
            .purge_principal_state(uid)
            .map_err(|error| format!("retire principal storage: {error}"))?;
        self.bindings
            .lock()
            .map_err(|_| "workspace branch binding lock poisoned".to_owned())?
            .remove(&uid);
        Ok(())
    }
}
