//! Authenticated principal retirement releases private working branches only.

use std::collections::{BTreeMap, BTreeSet};

use astrid_core::PrincipalUid;

use crate::engine::{PrincipalProjectionEngine, PrincipalProjectionError};
use crate::storage_model::ModelError;

use super::{
    WorkspaceBranchError, WorkspaceBranchStore, is_workspace_branch_label, parse_workspace_uid,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Release live branches bound to a retired immutable principal.
    ///
    /// The caller must hold deletion authority and quiesce that principal's
    /// writers. Other principals, the owner's main content and terminal
    /// promotion receipts remain unchanged. A concurrent promotion is re-read
    /// after a root conflict, so its completed receipt is never discarded.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid branch records or owner-root publication errors.
    /// Retrying after a committed removal is an idempotent no-op.
    pub fn retire_for_uid(
        &self,
        owner: &P,
        uid: PrincipalUid,
    ) -> Result<usize, WorkspaceBranchError> {
        loop {
            let header = self.content.header(owner)?;
            let retired: BTreeSet<_> = self
                .decode_branches(owner, &header)?
                .into_iter()
                .filter(|branch| branch.binding_uid == Some(uid))
                .map(|branch| branch.id)
                .collect();
            if retired.is_empty() {
                return Ok(0);
            }
            let mut next = header.as_ref().clone();
            next.preserved_state.retain(|reference| {
                let label = reference.label().as_bytes();
                !is_workspace_branch_label(label)
                    || parse_workspace_uid(label).is_none_or(|id| !retired.contains(&id))
            });
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, BTreeMap::new())?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => return Ok(retired.len()),
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
