use super::{
    BTreeMap, ModelError, PrincipalProjectionEngine, PrincipalProjectionError,
    WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceUid,
    make_promotion_receipt_for_uid, selected_catalog,
};

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Atomically publish a branch's working view as the owner's content view.
    ///
    /// Only the owner's content catalog identity is compared with the branch
    /// base.  A concurrent KV-only owner commit is retried against its latest
    /// root and is preserved in the resulting commit.
    pub fn promote(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        loop {
            let header = self.content.header(owner)?;
            let Some(branch) = self.find_branch(owner, &header, id)? else {
                if let Some(receipt) = self.completion_receipt(owner, &header, id)? {
                    return Ok(WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        receipt.binding_uid,
                        receipt.target_prefix,
                        receipt.base.map(|root| root.object),
                        receipt.working.map(|root| root.object),
                    ));
                }
                return Err(WorkspaceBranchError::NotFound(id));
            };
            let current_selected = selected_catalog(
                header.catalog,
                branch.target_prefix.as_ref(),
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?
            .0;
            let current = current_selected.map(|root| root.object);
            let base = branch.base.map(|root| root.object);
            if current != base {
                return Err(WorkspaceBranchError::StaleBase {
                    branch: id,
                    base,
                    current,
                });
            }
            let receipt = make_promotion_receipt_for_uid(
                branch.binding_uid,
                id,
                branch.target_prefix.as_ref(),
                branch.base,
                branch.working,
            )?;
            let receipt_id = self.content.engine.identify_object(&receipt);
            let mut records = BTreeMap::new();
            records.insert(receipt_id, receipt);
            let merged = self.merge_selected_catalog(
                owner,
                header.catalog,
                branch.target_prefix.as_ref(),
                branch.working,
                &mut records,
            )?;
            let branch_quota = branch.working.map_or(0, |root| root.summary.quota_bytes);
            self.enforce_catalog_replacement(owner, &header, branch_quota, merged)?;
            let mut next = header.as_ref().clone();
            next.catalog = merged;
            let directory_receipt =
                self.edit_directory(owner, &mut next, &mut records, id, Some((receipt_id, true)))?;
            let committed_header = next.clone();
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(outcome) => {
                    self.finish_workspace_commit(
                        owner,
                        committed_header,
                        outcome.root(),
                        directory_receipt,
                    );
                    return Ok(WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        branch.binding_uid,
                        branch.target_prefix.clone(),
                        base,
                        branch.working.map(|root| root.object),
                    ));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {
                    // A concurrent KV (or unrelated owner component) update
                    // is harmless; reload and compare the latest content root.
                },
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Remove a branch without changing the owner's main content view.
    pub fn rollback(&self, owner: &P, id: WorkspaceUid) -> Result<(), WorkspaceBranchError> {
        self.drop(owner, id)
    }

    /// Drop a branch and release its immutable DAG on the next owner-root GC.
    pub fn drop(&self, owner: &P, id: WorkspaceUid) -> Result<(), WorkspaceBranchError> {
        loop {
            let header = self.content.header(owner)?;
            let has_branch = self.find_branch(owner, &header, id)?.is_some();
            let has_receipt = self.completion_receipt(owner, &header, id)?.is_some();
            // Lifecycle cleanup is retry-safe. A lost response after a
            // successful remove therefore does not turn the retry into a
            // spurious NotFound, while an explicit drop of a promotion
            // receipt also releases that durable completion marker.
            if !has_branch && !has_receipt {
                return Ok(());
            }
            let mut next = header.as_ref().clone();
            let mut records = BTreeMap::new();
            let directory_receipt =
                self.edit_directory(owner, &mut next, &mut records, id, None)?;
            let committed_header = next.clone();
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(outcome) => {
                    self.finish_workspace_commit(
                        owner,
                        committed_header,
                        outcome.root(),
                        directory_receipt,
                    );
                    return Ok(());
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
