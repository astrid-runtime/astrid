use super::{
    BTreeMap, ContentName, PrincipalProjectionEngine, PrincipalUid, WorkspaceBindingLifecycle,
    WorkspaceBranchBinding, WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore,
    WorkspaceUid, parse_workspace_receipt_uid,
};

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Describe one live branch and its owner/base/current roots.
    pub fn describe(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        Ok(WorkspaceBranchDescriptor::new(
            owner.clone(),
            id,
            branch.binding_uid,
            branch.target_prefix,
            branch.base.map(|root| root.object),
            branch.working.map(|root| root.object),
        ))
    }

    /// Enumerate all live owner-internal branches for boot cleanup and mount
    /// authorization. Completion receipts are intentionally excluded.
    pub fn list_branches(
        &self,
        owner: &P,
    ) -> Result<Vec<WorkspaceBranchDescriptor<P>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        Ok(self
            .decode_branches(owner, &header)?
            .into_iter()
            .map(|branch| {
                WorkspaceBranchDescriptor::new(
                    owner.clone(),
                    branch.id,
                    branch.binding_uid,
                    branch.target_prefix,
                    branch.base.map(|root| root.object),
                    branch.working.map(|root| root.object),
                )
            })
            .collect())
    }

    /// Recover one durable branch binding, including a terminal promotion
    /// receipt when the branch was already committed.
    pub fn binding(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchBinding<P>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        if let Some(branch) = self.find_branch(owner, &header, id)? {
            return Ok(WorkspaceBranchBinding::new(
                WorkspaceBranchDescriptor::new(
                    owner.clone(),
                    id,
                    branch.binding_uid,
                    branch.target_prefix,
                    branch.base.map(|root| root.object),
                    branch.working.map(|root| root.object),
                ),
                WorkspaceBindingLifecycle::Live,
            ));
        }
        let receipt = self
            .completion_receipt(owner, &header, id)?
            .ok_or(WorkspaceBranchError::NotFound(id))?;
        Ok(WorkspaceBranchBinding::new(
            WorkspaceBranchDescriptor::new(
                owner.clone(),
                id,
                receipt.binding_uid,
                receipt.target_prefix,
                receipt.base.map(|root| root.object),
                receipt.working.map(|root| root.object),
            ),
            WorkspaceBindingLifecycle::Promoted,
        ))
    }

    /// Enumerate live and terminal bindings retained in one owner root.
    pub fn list_bindings(
        &self,
        owner: &P,
    ) -> Result<Vec<WorkspaceBranchBinding<P>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        if let Some(bindings) = self.indexed_bindings(owner, &header, None)? {
            return Ok(bindings);
        }
        let mut bindings = self
            .decode_branches(owner, &header)?
            .into_iter()
            .map(|branch| {
                WorkspaceBranchBinding::new(
                    WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        branch.id,
                        branch.binding_uid,
                        branch.target_prefix,
                        branch.base.map(|root| root.object),
                        branch.working.map(|root| root.object),
                    ),
                    WorkspaceBindingLifecycle::Live,
                )
            })
            .collect::<Vec<_>>();
        for reference in &header.preserved_state {
            let Some(id) = parse_workspace_receipt_uid(reference.label().as_bytes()) else {
                continue;
            };
            if let Some(receipt) = self.completion_receipt(owner, &header, id)? {
                bindings.push(WorkspaceBranchBinding::new(
                    WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        receipt.binding_uid,
                        receipt.target_prefix,
                        receipt.base.map(|root| root.object),
                        receipt.working.map(|root| root.object),
                    ),
                    WorkspaceBindingLifecycle::Promoted,
                ));
            }
        }
        bindings.sort_by_key(WorkspaceBranchBinding::branch_id);
        Ok(bindings)
    }

    /// Recover all bindings claimed by one acting principal UID.
    pub fn list_bindings_by_uid(
        &self,
        owner: &P,
        binding_uid: PrincipalUid,
    ) -> Result<Vec<WorkspaceBranchBinding<P>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        if let Some(bindings) = self.indexed_bindings(owner, &header, Some(binding_uid))? {
            return Ok(bindings);
        }
        let bindings = self
            .list_bindings(owner)?
            .into_iter()
            .filter(|binding| binding.binding_uid() == Some(binding_uid))
            .collect::<Vec<_>>();
        let mut seen = BTreeMap::<Option<&ContentName>, WorkspaceUid>::new();
        for binding in &bindings {
            if binding.lifecycle() != WorkspaceBindingLifecycle::Live {
                continue;
            }
            if let Some(previous) = seen.insert(binding.target_prefix(), binding.branch_id())
                && previous != binding.branch_id()
            {
                let prefix = binding.target_prefix().cloned().ok_or(
                    WorkspaceBranchError::InvalidTargetPrefix {
                        detail: "bound workspace prefix cannot be omitted",
                    },
                )?;
                return Err(WorkspaceBranchError::BindingAlreadyExists {
                    binding_uid,
                    target_prefix: prefix,
                });
            }
        }
        Ok(bindings)
    }

    /// Recover the unique binding for a UID/prefix attachment, if present.
    pub fn binding_for_uid(
        &self,
        owner: &P,
        binding_uid: PrincipalUid,
        target_prefix: &ContentName,
    ) -> Result<Option<WorkspaceBranchBinding<P>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        match self.indexed_binding_for_uid(owner, &header, binding_uid, target_prefix)? {
            super::super::directory::WorkspaceBindingLookup::Legacy => {},
            super::super::directory::WorkspaceBindingLookup::Indexed(binding) => {
                return Ok(binding);
            },
        }
        let mut matches = self
            .list_bindings_by_uid(owner, binding_uid)?
            .into_iter()
            .filter(|binding| binding.target_prefix() == Some(target_prefix))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(WorkspaceBranchError::BindingAlreadyExists {
                binding_uid,
                target_prefix: target_prefix.clone(),
            });
        }
        Ok(matches.pop())
    }
}
