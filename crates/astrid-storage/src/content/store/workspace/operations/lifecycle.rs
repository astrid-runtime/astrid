use super::{
    BTreeMap, ContentName, ModelError, PrincipalProjectionEngine, PrincipalProjectionError,
    PrincipalUid, WorkspaceBindingLifecycle, WorkspaceBranchDescriptor, WorkspaceBranchError,
    WorkspaceBranchStore, WorkspaceUid, make_branch_record, make_branch_record_for_uid,
    validate_target_prefix,
};

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Begin a branch with a caller-supplied opaque identifier.
    #[cfg(test)]
    pub(crate) fn begin_with_uid_at(
        &self,
        owner: &P,
        id: WorkspaceUid,
        target_prefix: ContentName,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        let target_prefix = validate_target_prefix(Some(target_prefix))?;
        self.create_branch(owner, id, None, target_prefix.as_ref())
    }

    /// Begin a branch bound to an acting principal UID and canonical prefix.
    ///
    /// The UID is persisted in the branch record itself and is checked during
    /// recovery/mount selection. This is the only runtime creation API; the
    /// older UID-less helpers are test/migration-only and emit legacy,
    /// unbound records.
    pub fn begin_for_uid_at(
        &self,
        owner: &P,
        binding_uid: PrincipalUid,
        id: WorkspaceUid,
        target_prefix: ContentName,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        let target_prefix = validate_target_prefix(Some(target_prefix))?;
        self.create_branch(owner, id, Some(binding_uid), target_prefix.as_ref())
    }

    /// Deterministic whole-catalog helper, restricted to tests in this crate.
    #[cfg(test)]
    pub(crate) fn begin_root_with_uid(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        self.create_branch(owner, id, None, None)
    }

    // Test and migration helpers retain the old spelling inside this crate;
    // they are deliberately private so external runtime code cannot create an
    // unscoped whole-catalog mount.
    #[cfg(test)]
    pub(in crate::content::store::workspace) fn begin_with_uid(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        self.begin_root_with_uid(owner, id)
    }

    /// Fork an existing branch's immutable working view.
    ///
    /// The child captures the source working root as both base and working
    /// roots.  It therefore shares the source DAG at fork time and can only be
    /// promoted after the owner reaches that same content root.
    pub fn fork(
        &self,
        owner: &P,
        source: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        self.fork_with_uid(owner, source, WorkspaceUid::random())
    }

    /// Fork an existing branch using a deterministic child identifier.
    pub fn fork_with_uid(
        &self,
        owner: &P,
        source: WorkspaceUid,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        loop {
            let header = self.content.header(owner)?;
            let source_state = self.branch(owner, &header, source)?;
            if self.completion_receipt(owner, &header, id)?.is_some() {
                return Err(WorkspaceBranchError::AlreadyExists(id));
            }
            if let Some(existing) = self.find_branch(owner, &header, id)? {
                if existing.base == source_state.working
                    && existing.working == source_state.working
                    && existing.binding_uid == source_state.binding_uid
                    && existing.target_prefix == source_state.target_prefix
                {
                    let root = existing.base.map(|root| root.object);
                    return Ok(WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        source_state.binding_uid,
                        source_state.target_prefix.clone(),
                        root,
                        root,
                    ));
                }
                return Err(WorkspaceBranchError::AlreadyExists(id));
            }
            if let Some(binding_uid) = source_state.binding_uid
                && let Some(target_prefix) = source_state.target_prefix.clone()
                && self
                    .binding_for_uid(owner, binding_uid, &target_prefix)?
                    .is_some_and(|binding| binding.lifecycle() == WorkspaceBindingLifecycle::Live)
            {
                return Err(WorkspaceBranchError::BindingAlreadyExists {
                    binding_uid,
                    target_prefix,
                });
            }
            let base = source_state.working;
            self.enforce_quota_change(
                owner,
                &header,
                0,
                base.map_or(0, |root| root.summary.quota_bytes),
            )?;
            let record = source_state.binding_uid.map_or_else(
                || make_branch_record(id, source_state.target_prefix.as_ref(), base, base),
                |binding_uid| {
                    make_branch_record_for_uid(
                        binding_uid,
                        id,
                        source_state.target_prefix.as_ref(),
                        base,
                        base,
                    )
                },
            )?;
            let record_id = self.content.engine.identify_object(&record);
            let mut next = header.as_ref().clone();
            let mut records = BTreeMap::new();
            records.insert(record_id, record);
            let directory_receipt =
                self.edit_directory(owner, &mut next, &mut records, id, Some((record_id, false)))?;
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
                        source_state.binding_uid,
                        source_state.target_prefix.clone(),
                        base.map(|root| root.object),
                        base.map(|root| root.object),
                    ));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
