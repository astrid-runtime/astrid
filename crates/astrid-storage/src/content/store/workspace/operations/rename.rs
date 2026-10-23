use super::{
    BTreeMap, ContentName, ModelError, ObjectId, ObjectRecord, PrincipalProjectionEngine,
    PrincipalProjectionError, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceUid, lookup,
    make_branch_record, make_branch_record_for_uid, retain_final_catalog_records,
};

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Atomically rename exact branch names, optionally replacing admitted
    /// destinations.  The operation never reconstructs immutable file bytes.
    pub fn rename_batch(
        &self,
        owner: &P,
        id: WorkspaceUid,
        moves: &[(ContentName, ContentName)],
        replacements: &[ContentName],
    ) -> Result<bool, WorkspaceBranchError> {
        use super::super::rename_guards::RenameBatchOutcome;
        if moves.is_empty() {
            return Ok(true);
        }
        Ok(matches!(
            self.rename_batch_inner(owner, id, moves, replacements, None)?,
            RenameBatchOutcome::Committed
        ))
    }

    pub(in crate::content::store::workspace) fn rename_batch_guarded(
        &self,
        owner: &P,
        id: WorkspaceUid,
        plan: &super::super::rename_guards::RenamePlan<'_>,
    ) -> Result<super::super::rename_guards::RenameBatchOutcome, WorkspaceBranchError> {
        self.rename_batch_inner(owner, id, plan.moves, plan.replacements, Some(plan))
    }

    #[allow(clippy::too_many_lines)]
    fn rename_batch_inner(
        &self,
        owner: &P,
        id: WorkspaceUid,
        moves: &[(ContentName, ContentName)],
        replacements: &[ContentName],
        plan: Option<&super::super::rename_guards::RenamePlan<'_>>,
    ) -> Result<super::super::rename_guards::RenameBatchOutcome, WorkspaceBranchError> {
        use super::super::rename_guards::RenameBatchOutcome;
        if moves.is_empty() {
            return Ok(RenameBatchOutcome::Replan);
        }
        let sources = moves
            .iter()
            .map(|(source, _)| source)
            .collect::<std::collections::BTreeSet<_>>();
        let destinations = moves
            .iter()
            .map(|(_, destination)| destination)
            .collect::<std::collections::BTreeSet<_>>();
        let replacement_set = replacements
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if sources.len() != moves.len()
            || destinations.len() != moves.len()
            || replacement_set.len() != replacements.len()
        {
            return Ok(RenameBatchOutcome::DestinationConflict);
        }
        loop {
            let header = self.content.header(owner)?;
            let branch = self.branch(owner, &header, id)?;
            if let Some(plan) = plan
                && !self.rename_membership_matches(
                    owner,
                    branch.working,
                    plan,
                    &sources,
                    &replacement_set,
                )?
            {
                return Ok(RenameBatchOutcome::Replan);
            }
            let mut values = Vec::with_capacity(moves.len());
            for (source, destination) in moves {
                let Some(value) = lookup(branch.working, source, &mut |object| {
                    self.content.load_required_for(owner, object)
                })?
                else {
                    return Ok(RenameBatchOutcome::Replan);
                };
                if !sources.contains(destination)
                    && !replacement_set.contains(destination)
                    && lookup(branch.working, destination, &mut |object| {
                        self.content.load_required_for(owner, object)
                    })?
                    .is_some()
                {
                    return Ok(RenameBatchOutcome::DestinationConflict);
                }
                values.push(value);
            }
            // Every path-copy mutation may return a new root that is not yet
            // committed. Later deletes/inserts must resolve those pending nodes
            // before falling back to the published owner graph.
            let mut records = BTreeMap::<ObjectId, ObjectRecord>::new();
            let mut root = branch.working;
            for (source, _) in moves {
                let mutation = super::super::delete(
                    root,
                    source,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.content.load_required_for(owner, object),
                    },
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(RenameBatchOutcome::Replan);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            for replacement in replacements {
                if sources.contains(replacement) {
                    continue;
                }
                let mutation = super::super::delete(
                    root,
                    replacement,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.content.load_required_for(owner, object),
                    },
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(RenameBatchOutcome::Replan);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            for ((_, destination), value) in moves.iter().zip(values) {
                let mutation = super::super::insert(
                    root,
                    destination,
                    value,
                    &mut |object| match records.get(&object) {
                        Some(record) => Ok(record.clone()),
                        None => self.content.load_required_for(owner, object),
                    },
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_some() {
                    return Ok(RenameBatchOutcome::DestinationConflict);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            retain_final_catalog_records(root, &mut records);
            let old_quota = branch
                .working
                .map_or(0, |catalog| catalog.summary.quota_bytes);
            let new_quota = root.map_or(0, |catalog| catalog.summary.quota_bytes);
            self.enforce_quota_change(owner, &header, old_quota, new_quota)?;
            let branch_record = branch.binding_uid.map_or_else(
                || make_branch_record(id, branch.target_prefix.as_ref(), branch.base, root),
                |binding_uid| {
                    make_branch_record_for_uid(
                        binding_uid,
                        id,
                        branch.target_prefix.as_ref(),
                        branch.base,
                        root,
                    )
                },
            )?;
            let branch_id = self.content.engine.identify_object(&branch_record);
            records.insert(branch_id, branch_record);
            let mut next = header.as_ref().clone();
            let directory_receipt =
                self.edit_directory(owner, &mut next, &mut records, id, Some((branch_id, false)))?;
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
                    return Ok(RenameBatchOutcome::Committed);
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
