//! Public workspace branch store operations.

use std::collections::BTreeMap;

use astrid_core::PrincipalUid;

use crate::content::{ContentEntry, ContentName};
use crate::content_dag::{
    build_content, open_content, read_opened_content, read_opened_content_range,
};
use crate::engine::{PrincipalProjectionEngine, PrincipalProjectionError};
use crate::storage_model::{ModelError, ObjectReference};

use super::{
    EngineIdentity, EngineSource, MAX_WORKSPACE_BRANCHES, WorkspaceBindingLifecycle,
    WorkspaceBranchBinding, WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore,
    WorkspaceFilesystem, WorkspaceUid, list, lookup, make_branch_record,
    make_branch_record_for_uid, make_promotion_receipt_for_uid, map_read_error,
    parse_workspace_receipt_uid, parse_workspace_uid, selected_catalog, validate_target_prefix,
    workspace_receipt_label, workspace_ref_label,
};

impl<P: Ord, E> WorkspaceBranchStore<P, E> {
    /// Bind a filesystem view to one owner and branch identifier.
    #[must_use]
    pub fn filesystem(&self, owner: P, branch: WorkspaceUid) -> WorkspaceFilesystem<P, E> {
        WorkspaceFilesystem {
            branches: self.clone(),
            owner,
            branch,
        }
    }
}

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
    pub(super) fn begin_with_uid(
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
            let branches = self.decode_branches(owner, &header)?;
            let source_state = branches
                .iter()
                .find(|branch| branch.id == source)
                .ok_or(WorkspaceBranchError::NotFound(source))?;
            if self.completion_receipt(owner, &header, id)?.is_some() {
                return Err(WorkspaceBranchError::AlreadyExists(id));
            }
            if let Some(existing) = branches.iter().find(|branch| branch.id == id) {
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
            if branches.len() >= MAX_WORKSPACE_BRANCHES {
                return Err(WorkspaceBranchError::BranchLimitExceeded);
            }
            if let Some(binding_uid) = source_state.binding_uid
                && branches.iter().any(|branch| {
                    branch.id != id
                        && branch.binding_uid == Some(binding_uid)
                        && branch.target_prefix == source_state.target_prefix
                })
                && let Some(target_prefix) = source_state.target_prefix.clone()
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
            next.preserved_state
                .push(ObjectReference::owns(workspace_ref_label(id), record_id));
            let mut records = BTreeMap::new();
            records.insert(record_id, record);
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => {
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

    /// Describe one live branch and its owner/base/current roots.
    pub fn describe(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self
            .decode_branches(owner, &header)?
            .into_iter()
            .find(|branch| branch.id == id)
            .ok_or(WorkspaceBranchError::NotFound(id))?;
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
        if let Some(branch) = self
            .decode_branches(owner, &header)?
            .into_iter()
            .find(|branch| branch.id == id)
        {
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

    /// Read one complete immutable branch file.
    pub fn read(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
    ) -> Result<Option<Vec<u8>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let Some(value) = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        else {
            return Ok(None);
        };
        let source = EngineSource::<P, E>::new(self.content.engine.as_ref(), owner);
        let opened = open_content(&source, value.file).map_err(map_read_error)?;
        read_opened_content(&source, opened)
            .map(Some)
            .map_err(map_read_error)
    }

    /// Read an exact range from one immutable branch file.
    pub fn read_range(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
        offset: u64,
        length: u64,
    ) -> Result<Option<Vec<u8>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let Some(value) = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        else {
            return Ok(None);
        };
        let source = EngineSource::<P, E>::new(self.content.engine.as_ref(), owner);
        let opened = open_content(&source, value.file).map_err(map_read_error)?;
        read_opened_content_range(&source, opened, offset, length)
            .map(Some)
            .map_err(map_read_error)
    }

    /// List all named values in a branch's current immutable catalog.
    pub fn list(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<Vec<ContentEntry>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        list(branch.working, &mut |object| {
            self.content.load_required_for(owner, object)
        })
        .map_err(Into::into)
    }

    /// Publish complete file bytes into a branch view.
    pub fn write(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
        bytes: &[u8],
    ) -> Result<(), WorkspaceBranchError> {
        let built = build_content(
            &EngineIdentity::<P, E>::new(self.content.engine.as_ref()),
            crate::content_dag::ChunkingProfile::ASTRID_V1,
            bytes,
        )?;
        let file = built.descriptor().file();
        let logical_bytes = built.descriptor().logical_bytes();
        self.mutate_catalog(owner, id, Some(&built), |root, records| {
            let mutation = super::insert(
                root,
                name,
                super::CatalogValue {
                    file,
                    logical_bytes,
                },
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            records.extend(mutation.records);
            Ok(mutation.root)
        })
    }

    /// Remove one named file from a branch.  Directory markers are treated as
    /// ordinary named values by this lower-level API; the filesystem wrapper
    /// enforces directory semantics.
    pub fn remove_name(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
    ) -> Result<bool, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let exists = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        .is_some();
        if !exists {
            return Ok(false);
        }
        self.mutate_catalog(owner, id, None, |root, records| {
            let mutation = super::delete(
                root,
                name,
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            records.extend(mutation.records);
            Ok(mutation.root)
        })?;
        Ok(true)
    }

    /// Atomically rename exact branch names, optionally replacing admitted
    /// destinations.  The operation never reconstructs immutable file bytes.
    #[allow(clippy::too_many_lines)]
    pub fn rename_batch(
        &self,
        owner: &P,
        id: WorkspaceUid,
        moves: &[(ContentName, ContentName)],
        replacements: &[ContentName],
    ) -> Result<bool, WorkspaceBranchError> {
        if moves.is_empty() {
            return Ok(true);
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
            return Ok(false);
        }
        loop {
            let header = self.content.header(owner)?;
            let branch = self.branch(owner, &header, id)?;
            let mut values = Vec::with_capacity(moves.len());
            for (source, destination) in moves {
                let Some(value) = lookup(branch.working, source, &mut |object| {
                    self.content.load_required_for(owner, object)
                })?
                else {
                    return Ok(false);
                };
                if !sources.contains(destination)
                    && !replacement_set.contains(destination)
                    && lookup(branch.working, destination, &mut |object| {
                        self.content.load_required_for(owner, object)
                    })?
                    .is_some()
                {
                    return Ok(false);
                }
                values.push(value);
            }
            let mut records = BTreeMap::new();
            let mut root = branch.working;
            for (source, _) in moves {
                let mutation = super::delete(
                    root,
                    source,
                    &mut |object| self.content.load_required_for(owner, object),
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(false);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            for replacement in replacements {
                if sources.contains(replacement) {
                    continue;
                }
                let mutation = super::delete(
                    root,
                    replacement,
                    &mut |object| self.content.load_required_for(owner, object),
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_none() {
                    return Ok(false);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            for ((_, destination), value) in moves.iter().zip(values) {
                let mutation = super::insert(
                    root,
                    destination,
                    value,
                    &mut |object| self.content.load_required_for(owner, object),
                    &|record| self.content.engine.identify_object(record),
                )?;
                if mutation.previous.is_some() {
                    return Ok(false);
                }
                root = mutation.root;
                records.extend(mutation.records);
            }
            let old_quota = branch
                .working
                .map_or(0, |catalog| catalog.summary.quota_bytes);
            let new_quota = root.map_or(0, |catalog| catalog.summary.quota_bytes);
            self.enforce_quota_change(owner, &header, old_quota, new_quota)?;
            let branch_record =
                make_branch_record(id, branch.target_prefix.as_ref(), branch.base, root)?;
            let branch_id = self.content.engine.identify_object(&branch_record);
            records.insert(branch_id, branch_record);
            let mut next = header.as_ref().clone();
            next.preserved_state
                .retain(|reference| parse_workspace_uid(reference.label().as_bytes()) != Some(id));
            next.preserved_state
                .push(ObjectReference::owns(workspace_ref_label(id), branch_id));
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => return Ok(true),
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

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
            let branches = self.decode_branches(owner, &header)?;
            let Some(branch) = branches.iter().find(|branch| branch.id == id) else {
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
            next.preserved_state.retain(|reference| {
                parse_workspace_uid(reference.label().as_bytes()) != Some(id)
                    && parse_workspace_receipt_uid(reference.label().as_bytes()) != Some(id)
            });
            next.preserved_state.push(ObjectReference::owns(
                workspace_receipt_label(id),
                receipt_id,
            ));
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => {
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
            let has_branch = self
                .decode_branches(owner, &header)?
                .iter()
                .any(|branch| branch.id == id);
            let has_receipt = self.completion_receipt(owner, &header, id)?.is_some();
            // Lifecycle cleanup is retry-safe. A lost response after a
            // successful remove therefore does not turn the retry into a
            // spurious NotFound, while an explicit drop of a promotion
            // receipt also releases that durable completion marker.
            if !has_branch && !has_receipt {
                return Ok(());
            }
            let mut next = header.as_ref().clone();
            next.preserved_state.retain(|reference| {
                parse_workspace_uid(reference.label().as_bytes()) != Some(id)
                    && parse_workspace_receipt_uid(reference.label().as_bytes()) != Some(id)
            });
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, BTreeMap::new())?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => return Ok(()),
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
