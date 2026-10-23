use super::{
    BranchState, CatalogRoot, ContentHeader, ContentName, DIRECTORY_LABEL, DirectoryCommitReceipt,
    PROOF_CACHE_KEY, PrincipalContentError, PrincipalProjectionEngine, PrincipalUid,
    ProjectionCacheEntry, WorkspaceBindingLifecycle, WorkspaceBranchBinding,
    WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceLayout,
    WorkspaceUid, decode_row, inventory_prefix, is_workspace_branch_label,
    is_workspace_receipt_label, key, tree, uid_prefix,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(in super::super) fn directory_root(
        &self,
        owner: &P,
        header: &ContentHeader,
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        let Some(reference) = header
            .preserved_state
            .iter()
            .find(|reference| reference.label().as_bytes() == DIRECTORY_LABEL)
        else {
            return Ok(None);
        };
        if header.preserved_state.iter().any(|reference| {
            is_workspace_branch_label(reference.label().as_bytes())
                || is_workspace_receipt_label(reference.label().as_bytes())
        }) {
            return Err(WorkspaceBranchError::InvalidGraph {
                object: reference.target(),
                detail: "mixed flat and indexed workspace state",
            });
        }
        Ok(Some(tree::root_from_record_with_layout::<WorkspaceLayout>(
            reference.target(),
            &self.content.load_required_for(owner, reference.target())?,
        )?))
    }

    pub(in super::super) fn find_branch(
        &self,
        owner: &P,
        header: &ContentHeader,
        id: WorkspaceUid,
    ) -> Result<Option<BranchState>, WorkspaceBranchError> {
        let Some(root) = self.directory_root(owner, header)? else {
            return Ok(self
                .decode_legacy_branches(owner, header)?
                .into_iter()
                .find(|branch| branch.id == id));
        };
        self.directory_state(owner, root, &key("b", id)?)
            .map(|state| state.map(|(branch, _)| branch))
    }

    pub(in super::super) fn directory_state(
        &self,
        owner: &P,
        root: CatalogRoot,
        name: &ContentName,
    ) -> Result<Option<(BranchState, bool)>, WorkspaceBranchError> {
        let Some(value) =
            tree::lookup_with_layout::<WorkspaceLayout>(Some(root), name, &mut |object| {
                self.content.load_required_for(owner, object)
            })?
        else {
            return Ok(None);
        };
        let (mut branch, promoted) = decode_row(
            value.file,
            &self.content.load_required_for(owner, value.file)?,
        )?;
        if !promoted {
            branch.base = self.hydrate_root(owner, branch.base)?;
            branch.working = self.hydrate_root(owner, branch.working)?;
        }
        Ok(Some((branch, promoted)))
    }

    pub(in super::super) fn decode_branches(
        &self,
        owner: &P,
        header: &ContentHeader,
    ) -> Result<Vec<BranchState>, WorkspaceBranchError> {
        let Some(root) = self.directory_root(owner, header)? else {
            return self.decode_legacy_branches(owner, header);
        };
        let prefix = ContentName::new("b/").map_err(PrincipalContentError::InvalidName)?;
        tree::list_prefix_with_layout::<WorkspaceLayout>(Some(root), &prefix, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        .into_iter()
        .map(|entry| {
            self.directory_state(owner, root, entry.name())?
                .map(|(branch, _)| branch)
                .ok_or(WorkspaceBranchError::InvalidGraph {
                    object: root.object,
                    detail: "workspace directory branch disappeared",
                })
        })
        .collect()
    }

    pub(in super::super) fn completion_receipt(
        &self,
        owner: &P,
        header: &ContentHeader,
        id: WorkspaceUid,
    ) -> Result<Option<BranchState>, WorkspaceBranchError> {
        let Some(root) = self.directory_root(owner, header)? else {
            return self.completion_receipt_legacy(owner, header, id);
        };
        self.directory_state(owner, root, &key("r", id)?)
            .map(|state| state.map(|(branch, _)| branch))
    }

    pub(in super::super) fn indexed_bindings(
        &self,
        owner: &P,
        header: &ContentHeader,
        uid: Option<PrincipalUid>,
    ) -> Result<Option<Vec<WorkspaceBranchBinding<P>>>, WorkspaceBranchError> {
        let Some(root) = self.directory_root(owner, header)? else {
            return Ok(None);
        };
        let entries = if let Some(uid) = uid {
            tree::list_prefix_with_layout::<WorkspaceLayout>(
                Some(root),
                &ContentName::new(inventory_prefix(uid))
                    .map_err(PrincipalContentError::InvalidName)?,
                &mut |object| self.content.load_required_for(owner, object),
            )?
        } else {
            tree::list_with_layout::<WorkspaceLayout>(Some(root), &mut |object| {
                self.content.load_required_for(owner, object)
            })?
            .into_iter()
            .filter(|entry| {
                !entry.name().as_str().starts_with("u/") && !entry.name().as_str().starts_with("a/")
            })
            .collect()
        };
        entries
            .into_iter()
            .map(|entry| {
                let (branch, promoted) = self.directory_state(owner, root, entry.name())?.ok_or(
                    WorkspaceBranchError::InvalidGraph {
                        object: root.object,
                        detail: "workspace directory binding disappeared",
                    },
                )?;
                Ok(Self::binding_descriptor(owner, branch, promoted))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    pub(in super::super) fn binding_descriptor(
        owner: &P,
        branch: BranchState,
        promoted: bool,
    ) -> WorkspaceBranchBinding<P> {
        WorkspaceBranchBinding::new(
            WorkspaceBranchDescriptor::new(
                owner.clone(),
                branch.id,
                branch.binding_uid,
                branch.target_prefix,
                branch.base.map(|root| root.object),
                branch.working.map(|root| root.object),
            ),
            if promoted {
                WorkspaceBindingLifecycle::Promoted
            } else {
                WorkspaceBindingLifecycle::Live
            },
        )
    }

    pub(in super::super) fn indexed_binding_for_uid(
        &self,
        owner: &P,
        header: &ContentHeader,
        uid: PrincipalUid,
        prefix: &ContentName,
    ) -> Result<super::WorkspaceBindingLookup<P>, WorkspaceBranchError> {
        let Some(root) = self.directory_root(owner, header)? else {
            return Ok(super::WorkspaceBindingLookup::Legacy);
        };
        let name = ContentName::new(format!("{}{prefix}", uid_prefix(uid)))
            .map_err(PrincipalContentError::InvalidName)?;
        self.directory_state(owner, root, &name).map(|state| {
            super::WorkspaceBindingLookup::Indexed(
                state.map(|(branch, promoted)| Self::binding_descriptor(owner, branch, promoted)),
            )
        })
    }

    pub(in super::super) fn finish_workspace_commit(
        &self,
        owner: &P,
        header: ContentHeader,
        root: crate::storage_model::RootState,
        receipt: DirectoryCommitReceipt,
    ) {
        // Only the single-use validated delta from this successful CAS can
        // admit a proof. A directory's structural root alone is insufficient.
        let (proof, previous) = receipt.into_parts();
        let current = header
            .preserved_state
            .iter()
            .find(|reference| reference.label().as_bytes() == DIRECTORY_LABEL)
            .map(crate::storage_model::ObjectReference::target);
        if let Some(previous) = previous.filter(|previous| Some(*previous) != current) {
            self.content
                .engine
                .discard_projection_cache(owner, previous, PROOF_CACHE_KEY);
        }
        if let Some(proof) = proof.filter(|proof| Some(proof.root.object) == current) {
            let _ = self
                .content
                .engine
                .load_shared_object_for(owner, proof.root.object);
            let _ = self.content.engine.retain_projection_cache(
                owner,
                proof.root.object,
                PROOF_CACHE_KEY,
                ProjectionCacheEntry::new(proof),
            );
        }
        self.content.finish_catalog_commit(owner, header, root);
    }
}
