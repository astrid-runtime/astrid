use super::{
    BTreeMap, BranchState, CatalogRoot, CatalogValue, ContentHeader, ContentName, DIRECTORY_LABEL,
    DIRECTORY_VERSION, DirectoryCommitReceipt, DirectoryProof, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, PROOF_CACHE_KEY, PrincipalContentError, PrincipalProjectionEngine,
    ProjectionCacheEntry, ReferenceKind, ReferenceLabel, WorkspaceBranchError,
    WorkspaceBranchStore, WorkspaceLayout, WorkspaceUid, binding_key, decode_row, inventory_key,
    is_workspace_branch_label, is_workspace_receipt_label, key, parse_workspace_receipt_uid,
    parse_workspace_uid, root_from_record, row_charge, tree, validation,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Apply the identity row and its UID selector together in the caller's
    /// root CAS. No intermediate directory becomes authoritative. Returns a
    /// single-use proof receipt for finish after a successful commit.
    pub(in super::super) fn edit_directory(
        &self,
        owner: &P,
        header: &mut ContentHeader,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        id: WorkspaceUid,
        replacement: Option<(ObjectId, bool)>,
    ) -> Result<DirectoryCommitReceipt, WorkspaceBranchError> {
        let indexed = self.directory_root(owner, header)?;
        if indexed.is_none() && replacement.is_none_or(|(_, promoted)| promoted) {
            return self.edit_legacy_cleanup(owner, header, records, id, replacement);
        }
        let previous = indexed.map(|root| root.object);
        let prior = indexed
            .map(|root| self.load_authenticated_proof(owner, root))
            .transpose()?;
        let mut root = match indexed {
            Some(root) => Some(root),
            None => self.migrate_directory(owner, header, records)?,
        };
        let old_quota = if let Some(root) = indexed {
            root.summary.quota_bytes
        } else {
            self.decode_legacy_branches(owner, header)?
                .iter()
                .try_fold(0_u64, |total, branch| {
                    total
                        .checked_add(branch.working.map_or(0, |root| root.summary.quota_bytes))
                        .ok_or(PrincipalContentError::AccountingOverflow)
                })?
        };
        let old_primary = self.pending_primary(owner, root, records, id)?;
        let selectors = self.plan_selectors(
            owner,
            root,
            records,
            old_primary.as_ref().map(|(branch, _)| branch),
            replacement,
        )?;
        let replacement_binding = replacement
            .map(|(object, _)| {
                let (branch, _) = decode_row(
                    object,
                    &self.directory_load_pending(owner, object, records)?,
                )?;
                binding_key(&branch)
            })
            .transpose()?
            .flatten();
        self.remove_directory_primary(
            owner,
            &mut root,
            records,
            id,
            replacement_binding.as_ref(),
            &selectors,
        )?;
        let new_primary = if let Some((object, promoted)) = replacement {
            root = self.replace_directory_row(owner, root, records, id, (object, promoted))?;
            self.pending_primary(owner, root, records, id)?
        } else {
            None
        };
        let new_quota = root.map_or(0, |root| root.summary.quota_bytes);
        if new_quota > old_quota {
            self.enforce_quota_change(owner, header, old_quota, new_quota)?;
        }
        header.other_quota_bytes = header
            .other_quota_bytes
            .checked_sub(old_quota)
            .and_then(|bytes| bytes.checked_add(new_quota))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        header.preserved_state.retain(|reference| {
            reference.label().as_bytes() != DIRECTORY_LABEL
                && !is_workspace_branch_label(reference.label().as_bytes())
                && !is_workspace_receipt_label(reference.label().as_bytes())
        });
        if let Some(root) = root {
            header.preserved_state.push(ObjectReference::owns(
                ReferenceLabel::new(DIRECTORY_LABEL.to_vec()),
                root.object,
            ));
        }
        Self::retain_directory_records(root, records);
        let proof = validation::prove_commit(
            prior,
            root,
            id,
            old_primary.as_ref(),
            new_primary.as_ref(),
            &selectors,
            &mut |object| self.directory_load_pending(owner, object, records),
        )?;
        Ok(DirectoryCommitReceipt { proof, previous })
    }

    fn remove_directory_primary(
        &self,
        owner: &P,
        root: &mut Option<CatalogRoot>,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        id: WorkspaceUid,
        replacement_binding: Option<&ContentName>,
        selectors: &BTreeMap<ContentName, Option<ObjectId>>,
    ) -> Result<Option<(BranchState, bool)>, WorkspaceBranchError> {
        let mut old_primary = None;
        for tag in ["b", "r"] {
            let name = key(tag, id)?;
            let Some(value) = self.directory_lookup_pending(owner, *root, &name, records)? else {
                continue;
            };
            let record = self.directory_load_pending(owner, value.file, records)?;
            let (previous, promoted) = decode_row(value.file, &record)?;
            if let Some(inventory) = inventory_key(&previous)? {
                if self
                    .directory_lookup_pending(owner, *root, &inventory, records)?
                    .map(|entry| entry.file)
                    != Some(value.file)
                {
                    return Err(WorkspaceBranchError::InvalidGraph {
                        object: value.file,
                        detail: "workspace inventory changed independently",
                    });
                }
                *root = self.directory_delete(owner, *root, &inventory, records)?;
            }
            if let Some(binding) = binding_key(&previous)?
                && self
                    .directory_lookup_pending(owner, *root, &binding, records)?
                    .map(|entry| entry.file)
                    == Some(value.file)
            {
                *root = self.directory_delete(owner, *root, &binding, records)?;
                if replacement_binding != Some(&binding)
                    && let Some(object) = selectors.get(&binding).copied().flatten()
                {
                    *root = self.directory_insert(
                        owner,
                        *root,
                        &binding,
                        CatalogValue {
                            file: object,
                            logical_bytes: 0,
                        },
                        records,
                    )?;
                }
            }
            *root = self.directory_delete(owner, *root, &name, records)?;
            old_primary = Some((previous, promoted));
        }
        Ok(old_primary)
    }

    fn pending_primary(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        records: &BTreeMap<ObjectId, ObjectRecord>,
        id: WorkspaceUid,
    ) -> Result<Option<(BranchState, bool)>, WorkspaceBranchError> {
        for promoted in [false, true] {
            let name = key(if promoted { "r" } else { "b" }, id)?;
            let Some(value) = self.directory_lookup_pending(owner, root, &name, records)? else {
                continue;
            };
            let record = self.directory_load_pending(owner, value.file, records)?;
            let (branch, actual) = decode_row(value.file, &record)?;
            if actual != promoted {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: value.file,
                    detail: "workspace primary lifecycle disagrees",
                });
            }
            return Ok(Some((branch, actual)));
        }
        Ok(None)
    }

    fn load_authenticated_proof(
        &self,
        owner: &P,
        root: CatalogRoot,
    ) -> Result<DirectoryProof, WorkspaceBranchError> {
        if let Some(entry) =
            self.content
                .engine
                .load_projection_cache(owner, root.object, PROOF_CACHE_KEY)
            && let Some(proof) = entry.downcast::<DirectoryProof>()
            && proof.root == root
        {
            return Ok(*proof);
        }
        let reference =
            ObjectReference::owns(ReferenceLabel::new(DIRECTORY_LABEL.to_vec()), root.object);
        let proof = validation::validate(&reference, &mut |object| {
            self.content.load_required_for(owner, object)
        })?;
        if proof.root != root {
            return Err(WorkspaceBranchError::InvalidGraph {
                object: root.object,
                detail: "workspace directory proof root disagrees",
            });
        }
        let _ = self.content.engine.retain_projection_cache(
            owner,
            root.object,
            PROOF_CACHE_KEY,
            ProjectionCacheEntry::new(proof),
        );
        Ok(proof)
    }

    fn replace_directory_row(
        &self,
        owner: &P,
        mut root: Option<CatalogRoot>,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        id: WorkspaceUid,
        replacement: (ObjectId, bool),
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        let (object, promoted) = replacement;
        let record = self.directory_load_pending(owner, object, records)?;
        let (mut branch, actual_promoted) = decode_row(object, &record)?;
        if branch.id != id || promoted != actual_promoted {
            return Err(WorkspaceBranchError::InvalidGraph {
                object,
                detail: "workspace replacement identity disagrees",
            });
        }
        if !promoted {
            branch.base = branch
                .base
                .map(|root| {
                    self.directory_load_pending(owner, root.object, records)
                        .and_then(|record| root_from_record(root.object, &record))
                })
                .transpose()?;
            branch.working = branch
                .working
                .map(|root| {
                    self.directory_load_pending(owner, root.object, records)
                        .and_then(|record| root_from_record(root.object, &record))
                })
                .transpose()?;
        }
        let value = CatalogValue {
            file: object,
            logical_bytes: row_charge(&record, &branch, promoted)?,
        };
        root = self.directory_insert(
            owner,
            root,
            &key(if promoted { "r" } else { "b" }, id)?,
            value,
            records,
        )?;
        if let Some(inventory) = inventory_key(&branch)? {
            root = self.directory_insert(
                owner,
                root,
                &inventory,
                CatalogValue {
                    file: object,
                    logical_bytes: 0,
                },
                records,
            )?;
        }
        if let Some(binding) = binding_key(&branch)? {
            if let Some(existing) = self.directory_lookup_pending(owner, root, &binding, records)? {
                let (_, previous_promoted) = decode_row(
                    existing.file,
                    &self.directory_load_pending(owner, existing.file, records)?,
                )?;
                if !previous_promoted {
                    return Err(WorkspaceBranchError::BindingAlreadyExists {
                        binding_uid: branch
                            .binding_uid
                            .ok_or(PrincipalContentError::AccountingOverflow)?,
                        target_prefix: branch
                            .target_prefix
                            .ok_or(PrincipalContentError::AccountingOverflow)?,
                    });
                }
            }
            root = self.directory_insert(
                owner,
                root,
                &binding,
                CatalogValue {
                    file: object,
                    logical_bytes: 0,
                },
                records,
            )?;
        }
        Ok(root)
    }

    pub(super) fn directory_load_pending(
        &self,
        owner: &P,
        object: ObjectId,
        records: &BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        records
            .get(&object)
            .cloned()
            .map_or_else(|| self.content.load_required_for(owner, object), Ok)
    }

    pub(super) fn directory_lookup_pending(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        name: &ContentName,
        records: &BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<Option<CatalogValue>, PrincipalContentError> {
        tree::lookup_with_layout::<WorkspaceLayout>(root, name, &mut |object| {
            self.directory_load_pending(owner, object, records)
        })
    }

    fn directory_insert(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        name: &ContentName,
        value: CatalogValue,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<Option<CatalogRoot>, PrincipalContentError> {
        let mutation = tree::insert_with_layout::<WorkspaceLayout>(
            root,
            name,
            value,
            &mut |object| self.directory_load_pending(owner, object, records),
            &|record| self.content.engine.identify_object(record),
        )?;
        records.extend(mutation.records);
        Ok(mutation.root)
    }

    fn directory_delete(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        name: &ContentName,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<Option<CatalogRoot>, PrincipalContentError> {
        let mutation = tree::delete_with_layout::<WorkspaceLayout>(
            root,
            name,
            &mut |object| self.directory_load_pending(owner, object, records),
            &|record| self.content.engine.identify_object(record),
        )?;
        records.extend(mutation.records);
        Ok(mutation.root)
    }

    fn migrate_directory(
        &self,
        owner: &P,
        header: &ContentHeader,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        let mut entries = BTreeMap::new();
        let mut ids = std::collections::BTreeSet::new();
        for reference in &header.preserved_state {
            let promoted = is_workspace_receipt_label(reference.label().as_bytes());
            if !promoted && !is_workspace_branch_label(reference.label().as_bytes()) {
                continue;
            }
            let id = if promoted {
                parse_workspace_receipt_uid(reference.label().as_bytes())
            } else {
                parse_workspace_uid(reference.label().as_bytes())
            }
            .ok_or(WorkspaceBranchError::InvalidGraph {
                object: reference.target(),
                detail: "invalid legacy workspace label",
            })?;
            let record = self.content.load_required_for(owner, reference.target())?;
            let (mut branch, actual_promoted) = decode_row(reference.target(), &record)?;
            if reference.kind() != ReferenceKind::Owns
                || branch.id != id
                || promoted != actual_promoted
                || !ids.insert(id)
            {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: reference.target(),
                    detail: "legacy workspace identity disagrees",
                });
            }
            if !promoted {
                branch.base =
                    self.validate_catalog(owner, self.hydrate_root(owner, branch.base)?)?;
                branch.working =
                    self.validate_catalog(owner, self.hydrate_root(owner, branch.working)?)?;
            }
            entries.insert(
                key(if promoted { "r" } else { "b" }, id)?,
                CatalogValue {
                    file: reference.target(),
                    logical_bytes: row_charge(&record, &branch, promoted)?,
                },
            );
            if let Some(inventory) = inventory_key(&branch)? {
                entries.insert(
                    inventory,
                    CatalogValue {
                        file: reference.target(),
                        logical_bytes: 0,
                    },
                );
            }
            if let Some(binding) = binding_key(&branch)? {
                if let Some(existing) = entries.get(&binding) {
                    let (_, previous_promoted) = decode_row(
                        existing.file,
                        &self.content.load_required_for(owner, existing.file)?,
                    )?;
                    if !promoted && !previous_promoted {
                        return Err(WorkspaceBranchError::InvalidGraph {
                            object: reference.target(),
                            detail: "duplicate legacy live workspace binding",
                        });
                    }
                    if !previous_promoted {
                        continue;
                    }
                }
                entries.insert(
                    binding,
                    CatalogValue {
                        file: reference.target(),
                        logical_bytes: 0,
                    },
                );
            }
        }
        let (root, nodes) =
            tree::build_catalog_with_layout::<WorkspaceLayout>(&entries, &|record| {
                self.content.engine.identify_object(record)
            })?;
        records.extend(nodes);
        Ok(root)
    }

    fn retain_directory_records(
        root: Option<CatalogRoot>,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) {
        let mut retained = std::collections::BTreeSet::new();
        let mut pending = root.map(|root| root.object).into_iter().collect::<Vec<_>>();
        while let Some(object) = pending.pop() {
            if !retained.insert(object) {
                continue;
            }
            if let Some(record) = records.get(&object)
                && record.kind() == ObjectKind::Directory
                && record.format_version() == DIRECTORY_VERSION
            {
                pending.extend(record.references().iter().map(ObjectReference::target));
            }
        }
        records.retain(|object, record| {
            record.kind() != ObjectKind::Directory
                || record.format_version() != DIRECTORY_VERSION
                || retained.contains(object)
        });
    }
}
