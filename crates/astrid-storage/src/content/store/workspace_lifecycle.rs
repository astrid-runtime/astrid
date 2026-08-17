use std::collections::BTreeMap;

use astrid_core::PrincipalUid;

use crate::content::catalog::{delete, insert, list, root_from_record};
use crate::content_dag::BuiltContent;

use super::{
    BranchState, CatalogRoot, CatalogValue, ContentHeader, ContentName, MAX_WORKSPACE_BRANCHES,
    ModelError, ObjectId, ObjectRecord, ObjectReference, PrincipalContentError,
    PrincipalProjectionEngine, PrincipalProjectionError, ReferenceKind, WorkspaceBranchDescriptor,
    WorkspaceBranchError, WorkspaceBranchStore, WorkspaceUid, decode_branch_record,
    decode_promotion_receipt, is_workspace_branch_label, is_workspace_receipt_label,
    make_branch_record, make_branch_record_for_uid, parse_workspace_receipt_uid,
    parse_workspace_uid, qualify_name, selected_catalog, selected_name, validate_catalog,
    workspace_ref_label,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn create_branch(
        &self,
        owner: &P,
        id: WorkspaceUid,
        binding_uid: Option<PrincipalUid>,
        target_prefix: Option<&ContentName>,
    ) -> Result<WorkspaceBranchDescriptor<P>, WorkspaceBranchError> {
        loop {
            let header = self.content.header(owner)?;
            let branches = self.decode_branches(owner, &header)?;
            if self.completion_receipt(owner, &header, id)?.is_some() {
                return Err(WorkspaceBranchError::AlreadyExists(id));
            }
            if let Some(existing) = branches.iter().find(|branch| branch.id == id) {
                let requested = selected_catalog(
                    header.catalog,
                    target_prefix,
                    &mut |object| self.content.load_required_for(owner, object),
                    &|record| self.content.engine.identify_object(record),
                )?;
                if requested.0 == existing.base
                    && existing.working == existing.base
                    && existing.target_prefix.as_ref() == target_prefix
                {
                    let root = existing.base.map(|root| root.object);
                    return Ok(WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        existing.binding_uid,
                        existing.target_prefix.clone(),
                        root,
                        root,
                    ));
                }
                return Err(WorkspaceBranchError::AlreadyExists(id));
            }
            if let Some(binding_uid) = binding_uid
                && branches.iter().any(|branch| {
                    branch.binding_uid == Some(binding_uid)
                        && branch.target_prefix.as_ref() == target_prefix
                })
            {
                return Err(WorkspaceBranchError::BindingAlreadyExists {
                    binding_uid,
                    target_prefix: target_prefix.cloned().ok_or(
                        WorkspaceBranchError::InvalidTargetPrefix {
                            detail: "bound workspace prefix cannot be omitted",
                        },
                    )?,
                });
            }
            if branches.len() >= MAX_WORKSPACE_BRANCHES {
                return Err(WorkspaceBranchError::BranchLimitExceeded);
            }
            let (base, mut base_records) = selected_catalog(
                header.catalog,
                target_prefix,
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            let added_quota = base.map_or(0, |root| root.summary.quota_bytes);
            self.enforce_quota_change(owner, &header, 0, added_quota)?;
            let record = binding_uid.map_or_else(
                || make_branch_record(id, target_prefix, base, base),
                |binding_uid| {
                    make_branch_record_for_uid(binding_uid, id, target_prefix, base, base)
                },
            )?;
            let record_id = self.content.engine.identify_object(&record);
            let mut next = header.as_ref().clone();
            next.preserved_state
                .push(ObjectReference::owns(workspace_ref_label(id), record_id));
            let mut records = BTreeMap::new();
            records.append(&mut base_records);
            records.insert(record_id, record);
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => {
                    let root = base.map(|root| root.object);
                    return Ok(WorkspaceBranchDescriptor::new(
                        owner.clone(),
                        id,
                        binding_uid,
                        target_prefix.cloned(),
                        root,
                        root,
                    ));
                },
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(super) fn branch(
        &self,
        owner: &P,
        header: &ContentHeader,
        id: WorkspaceUid,
    ) -> Result<BranchState, WorkspaceBranchError> {
        self.decode_branches(owner, header)?
            .into_iter()
            .find(|branch| branch.id == id)
            .ok_or(WorkspaceBranchError::NotFound(id))
    }

    pub(super) fn merge_selected_catalog(
        &self,
        owner: &P,
        main: Option<CatalogRoot>,
        target_prefix: Option<&ContentName>,
        working: Option<CatalogRoot>,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        let Some(prefix) = target_prefix else {
            return Ok(working);
        };
        let mut root = main;
        let main_entries = list(main, &mut |object| {
            records
                .get(&object)
                .cloned()
                .map_or_else(|| self.content.load_required_for(owner, object), Ok)
        })?;
        let marker = ContentName::new(format!("{}/", prefix.as_str()))
            .ok()
            .and_then(|marker| {
                main_entries
                    .iter()
                    .find(|entry| entry.name() == &marker)
                    .map(|entry| (marker, entry.file(), entry.logical_bytes()))
            });
        let names = main_entries
            .into_iter()
            .filter(|entry| selected_name(entry.name(), Some(prefix)))
            .map(|entry| entry.name().clone())
            .collect::<Vec<_>>();
        for name in names {
            let mutation = delete(
                root,
                &name,
                &mut |object| {
                    records
                        .get(&object)
                        .cloned()
                        .map_or_else(|| self.content.load_required_for(owner, object), Ok)
                },
                &|record| self.content.engine.identify_object(record),
            )?;
            root = mutation.root;
            records.extend(mutation.records);
        }
        for entry in list(working, &mut |object| {
            self.content.load_required_for(owner, object)
        })? {
            let full_name = qualify_name(entry.name(), Some(prefix))?;
            let mutation = insert(
                root,
                &full_name,
                CatalogValue {
                    file: entry.file(),
                    logical_bytes: entry.logical_bytes(),
                },
                &mut |object| {
                    records
                        .get(&object)
                        .cloned()
                        .map_or_else(|| self.content.load_required_for(owner, object), Ok)
                },
                &|record| self.content.engine.identify_object(record),
            )?;
            root = mutation.root;
            records.extend(mutation.records);
        }
        if let Some((marker, file, logical_bytes)) = marker {
            let mutation = insert(
                root,
                &marker,
                CatalogValue {
                    file,
                    logical_bytes,
                },
                &mut |object| {
                    records
                        .get(&object)
                        .cloned()
                        .map_or_else(|| self.content.load_required_for(owner, object), Ok)
                },
                &|record| self.content.engine.identify_object(record),
            )?;
            root = mutation.root;
            records.extend(mutation.records);
        }
        Ok(root)
    }

    pub(super) fn enforce_catalog_replacement(
        &self,
        owner: &P,
        header: &ContentHeader,
        old_branch_quota: u64,
        catalog: Option<CatalogRoot>,
    ) -> Result<(), WorkspaceBranchError> {
        let Some(quota) = &self.content.quota else {
            return Ok(());
        };
        let Some(limit) = quota
            .max_logical_bytes(owner)
            .map_err(PrincipalContentError::QuotaPolicy)?
        else {
            return Ok(());
        };
        let new_other = header
            .other_quota_bytes
            .checked_sub(old_branch_quota)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let new_used = new_other
            .checked_add(catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let old_used = header
            .other_quota_bytes
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        if new_used > limit && new_used > old_used {
            return Err(WorkspaceBranchError::QuotaExceeded {
                used: new_used,
                limit,
            });
        }
        Ok(())
    }

    pub(super) fn completion_receipt(
        &self,
        owner: &P,
        header: &ContentHeader,
        id: WorkspaceUid,
    ) -> Result<Option<BranchState>, WorkspaceBranchError> {
        for reference in &header.preserved_state {
            if !is_workspace_receipt_label(reference.label().as_bytes()) {
                continue;
            }
            let Some(receipt_id) = parse_workspace_receipt_uid(reference.label().as_bytes()) else {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: reference.target(),
                    detail: "workspace completion label is malformed",
                });
            };
            if receipt_id != id {
                continue;
            }
            if reference.kind() != ReferenceKind::Owns {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: reference.target(),
                    detail: "workspace completion reference is not owning",
                });
            }
            let record = self.content.load_required_for(owner, reference.target())?;
            return decode_promotion_receipt(reference.target(), &record, id).map(Some);
        }
        Ok(None)
    }

    pub(super) fn decode_branches(
        &self,
        owner: &P,
        header: &ContentHeader,
    ) -> Result<Vec<BranchState>, WorkspaceBranchError> {
        let mut branches = Vec::new();
        for reference in &header.preserved_state {
            if !is_workspace_branch_label(reference.label().as_bytes()) {
                continue;
            }
            let Some(id) = parse_workspace_uid(reference.label().as_bytes()) else {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: reference.target(),
                    detail: "workspace branch label is malformed",
                });
            };
            if reference.kind() != ReferenceKind::Owns {
                return Err(WorkspaceBranchError::InvalidGraph {
                    object: reference.target(),
                    detail: "workspace branch reference is not owning",
                });
            }
            let record = self.content.load_required_for(owner, reference.target())?;
            let branch = decode_branch_record(reference.target(), &record, id)?;
            let base = self.validate_catalog(owner, self.hydrate_root(owner, branch.base)?)?;
            let working =
                self.validate_catalog(owner, self.hydrate_root(owner, branch.working)?)?;
            branches.push(BranchState {
                id,
                binding_uid: branch.binding_uid,
                target_prefix: branch.target_prefix,
                base,
                working,
            });
        }
        Ok(branches)
    }

    pub(super) fn validate_catalog(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        let Some(root) = root else {
            return Ok(None);
        };
        let validation = validate_catalog(Some(root), &mut |object| {
            self.content.load_required_for(owner, object)
        })?;
        if validation.root != Some(root.object) || validation.summary != root.summary {
            return Err(WorkspaceBranchError::InvalidGraph {
                object: root.object,
                detail: "workspace catalog validation totals disagree",
            });
        }
        Ok(Some(CatalogRoot {
            object: root.object,
            summary: validation.summary,
        }))
    }

    pub(super) fn hydrate_root(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
    ) -> Result<Option<CatalogRoot>, WorkspaceBranchError> {
        root.map(|root| {
            self.content
                .load_required_for(owner, root.object)
                .map_err(WorkspaceBranchError::from)
                .and_then(|record| root_from_record(root.object, &record).map_err(Into::into))
        })
        .transpose()
    }

    pub(super) fn enforce_quota_change(
        &self,
        owner: &P,
        header: &ContentHeader,
        old_branch_quota: u64,
        new_branch_quota: u64,
    ) -> Result<(), WorkspaceBranchError> {
        let Some(quota) = &self.content.quota else {
            return Ok(());
        };
        let Some(limit) = quota
            .max_logical_bytes(owner)
            .map_err(PrincipalContentError::QuotaPolicy)?
        else {
            return Ok(());
        };
        let old_used = header
            .other_quota_bytes
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let new_other = header
            .other_quota_bytes
            .checked_sub(old_branch_quota)
            .ok_or(PrincipalContentError::AccountingOverflow)?
            .checked_add(new_branch_quota)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let new_used = new_other
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        if new_used > limit && new_used > old_used {
            return Err(WorkspaceBranchError::QuotaExceeded {
                used: new_used,
                limit,
            });
        }
        Ok(())
    }

    pub(super) fn mutate_catalog<F>(
        &self,
        owner: &P,
        id: WorkspaceUid,
        built: Option<&BuiltContent>,
        mut mutate: F,
    ) -> Result<(), WorkspaceBranchError>
    where
        F: FnMut(
            Option<CatalogRoot>,
            &mut BTreeMap<ObjectId, ObjectRecord>,
        ) -> Result<Option<CatalogRoot>, PrincipalContentError>,
    {
        loop {
            let header = self.content.header(owner)?;
            let branch = self.branch(owner, &header, id)?;
            let old_quota = branch.working.map_or(0, |root| root.summary.quota_bytes);
            let mut records = BTreeMap::new();
            if let Some(content) = &built {
                records.extend(content.records().iter().cloned());
            }
            let working = mutate(branch.working, &mut records)?;
            if working == branch.working {
                return Ok(());
            }
            let new_quota = working.map_or(0, |root| root.summary.quota_bytes);
            self.enforce_quota_change(owner, &header, old_quota, new_quota)?;
            let record = branch.binding_uid.map_or_else(
                || make_branch_record(id, branch.target_prefix.as_ref(), branch.base, working),
                |binding_uid| {
                    make_branch_record_for_uid(
                        binding_uid,
                        id,
                        branch.target_prefix.as_ref(),
                        branch.base,
                        working,
                    )
                },
            )?;
            let record_id = self.content.engine.identify_object(&record);
            records.insert(record_id, record);
            let mut next = header.as_ref().clone();
            next.preserved_state
                .retain(|reference| parse_workspace_uid(reference.label().as_bytes()) != Some(id));
            next.preserved_state
                .push(ObjectReference::owns(workspace_ref_label(id), record_id));
            let transaction =
                self.content
                    .encode_transaction(owner.clone(), next, None, records)?;
            match self.content.engine.commit_root(transaction) {
                Ok(_) => return Ok(()),
                Err(PrincipalProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(error.into()),
            }
        }
    }
}
