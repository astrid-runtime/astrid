use super::workspace::{is_workspace_branch_label, workspace_branch_quota};
use super::{
    BTreeMap, BuiltContent, CONTENT_COMPONENT_LABEL, CatalogRoot, CatalogSummary, CatalogValue,
    ContentBatchExpectation, ContentError, ContentHeader, ContentName, KV_COMPONENT_LABEL,
    LEGACY_PRINCIPAL_GRAPH_VERSION, ModelError, ObjectClass, ObjectFormatVersion, ObjectId,
    ObjectKind, ObjectRecord, ObjectReference, PARENT_LABEL, PRINCIPAL_GRAPH_VERSION,
    PrincipalContentError, PrincipalContentStore, PrincipalKvAdapter, PrincipalProjectionEngine,
    PrincipalProjectionError, ReferenceKind, ReferenceLabel, RootState, RootTransaction,
    STATE_LABEL, invalid, lookup, owned_target, require_structural, root_from_record,
    validate_catalog, validated_projection_quota,
};
use crate::content::catalog::prefix_exists as catalog_prefix_exists;

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn finish_catalog_commit(
        &self,
        principal: &P,
        mut header: ContentHeader,
        root: RootState,
    ) {
        self.validated_catalogs.lock().insert(
            principal.clone(),
            crate::content::catalog::CatalogValidation {
                root: header.catalog.map(|catalog| catalog.object),
                summary: header
                    .catalog
                    .map_or(CatalogSummary::default(), |catalog| catalog.summary),
            },
        );
        header.root = Some(root);
        header.previous_catalog_quota_bytes = header
            .catalog
            .map_or(0, |catalog| catalog.summary.quota_bytes);
        self.decoded_headers
            .lock()
            .insert(principal.clone(), std::sync::Arc::new(header));
    }

    pub(super) fn decode_header(
        &self,
        principal: &P,
        root: Option<RootState>,
    ) -> Result<ContentHeader, PrincipalContentError> {
        #[cfg(test)]
        self.decode_header_invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(root) = root else {
            return Ok(ContentHeader::empty());
        };
        let commit = self.load_typed(
            principal,
            root.commit,
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(root.commit, &commit)?;
        let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
        let state = self.load_typed(
            principal,
            state_id,
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
        )?;
        require_structural(state_id, &state)?;

        let mut catalog = None;
        let mut other_quota_bytes = 0_u64;
        let mut preserved_state = Vec::new();
        for reference in state.references() {
            if reference.kind() != ReferenceKind::Owns {
                return Err(invalid(state_id, "principal component is not owning"));
            }
            match reference.label().as_bytes() {
                CONTENT_COMPONENT_LABEL => {
                    let record = self
                        .engine
                        .load_object_for(principal, reference.target())?
                        .ok_or_else(|| ContentError::MissingObject(reference.target()))?;
                    let root = root_from_record(reference.target(), &record)?;
                    let cached = self
                        .validated_catalogs
                        .lock()
                        .get(principal)
                        .copied()
                        .filter(|validation| validation.root == Some(root.object));
                    let validation = if let Some(validation) = cached {
                        validation
                    } else {
                        let validation = validate_catalog(Some(root), &mut |object| {
                            self.load_required_for(principal, object)
                        })?;
                        self.validated_catalogs
                            .lock()
                            .insert(principal.clone(), validation);
                        validation
                    };
                    if validation.summary != root.summary {
                        return Err(invalid(
                            root.object,
                            "content catalog validation totals disagree",
                        ));
                    }
                    catalog = Some(root);
                },
                KV_COMPONENT_LABEL => {
                    other_quota_bytes = other_quota_bytes
                        .checked_add(self.kv_quota(principal, reference.target())?)
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    preserved_state.push(reference.clone());
                },
                label if is_workspace_branch_label(label) => {
                    other_quota_bytes = other_quota_bytes
                        .checked_add(workspace_branch_quota(self, principal, reference)?)
                        .ok_or(PrincipalContentError::AccountingOverflow)?;
                    preserved_state.push(reference.clone());
                },
                _ => {
                    preserved_state.push(reference.clone());
                },
            }
        }
        let preserved_commit = commit
            .references()
            .iter()
            .filter(|reference| {
                reference.label().as_bytes() != STATE_LABEL
                    && reference.label().as_bytes() != PARENT_LABEL
            })
            .cloned()
            .collect();
        Ok(ContentHeader {
            root: Some(root),
            previous_catalog_quota_bytes: catalog.map_or(0, |root| root.summary.quota_bytes),
            catalog,
            other_quota_bytes,
            preserved_state,
            preserved_commit,
        })
    }

    pub(super) fn kv_quota(
        &self,
        principal: &P,
        object: ObjectId,
    ) -> Result<u64, PrincipalContentError> {
        validated_projection_quota(
            &PrincipalKvAdapter::new(self.engine.as_ref()),
            principal,
            object,
            self.validated_kv.as_ref(),
        )
        .map_err(|_| invalid(object, "invalid KV component accounting"))
    }

    pub(super) fn load_typed(
        &self,
        principal: &P,
        object: ObjectId,
        kind: ObjectKind,
        version: ObjectFormatVersion,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        let record = self
            .engine
            .load_object_for(principal, object)?
            .ok_or(ContentError::MissingObject(object))?;
        if record.kind() != kind || record.format_version() != version {
            return Err(invalid(
                object,
                "principal object has wrong kind or version",
            ));
        }
        Ok(record)
    }

    pub(super) fn load_migration_graph_object(
        &self,
        object: ObjectId,
        kind: ObjectKind,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        let record = self
            .engine
            .load_object(object)?
            .ok_or(ContentError::MissingObject(object))?;
        if record.kind() != kind
            || (record.format_version() != PRINCIPAL_GRAPH_VERSION
                && record.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION)
        {
            return Err(invalid(
                object,
                "principal migration object has wrong kind or version",
            ));
        }
        Ok(record)
    }

    pub(super) fn enforce_quota(
        &self,
        principal: &P,
        header: &ContentHeader,
    ) -> Result<(), PrincipalContentError> {
        let Some(quota) = &self.quota else {
            return Ok(());
        };
        let Some(limit) = quota
            .max_logical_bytes(principal)
            .map_err(PrincipalContentError::QuotaPolicy)?
        else {
            return Ok(());
        };
        let used = header
            .other_quota_bytes
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        let previous = header
            .other_quota_bytes
            .checked_add(header.previous_catalog_quota_bytes)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        if used > limit && used > previous {
            return Err(PrincipalContentError::QuotaExceeded { used, limit });
        }
        Ok(())
    }

    pub(super) fn check_batch_expectation(
        &self,
        principal: &P,
        header: &ContentHeader,
        expectation: Option<&ContentBatchExpectation>,
    ) -> Result<(), PrincipalContentError> {
        let Some(ContentBatchExpectation::Exact(entries)) = expectation else {
            return Ok(());
        };
        for (name, expected) in entries {
            let actual = self.catalog_lookup(principal, header.catalog, name)?;
            let actual = actual.map(|value| value.file);
            if &actual != expected {
                return Err(PrincipalContentError::BatchPreconditionFailed);
            }
        }
        Ok(())
    }

    pub(crate) fn quota_staging_bound(
        &self,
        principal: &P,
    ) -> Result<Option<(u64, u64)>, PrincipalContentError> {
        let Some(quota) = &self.quota else {
            return Ok(None);
        };
        let Some(limit) = quota
            .max_logical_bytes(principal)
            .map_err(PrincipalContentError::QuotaPolicy)?
        else {
            return Ok(None);
        };
        if limit == u64::MAX {
            return Ok(None);
        }
        let header = self.header(principal)?;
        let current = header
            .other_quota_bytes
            .checked_add(header.catalog.map_or(0, |root| root.summary.quota_bytes))
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        Ok(Some((limit.max(current), limit)))
    }

    pub(super) fn encode_transaction(
        &self,
        principal: P,
        header: ContentHeader,
        built: Option<&BuiltContent>,
        catalog_records: BTreeMap<ObjectId, ObjectRecord>,
    ) -> Result<RootTransaction<P>, PrincipalContentError> {
        self.engine.admit_principal(&principal)?;
        let mut records: BTreeMap<ObjectId, ObjectRecord> = built
            .map(|built| built.records().iter().cloned().collect())
            .unwrap_or_default();
        for (_, record) in catalog_records {
            self.insert(&mut records, record)?;
        }
        let mut state_references = header.preserved_state;
        if let Some(catalog) = header.catalog {
            state_references.push(ObjectReference::owns(
                ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
                catalog.object,
            ));
        }
        state_references.sort();
        let state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            state_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(PrincipalProjectionError::Model)?;
        let state = self.insert(&mut records, state)?;

        let mut commit_references = header.preserved_commit;
        if let Some(previous) = header.root {
            commit_references.push(ObjectReference::new(
                ReferenceLabel::new(PARENT_LABEL.to_vec()),
                previous.commit,
                ReferenceKind::Lineage,
            ));
        }
        commit_references.push(ObjectReference::owns(
            ReferenceLabel::new(STATE_LABEL.to_vec()),
            state,
        ));
        commit_references.sort();
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            PRINCIPAL_GRAPH_VERSION,
            Vec::new(),
            commit_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(PrincipalProjectionError::Model)?;
        let commit = self.insert(&mut records, commit)?;
        Ok(RootTransaction::new(
            principal,
            header.root,
            commit,
            records.into_iter().collect(),
        ))
    }

    /// Return whether any catalog name begins with `prefix`.
    ///
    /// This is the existence form of [`Self::list_prefix`]: it uses the same
    /// Patricia skip, but stops at the first matching leaf so a parent-directory
    /// check does not materialize every child.
    ///
    /// # Errors
    ///
    /// Returns a principal graph or projection error when the owner catalog
    /// cannot be decoded.
    pub fn prefix_exists(
        &self,
        principal: &P,
        prefix: &str,
    ) -> Result<bool, PrincipalContentError> {
        #[cfg(test)]
        self.prefix_exists_invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if prefix.is_empty() {
            let header = self.header(principal)?;
            return Ok(header
                .catalog
                .is_some_and(|catalog| catalog.summary.entries > 0));
        }
        let prefix =
            ContentName::new(prefix.to_owned()).map_err(PrincipalContentError::InvalidName)?;
        let header = self.header(principal)?;
        catalog_prefix_exists(header.catalog, &prefix, &mut |object| {
            self.load_required_for(principal, object)
        })
    }

    #[cfg(test)]
    pub(crate) fn list_invocations(&self) -> u64 {
        self.list_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn list_prefix_invocations(&self) -> u64 {
        self.list_prefix_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn prefix_exists_invocations(&self) -> u64 {
        self.prefix_exists_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn decode_header_invocations(&self) -> u64 {
        self.decode_header_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn catalog_lookup(
        &self,
        principal: &P,
        root: Option<CatalogRoot>,
        name: &ContentName,
    ) -> Result<Option<CatalogValue>, PrincipalContentError> {
        lookup(root, name, &mut |object| {
            self.load_required_for(principal, object)
        })
    }

    pub(super) fn load_required(
        &self,
        object: ObjectId,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        self.engine
            .load_object(object)?
            .ok_or_else(|| ContentError::MissingObject(object).into())
    }

    pub(super) fn load_required_for(
        &self,
        principal: &P,
        object: ObjectId,
    ) -> Result<ObjectRecord, PrincipalContentError> {
        self.engine
            .load_object_for(principal, object)?
            .ok_or_else(|| ContentError::MissingObject(object).into())
    }

    pub(super) fn insert(
        &self,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        record: ObjectRecord,
    ) -> Result<ObjectId, PrincipalContentError> {
        let id = self.engine.identify_object(&record);
        match records.get(&id) {
            Some(existing) if existing == &record => {},
            Some(_) => {
                return Err(
                    PrincipalProjectionError::Model(ModelError::ObjectCollision(id)).into(),
                );
            },
            None => {
                records.insert(id, record);
            },
        }
        Ok(id)
    }
}
