use super::components::{self, Charge};
use super::workspace::workspace_branch_quota;
use super::{
    Arc, BTreeMap, BuiltContent, CONTENT_COMPONENT_LABEL, CatalogRoot, CatalogSummary,
    CatalogValue, ContentBatchExpectation, ContentError, ContentHeader, ContentName,
    LEGACY_PRINCIPAL_GRAPH_VERSION, ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, PARENT_LABEL, PRINCIPAL_GRAPH_VERSION, PrincipalContentError,
    PrincipalContentStore, PrincipalKvAdapter, PrincipalProjectionEngine, PrincipalProjectionError,
    ReferenceLabel, RootState, RootTransaction, STATE_LABEL, invalid, lookup, root_from_record,
    validate_catalog, validated_projection_quota,
};
use crate::content::catalog::prefix_exists as catalog_prefix_exists;

impl<P, E> PrincipalContentStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn header_at_epoch(
        &self,
        principal: &P,
        epoch: crate::kv::MemoEpoch,
    ) -> Result<Arc<ContentHeader>, PrincipalContentError> {
        let root = self.engine.current_root(principal)?;
        super::header_cache::read(
            principal,
            root,
            |owner, commit| {
                let header = self
                    .engine
                    .load_projection_cache(owner, commit, super::DECODED_HEADER_CACHE_KEY)?
                    .downcast::<ContentHeader>()?;
                Some((header.root, header))
            },
            |principal, root| {
                let header = self.decode_header(principal, root, epoch)?;
                let Some(root) = root else {
                    return Ok(Arc::new(header));
                };
                let header = Arc::new(header);
                let _ = self.engine.retain_projection_cache(
                    principal,
                    root.commit,
                    super::DECODED_HEADER_CACHE_KEY,
                    super::ProjectionCacheEntry::from_shared(Arc::clone(&header)),
                );
                Ok(header)
            },
        )
    }

    pub(super) fn finish_catalog_commit(
        &self,
        principal: &P,
        mut header: ContentHeader,
        root: RootState,
        epoch: crate::kv::MemoEpoch,
    ) {
        self.validated_kv.publish_catalog_if_current(
            &self.validated_catalogs,
            principal,
            epoch,
            crate::content::catalog::CatalogValidation {
                root: header.catalog.map(|catalog| catalog.object),
                summary: header
                    .catalog
                    .map_or(CatalogSummary::default(), |catalog| catalog.summary),
            },
            || matches!(self.engine.current_root(principal), Ok(Some(current)) if current == root),
        );
        header.root = Some(root);
        header.previous_catalog_quota_bytes = header
            .catalog
            .map_or(0, |catalog| catalog.summary.quota_bytes);
        // A header is an accelerator, governed by the same budget as its
        // authenticated commit. Do not retain an uncharged per-UID duplicate.
        let _ = self.engine.load_shared_object_for(principal, root.commit);
        let _ = self.engine.retain_projection_cache(
            principal,
            root.commit,
            super::DECODED_HEADER_CACHE_KEY,
            crate::engine::ProjectionCacheEntry::new(header),
        );
    }

    pub(super) fn decode_header(
        &self,
        principal: &P,
        root: Option<RootState>,
        epoch: crate::kv::MemoEpoch,
    ) -> Result<ContentHeader, PrincipalContentError> {
        #[cfg(test)]
        self.decode_header_invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(root) = root else {
            return Ok(ContentHeader::empty());
        };
        let super::header_graph::Graph {
            commit,
            state_id,
            state,
        } = self.read_header_graph(principal, root)?;

        let components::Components {
            catalog,
            other_bytes: other_quota_bytes,
            preserved: preserved_state,
        } = components::fold(
            principal,
            root,
            state.references(),
            |owner, target, root| self.validated_content_root(owner, target, root, epoch),
            |owner, kind, reference, root| match kind {
                Charge::Kv => self.kv_quota(owner, reference.target(), root, epoch),
                Charge::Workspace => workspace_branch_quota(self, owner, reference),
            },
        )
        .map_err(|error| match error {
            components::Error::NotOwning => invalid(state_id, "principal component is not owning"),
            components::Error::Overflow => PrincipalContentError::AccountingOverflow,
            components::Error::Storage(e) => e,
        })?;
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

    fn validated_content_root(
        &self,
        principal: &P,
        target: ObjectId,
        captured_root: RootState,
        epoch: crate::kv::MemoEpoch,
    ) -> Result<CatalogRoot, PrincipalContentError> {
        let record = self
            .engine
            .load_shared_object_for(principal, target)?
            .ok_or(ContentError::MissingObject(target))?;
        let root = root_from_record(target, &record)?;
        let cached = self
            .validated_catalogs
            .lock()
            .get(principal)
            .copied()
            .filter(|validation| validation.root == Some(root.object));
        let validation = if let Some(validation) = cached {
            validation
        } else {
            #[cfg(test)]
            self.catalog_validation_invocations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let validation = validate_catalog(Some(root), &mut |object| {
                self.load_required_for(principal, object)
            })?;
            self.validated_kv.publish_catalog_if_current(
                            &self.validated_catalogs, principal, epoch, validation,
                            || matches!(self.engine.current_root(principal), Ok(Some(current)) if current == captured_root),
                        );
            validation
        };
        if validation.summary != root.summary {
            return Err(invalid(
                root.object,
                "content catalog validation totals disagree",
            ));
        }
        Ok(root)
    }

    pub(super) fn kv_quota(
        &self,
        principal: &P,
        object: ObjectId,
        root: RootState,
        epoch: crate::kv::MemoEpoch,
    ) -> Result<u64, PrincipalContentError> {
        validated_projection_quota(
            &PrincipalKvAdapter::new(self.engine.as_ref()),
            principal,
            object,
            Some(root),
            self.validated_kv.as_ref(),
            epoch,
        )
        .map_err(|_| invalid(object, "invalid KV component accounting"))
    }

    pub(super) fn read_header_graph(
        &self,
        owner: &P,
        root: RootState,
    ) -> Result<super::header_graph::Graph, PrincipalContentError> {
        super::header_graph::read(owner, root, PRINCIPAL_GRAPH_VERSION, |owner, id| {
            self.engine
                .load_shared_object_for(owner, id)?
                .ok_or_else(|| ContentError::MissingObject(id).into())
        })
        .map_err(|error| match error {
            super::header_graph::Error::Read(e) => e,
            super::header_graph::Error::Invalid(id, why) => invalid(id, why),
        })
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

    pub(super) fn check_batch_preconditions(
        &self,
        principal: &P,
        header: &ContentHeader,
        preconditions: crate::content::ContentBatchPreconditions<'_>,
    ) -> Result<(), PrincipalContentError> {
        if preconditions
            .root
            .is_some_and(|expected| header.root != Some(expected))
        {
            return Err(PrincipalContentError::BatchPreconditionFailed);
        }
        let Some(ContentBatchExpectation::Exact(entries)) = preconditions.names else {
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

        let (owner, expected, commit, records) = super::commit_candidate::Candidate::new(
            principal,
            header.root,
            header.preserved_commit,
            state,
        )
        .seal(|mut references| {
            references.sort();
            let commit = ObjectRecord::new(
                ObjectKind::Commit,
                PRINCIPAL_GRAPH_VERSION,
                Vec::new(),
                references,
                0,
                ObjectClass::Metadata,
            )
            .map_err(PrincipalProjectionError::Model)?;
            let commit = self.insert(&mut records, commit)?;
            Ok::<_, PrincipalContentError>((commit, records.into_iter().collect()))
        })?;
        Ok(RootTransaction::new(owner, expected, commit, records))
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

#[cfg(all(test, not(target_family = "wasm")))]
mod retirement_tests;
