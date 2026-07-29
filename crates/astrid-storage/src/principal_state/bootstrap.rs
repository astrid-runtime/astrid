//! Registered standalone objects required to reopen a runtime store.

use std::sync::Arc;

use astrid_storage_engine::{CompactionRetainedRoot, CompactionRetention, CompactionRootKind};
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, RetentionPolicyId,
};

use super::format_amendment::format_spec_record;
use super::{RuntimeEngine, RuntimePrincipalStore, StorageError, StorageResult};

/// One standalone object that runtime composition must keep outside principal roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeBootstrapObject {
    /// Byte-exact specification required to decode the authoritative files.
    RunatalFormatSpecification,
    /// Byte-exact specification required to decode content-catalog trees.
    ContentCatalogFormatSpecification,
}

const CONTENT_CATALOG_FORMAT_SPEC: &[u8] =
    include_bytes!("../../../../docs/astrid-content-catalog-format-v2.txt");
const RUNTIME_BOOTSTRAP_OBJECTS: &[RuntimeBootstrapObject] = &[
    RuntimeBootstrapObject::RunatalFormatSpecification,
    RuntimeBootstrapObject::ContentCatalogFormatSpecification,
];

impl RuntimeBootstrapObject {
    /// Return every standalone object protected by runtime composition.
    pub(super) const fn registered() -> &'static [Self] {
        RUNTIME_BOOTSTRAP_OBJECTS
    }

    /// Construct the exact record persisted for this bootstrap role.
    pub(super) fn record(self) -> StorageResult<ObjectRecord> {
        match self {
            Self::RunatalFormatSpecification => format_spec_record(),
            Self::ContentCatalogFormatSpecification => ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                CONTENT_CATALOG_FORMAT_SPEC.to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .map_err(|error| {
                StorageError::Serialization(format!(
                    "construct in-band content catalog format specification: {error}"
                ))
            }),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::RunatalFormatSpecification => "RÚNATAL format specification",
            Self::ContentCatalogFormatSpecification => "content catalog format specification",
        }
    }
}

pub(super) fn format_specification() -> StorageResult<ObjectRecord> {
    RuntimeBootstrapObject::RunatalFormatSpecification.record()
}

pub(super) fn content_catalog_format_specification() -> StorageResult<ObjectRecord> {
    RuntimeBootstrapObject::ContentCatalogFormatSpecification.record()
}

fn compaction_retention(
    engine: &RuntimeEngine,
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    mut additional_roots: Vec<CompactionRetainedRoot>,
) -> StorageResult<CompactionRetention> {
    for bootstrap in RuntimeBootstrapObject::registered() {
        let expected = bootstrap.record()?;
        let object = engine.identify(&expected);
        let actual = engine
            .object(object)
            .map_err(|error| {
                StorageError::Connection(format!(
                    "verify protected {} before compaction: {error}",
                    bootstrap.name()
                ))
            })?
            .ok_or_else(|| {
                StorageError::Connection(format!(
                    "protected {} is missing before compaction",
                    bootstrap.name()
                ))
            })?;
        if actual != expected {
            return Err(StorageError::Connection(format!(
                "protected {} does not match the registered object",
                bootstrap.name()
            )));
        }
        additional_roots.push(CompactionRetainedRoot::new(
            CompactionRootKind::System,
            object,
        ));
    }
    Ok(CompactionRetention::new(
        operation_contract,
        policy,
        additional_roots,
    ))
}

impl RuntimePrincipalStore {
    /// Construct production compaction retention with every bootstrap root.
    ///
    /// Runtime composition, including future schedulers, must use this method
    /// instead of constructing the policy-neutral engine type directly.
    /// Registered standalone objects are identity-checked before the
    /// retention value is returned, so a destructive plan cannot be verified
    /// after one has already disappeared.
    ///
    /// # Errors
    ///
    /// Returns a storage error if a registered bootstrap record cannot be
    /// constructed, read, identity-verified, or matched byte-for-byte.
    pub async fn prepare_compaction_retention(
        &self,
        operation_contract: ObjectId,
        policy: RetentionPolicyId,
        additional_roots: Vec<CompactionRetainedRoot>,
    ) -> StorageResult<CompactionRetention> {
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || {
            compaction_retention(&engine, operation_contract, policy, additional_roots)
        })
        .await
        .map_err(|error| {
            StorageError::Connection(format!(
                "production compaction-retention worker failed: {error}"
            ))
        })?
    }
}
