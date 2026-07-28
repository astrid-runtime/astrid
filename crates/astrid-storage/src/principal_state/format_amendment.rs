//! Frozen format-v1 Rosetta object and crash-safe in-place amendments.

use std::path::Path;

use astrid_storage_model::{
    InsertOutcome, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
};

use super::migrations;
use super::native_io::{atomic_write, quarantine_directory};
use super::{BLAKE3_OBJECT_IDENTITY_V1_SCHEME, RuntimeEngine};
use crate::error::{StorageError, StorageResult};

pub(super) const STORE_METADATA_FILE: &str = "store.meta";
pub(super) const STORE_FORMAT_SPEC: &[u8] =
    include_bytes!("../../../../docs/astrid-principal-store-format-v1.txt");
pub(super) const PRE_DERIVATION_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    98, 205, 237, 154, 91, 1, 254, 117, 215, 120, 27, 102, 48, 63, 95, 254, 140, 237, 85, 164, 48,
    37, 160, 56, 158, 239, 174, 165, 160, 197, 143, 226,
]);

pub(super) fn format_spec_record() -> StorageResult<ObjectRecord> {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        STORE_FORMAT_SPEC.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| {
        StorageError::Serialization(format!(
            "construct in-band store format specification: {error}"
        ))
    })
}

pub(super) fn store_metadata(format_spec: ObjectId) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         principal-codec=state-owner-v1\n\
         projection=kv-tree-v3\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

pub(super) fn object_id_hex(id: ObjectId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::with_capacity(64);
    for byte in id.as_bytes() {
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    digest
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DestinationFormat {
    New,
    Current,
    PreDerivationV1(ObjectId),
}

impl DestinationFormat {
    pub(super) const fn is_existing(self) -> bool {
        !matches!(self, Self::New)
    }
}

pub(super) fn prepare_destination(
    path: &Path,
    expected_metadata: &[u8],
) -> StorageResult<DestinationFormat> {
    let mut existing_complete = false;
    if path.exists() {
        if migrations::is_complete(path) {
            existing_complete = true;
        } else {
            quarantine_incomplete(path)?;
        }
    }
    std::fs::create_dir_all(path).map_err(|error| {
        StorageError::Connection(format!(
            "create principal store directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = path.join(STORE_METADATA_FILE);
    if metadata.exists() {
        let actual = std::fs::read(&metadata).map_err(|error| {
            StorageError::Connection(format!(
                "read principal store metadata {}: {error}",
                metadata.display()
            ))
        })?;
        if actual != expected_metadata {
            if existing_complete && actual == store_metadata(PRE_DERIVATION_FORMAT_SPEC_ID) {
                return validate_authoritative_files(path)
                    .map(|()| DestinationFormat::PreDerivationV1(PRE_DERIVATION_FORMAT_SPEC_ID));
            }
            return Err(unsupported_format_error(&metadata));
        }
    } else if existing_complete {
        return Err(StorageError::Connection(format!(
            "completed principal store at {} is missing format metadata",
            path.display()
        )));
    } else {
        atomic_write(&metadata, expected_metadata)?;
    }
    if existing_complete {
        validate_authoritative_files(path)?;
        Ok(DestinationFormat::Current)
    } else {
        Ok(DestinationFormat::New)
    }
}

pub(super) fn prepare_format_specification(
    engine: &RuntimeEngine,
    store_path: &Path,
    destination_format: DestinationFormat,
    current_spec: &ObjectRecord,
    current_spec_id: ObjectId,
    current_metadata: &[u8],
) -> StorageResult<()> {
    match destination_format {
        DestinationFormat::Current => match read_format_specification(engine, current_spec_id)? {
            Some(actual) if actual == *current_spec => Ok(()),
            Some(_) => Err(StorageError::Connection(
                "in-band store format specification does not match store.meta".to_owned(),
            )),
            None => Err(StorageError::Connection(
                "completed principal store is missing its in-band format specification".to_owned(),
            )),
        },
        DestinationFormat::New => {
            if let Some(actual) = read_format_specification(engine, current_spec_id)? {
                if actual != *current_spec {
                    return Err(StorageError::Connection(
                        "new principal store contains a conflicting format specification"
                            .to_owned(),
                    ));
                }
                return Ok(());
            }
            persist_format_specification(engine, current_spec).map(|_| ())
        },
        DestinationFormat::PreDerivationV1(legacy_spec_id) => {
            let legacy = read_format_specification(engine, legacy_spec_id)?.ok_or_else(|| {
                StorageError::Connection(
                    "completed principal store is missing its pre-derivation format specification"
                        .to_owned(),
                )
            })?;
            if legacy.kind() != ObjectKind::Evidence
                || legacy.format_version() != ObjectFormatVersion::V1
                || legacy.class() != ObjectClass::Metadata
                || legacy.logical_bytes() != 0
                || !legacy.references().is_empty()
            {
                return Err(StorageError::Connection(
                    "pre-derivation format specification has an invalid object shape".to_owned(),
                ));
            }
            persist_format_specification(engine, current_spec)?;
            atomic_write(&store_path.join(STORE_METADATA_FILE), current_metadata)
        },
    }
}

pub(super) fn read_format_specification(
    engine: &RuntimeEngine,
    object: ObjectId,
) -> StorageResult<Option<ObjectRecord>> {
    engine.object(object).map_err(|error| {
        StorageError::Connection(format!("read in-band store format specification: {error}"))
    })
}

pub(super) fn persist_format_specification(
    engine: &RuntimeEngine,
    record: &ObjectRecord,
) -> StorageResult<(ObjectId, InsertOutcome)> {
    engine.persist_standalone_object(record).map_err(|error| {
        StorageError::Connection(format!(
            "persist in-band store format specification: {error}"
        ))
    })
}

fn validate_authoritative_files(path: &Path) -> StorageResult<()> {
    for authoritative in ["objects.arena", "roots.journal"] {
        let required = path.join(authoritative);
        if !required.is_file() {
            return Err(StorageError::Connection(format!(
                "completed principal store is missing authoritative file {}",
                required.display()
            )));
        }
    }
    Ok(())
}

fn unsupported_format_error(metadata: &Path) -> StorageError {
    StorageError::Connection(format!(
        "principal store metadata at {} selects an unsupported format",
        metadata.display()
    ))
}

fn quarantine_incomplete(path: &Path) -> StorageResult<()> {
    quarantine_directory(path, "incomplete").map(|_| ())
}
