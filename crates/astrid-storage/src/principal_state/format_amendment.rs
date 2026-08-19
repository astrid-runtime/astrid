//! Frozen format-v1 RÚNATAL object and crash-safe in-place amendments.

use std::path::Path;

#[cfg(test)]
use crate::storage_model::InsertOutcome;
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};

use super::migrations;
use super::native_io::{ensure_private_directory, quarantine_directory};
use super::{BLAKE3_OBJECT_IDENTITY_V1_SCHEME, RuntimeEngine};
use crate::error::{StorageError, StorageResult};

pub(super) const STORE_METADATA_FILE: &str = "store.meta";
pub(super) const STORE_FORMAT_SPEC: &[u8] = include_bytes!("../../formats/principal-store-v1.txt");
pub(super) const PRE_DERIVATION_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    98, 205, 237, 154, 91, 1, 254, 117, 215, 120, 27, 102, 48, 63, 95, 254, 140, 237, 85, 164, 48,
    37, 160, 56, 158, 239, 174, 165, 160, 197, 143, 226,
]);
pub(super) const PRE_COMPACTION_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    53, 180, 70, 251, 209, 156, 164, 173, 11, 19, 67, 180, 12, 26, 50, 178, 238, 216, 238, 247,
    149, 3, 66, 97, 164, 9, 42, 10, 42, 232, 6, 254,
]);
pub(super) const PRE_GC_OUTBOX_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    216, 242, 203, 37, 7, 54, 121, 159, 216, 178, 111, 48, 126, 32, 196, 217, 73, 214, 206, 161,
    131, 102, 20, 165, 84, 114, 16, 232, 43, 191, 206, 193,
]);
pub(super) const PRE_RUNATAL_NAMING_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    134, 57, 14, 85, 115, 205, 98, 72, 236, 238, 181, 144, 75, 249, 222, 203, 137, 41, 254, 103,
    170, 230, 56, 213, 49, 171, 17, 148, 24, 0, 14, 25,
]);
pub(super) const PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    50, 55, 156, 42, 158, 29, 15, 225, 102, 172, 55, 243, 13, 135, 114, 189, 136, 214, 201, 154,
    106, 227, 27, 183, 92, 199, 232, 168, 244, 206, 67, 7,
]);
pub(super) const PRE_PRINCIPAL_UID_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    85, 200, 134, 121, 240, 15, 63, 130, 73, 234, 248, 71, 254, 79, 186, 136, 159, 63, 159, 9, 224,
    16, 72, 245, 235, 0, 226, 208, 216, 12, 142, 147,
]);
pub(super) const PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    155, 248, 23, 9, 199, 131, 17, 254, 161, 1, 17, 55, 248, 218, 179, 182, 205, 143, 254, 108,
    142, 166, 4, 12, 254, 199, 25, 46, 251, 137, 171, 160,
]);
pub(super) const PRE_KV_TRANSITION_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    57, 235, 162, 89, 88, 127, 140, 172, 190, 224, 66, 120, 143, 44, 189, 195, 232, 6, 75, 140, 72,
    252, 139, 169, 56, 0, 186, 2, 200, 198, 13, 50,
]);
pub(super) const PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    57, 145, 181, 144, 2, 201, 129, 253, 59, 86, 3, 186, 221, 78, 165, 179, 17, 67, 37, 48, 35,
    203, 169, 128, 80, 207, 199, 233, 40, 99, 138, 255,
]);
pub(super) const PRE_MECHANICAL_AUDIT_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    195, 253, 108, 67, 165, 182, 160, 95, 254, 17, 195, 57, 80, 44, 227, 80, 144, 246, 100, 62,
    227, 7, 1, 119, 229, 128, 47, 193, 85, 210, 184, 192,
]);
pub(super) const PRE_PHYSICAL_CATALOGUE_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    130, 228, 111, 83, 186, 155, 178, 245, 45, 107, 148, 32, 136, 213, 150, 94, 170, 23, 194, 114,
    14, 97, 206, 132, 46, 217, 213, 227, 192, 209, 33, 157,
]);
pub(super) const PRE_DENSE_RADIX_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    144, 13, 30, 250, 206, 50, 148, 188, 158, 71, 54, 156, 15, 203, 100, 220, 165, 111, 243, 52,
    223, 188, 18, 136, 243, 73, 9, 14, 16, 192, 158, 111,
]);
pub(super) const PRE_FLEET_OWNER_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    157, 112, 29, 200, 115, 96, 230, 52, 178, 91, 123, 127, 93, 94, 121, 49, 95, 159, 39, 188, 244,
    213, 14, 9, 194, 24, 30, 67, 155, 12, 125, 117,
]);
const CONTENT_CATALOG_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    143, 57, 153, 176, 102, 182, 102, 57, 98, 89, 196, 169, 47, 157, 231, 197, 184, 230, 125, 249,
    211, 138, 105, 251, 79, 184, 36, 150, 139, 86, 236, 219,
]);
/// The format-1 specification identity before the workspace-branch kind was
/// registered. Stores bearing this exact published profile are upgraded by
/// replacing the in-band specification object; live object graphs remain
/// unchanged and are validated before the new profile is activated.
pub(super) const PRE_WORKSPACE_BRANCH_FORMAT_SPEC_ID: ObjectId = ObjectId::new([
    249, 177, 127, 165, 230, 180, 172, 69, 98, 199, 228, 171, 45, 161, 240, 199, 86, 218, 7, 148,
    93, 128, 135, 148, 173, 117, 84, 74, 19, 43, 13, 145,
]);
const PRIOR_V1_FORMAT_SPEC_IDS: [ObjectId; 13] = [
    PRE_DERIVATION_FORMAT_SPEC_ID,
    PRE_COMPACTION_FORMAT_SPEC_ID,
    PRE_GC_OUTBOX_FORMAT_SPEC_ID,
    PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
    PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID,
    PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID,
    PRE_KV_TRANSITION_FORMAT_SPEC_ID,
    PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID,
    PRE_MECHANICAL_AUDIT_FORMAT_SPEC_ID,
    PRE_PHYSICAL_CATALOGUE_FORMAT_SPEC_ID,
    PRE_DENSE_RADIX_FORMAT_SPEC_ID,
    PRE_FLEET_OWNER_FORMAT_SPEC_ID,
    PRE_WORKSPACE_BRANCH_FORMAT_SPEC_ID,
];

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

pub(super) fn store_metadata(format_spec: ObjectId, catalog_spec: ObjectId) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    let catalog_digest = object_id_hex(catalog_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         content-catalog-spec-object={}:{}:32:{catalog_digest}\n\
         representations=authoritative-direct-v1\n\
         principal-codec=state-owner-v2\n\
         projection=kv-transition-bplus-v4\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

pub(super) fn pre_fleet_owner_store_metadata(
    format_spec: ObjectId,
    catalog_spec: ObjectId,
) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    let catalog_digest = object_id_hex(catalog_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         content-catalog-spec-object={}:{}:32:{catalog_digest}\n\
         representations=authoritative-direct-v1\n\
         principal-codec=principal-uid-v1\n\
         projection=kv-transition-bplus-v4\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

pub(super) fn pre_representation_store_metadata(
    format_spec: ObjectId,
    catalog_spec: ObjectId,
) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    let catalog_digest = object_id_hex(catalog_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         content-catalog-spec-object={}:{}:32:{catalog_digest}\n\
         principal-codec=principal-uid-v1\n\
         projection=kv-transition-bplus-v4\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

pub(super) fn representation_bootstrap_objects(
    current_format_spec: ObjectId,
    catalog_spec: ObjectId,
) -> Vec<ObjectId> {
    let mut objects = PRIOR_V1_FORMAT_SPEC_IDS.to_vec();
    objects.extend([
        PRE_PRINCIPAL_UID_FORMAT_SPEC_ID,
        current_format_spec,
        catalog_spec,
    ]);
    objects.sort_unstable();
    objects.dedup();
    objects
}

pub(super) fn previous_store_metadata(format_spec: ObjectId, catalog_spec: ObjectId) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    let catalog_digest = object_id_hex(catalog_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         content-catalog-spec-object={}:{}:32:{catalog_digest}\n\
         principal-codec=principal-uid-v1\n\
         projection=kv-tree-v3\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

fn alias_store_metadata(format_spec: ObjectId, catalog_spec: ObjectId) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    let catalog_digest = object_id_hex(catalog_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         content-catalog-spec-object={}:{}:32:{catalog_digest}\n\
         principal-codec=state-owner-v1\n\
         projection=kv-tree-v3\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

pub(super) fn legacy_store_metadata(format_spec: ObjectId) -> Vec<u8> {
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

pub(super) fn is_supported_alias_owner_metadata(actual: &[u8]) -> bool {
    PRIOR_V1_FORMAT_SPEC_IDS
        .iter()
        .copied()
        .chain([PRE_PRINCIPAL_UID_FORMAT_SPEC_ID])
        .any(|candidate| {
            actual == legacy_store_metadata(candidate)
                || actual == alias_store_metadata(candidate, CONTENT_CATALOG_FORMAT_SPEC_ID)
        })
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
    PriorV1 {
        format_spec: ObjectId,
        catalog_spec_was_declared: bool,
    },
}

impl DestinationFormat {
    pub(super) const fn metadata_is_current(self) -> bool {
        matches!(self, Self::Current)
    }
}

pub(super) fn prepare_destination(
    path: &Path,
    expected_metadata: &[u8],
    current_catalog_spec: ObjectId,
) -> StorageResult<DestinationFormat> {
    let mut existing_complete = false;
    if path.exists() {
        if migrations::is_complete(path) {
            existing_complete = true;
        } else {
            quarantine_incomplete(path)?;
        }
    }
    ensure_private_directory(path)?;
    let metadata = path.join(STORE_METADATA_FILE);
    if metadata.exists() {
        let actual = std::fs::read(&metadata).map_err(|error| {
            StorageError::Connection(format!(
                "read principal store metadata {}: {error}",
                metadata.display()
            ))
        })?;
        if actual != expected_metadata {
            if existing_complete
                && let Some(prior) =
                    PRIOR_V1_FORMAT_SPEC_IDS
                        .iter()
                        .copied()
                        .find_map(|candidate| {
                            if actual == legacy_store_metadata(candidate) {
                                Some(DestinationFormat::PriorV1 {
                                    format_spec: candidate,
                                    catalog_spec_was_declared: false,
                                })
                            } else if actual
                                == previous_store_metadata(candidate, current_catalog_spec)
                                || actual
                                    == pre_representation_store_metadata(
                                        candidate,
                                        current_catalog_spec,
                                    )
                                || actual == store_metadata(candidate, current_catalog_spec)
                                || (candidate == PRE_FLEET_OWNER_FORMAT_SPEC_ID
                                    && actual
                                        == pre_fleet_owner_store_metadata(
                                            candidate,
                                            current_catalog_spec,
                                        ))
                            {
                                Some(DestinationFormat::PriorV1 {
                                    format_spec: candidate,
                                    catalog_spec_was_declared: true,
                                })
                            } else {
                                None
                            }
                        })
            {
                return validate_authoritative_files(path).map(|()| prior);
            }
            return Err(unsupported_format_error(&metadata));
        }
    } else if existing_complete {
        if path.join("representations").join("CURRENT").is_file() {
            return validate_authoritative_files(path).map(|()| DestinationFormat::New);
        }
        return Err(StorageError::Connection(format!(
            "completed principal store at {} is missing format metadata",
            path.display()
        )));
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
    destination_format: DestinationFormat,
    current_spec: &ObjectRecord,
    current_spec_id: ObjectId,
) -> StorageResult<()> {
    match destination_format {
        DestinationFormat::Current => ensure_specification(
            engine,
            current_spec_id,
            current_spec,
            true,
            "in-band format specification",
        ),
        DestinationFormat::New => ensure_specification(
            engine,
            current_spec_id,
            current_spec,
            false,
            "in-band format specification",
        ),
        DestinationFormat::PriorV1 {
            format_spec: legacy_spec_id,
            ..
        } => {
            let legacy = read_format_specification(engine, legacy_spec_id)?.ok_or_else(|| {
                StorageError::Connection(
                    "completed principal store is missing its prior format-v1 specification"
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
                    "prior format-v1 specification has an invalid object shape".to_owned(),
                ));
            }
            ensure_specification(
                engine,
                current_spec_id,
                current_spec,
                false,
                "in-band format specification",
            )
        },
    }
}

pub(super) fn prepare_catalog_specification(
    engine: &RuntimeEngine,
    destination_format: DestinationFormat,
    catalog_spec: &ObjectRecord,
    catalog_spec_id: ObjectId,
) -> StorageResult<()> {
    ensure_specification(
        engine,
        catalog_spec_id,
        catalog_spec,
        matches!(
            destination_format,
            DestinationFormat::Current
                | DestinationFormat::PriorV1 {
                    catalog_spec_was_declared: true,
                    ..
                }
        ),
        "content catalog specification",
    )
}

fn ensure_specification(
    engine: &RuntimeEngine,
    object: ObjectId,
    expected: &ObjectRecord,
    missing_is_error: bool,
    description: &'static str,
) -> StorageResult<()> {
    match engine
        .object(object)
        .map_err(|error| StorageError::Connection(format!("read {description}: {error}")))?
    {
        Some(actual) if actual == *expected => Ok(()),
        Some(_) => Err(StorageError::Connection(format!(
            "{description} does not match store.meta"
        ))),
        None if missing_is_error => Err(StorageError::Connection(format!(
            "completed principal store is missing its {description}"
        ))),
        None => engine
            .persist_standalone_object(expected)
            .map(|_| ())
            .map_err(|error| StorageError::Connection(format!("persist {description}: {error}"))),
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

#[cfg(test)]
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
