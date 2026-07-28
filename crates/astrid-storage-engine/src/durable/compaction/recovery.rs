//! Recovery protocol for atomic arena and root-journal generation replacement.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use astrid_storage_model::{
    GcCommitId, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, PlacementSetId, ReferenceKind, ReferenceLabel,
};

use super::super::scan_frames;
use super::{
    ARENA_COMPACTING, ARENA_FILE, ARENA_PREVIOUS, COMPACTION_INTENT_FILE, COMPACTION_INTENT_PREFIX,
    COMPACTION_INTENT_TEMP, COMPACTION_MAGIC, CompactionIntent, DurableError, INDEX_FILE,
    PersistentObjectIdentity, PrincipalCodec, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS,
    RecoveryLimits, append_frame, decode_object_frame, encode_object_frame, ensure_payload_limit,
    evidence, io_error, open_rw, outbox, recover_arena, recover_roots, root_journal_digest,
    sync_store_directory,
};

const INTENT_OPERATION_LABEL: &[u8] = b"00-operation-contract";
const INTENT_COMMIT_LABEL: &[u8] = b"01-gc-commit";
const INTENT_PLACEMENT_LABEL: &[u8] = b"02-placement-after";

pub(super) fn write_compaction_intent<I: PersistentObjectIdentity>(
    directory: &Path,
    intent_model: CompactionIntent,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let temporary = directory.join(COMPACTION_INTENT_TEMP);
    let intent = directory.join(COMPACTION_INTENT_FILE);
    let mut file = super::create_private_file(&temporary)?;
    let record = intent_record(intent_model)?;
    let id = identity.identify(&record);
    let payload = encode_object_frame(identity.scheme(), id, &record)?;
    ensure_payload_limit(COMPACTION_INTENT_FILE, 0, payload.len(), limits)?;
    append_frame(&mut file, COMPACTION_MAGIC, &payload)?;
    file.sync_data()
        .map_err(|source| io_error("flush compaction intent", source))?;
    std::fs::rename(&temporary, &intent)
        .map_err(|source| io_error("publish compaction intent", source))?;
    sync_store_directory(directory)
}

pub(super) fn backup_active(
    directory: &Path,
    active: &'static str,
    previous: &'static str,
) -> Result<(), DurableError> {
    remove_if_exists(&directory.join(previous))?;
    std::fs::rename(directory.join(active), directory.join(previous))
        .map_err(|source| io_error("backup active compaction generation", source))
}

pub(super) fn promote_compacting(
    directory: &Path,
    compacting: &'static str,
    active: &'static str,
) -> Result<(), DurableError> {
    std::fs::rename(directory.join(compacting), directory.join(active))
        .map_err(|source| io_error("promote compacted generation", source))
}

pub(super) fn prepare_finish_compaction(directory: &Path) -> Result<(), DurableError> {
    for file in [
        ARENA_PREVIOUS,
        ROOTS_PREVIOUS,
        ARENA_COMPACTING,
        ROOTS_COMPACTING,
        COMPACTION_INTENT_TEMP,
    ] {
        remove_if_exists(&directory.join(file))?;
    }
    sync_store_directory(directory)
}

pub(super) fn remove_compaction_intent(directory: &Path) -> Result<(), DurableError> {
    remove_if_exists(&directory.join(COMPACTION_INTENT_FILE))?;
    sync_store_directory(directory)
}

fn finish_compaction(directory: &Path) -> Result<(), DurableError> {
    prepare_finish_compaction(directory)?;
    remove_compaction_intent(directory)
}

pub(super) fn cleanup_without_intent(directory: &Path) -> Result<(), DurableError> {
    if directory
        .join(COMPACTION_INTENT_FILE)
        .try_exists()
        .map_err(|source| io_error("inspect compaction intent while cleaning remnants", source))?
    {
        return Ok(());
    }
    cleanup_authority_remnants(directory, ARENA_FILE, ARENA_COMPACTING, ARENA_PREVIOUS)?;
    cleanup_authority_remnants(directory, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS)?;
    remove_if_exists(&directory.join(COMPACTION_INTENT_TEMP))?;
    outbox::cleanup_unpublished(directory)?;
    sync_store_directory(directory)
}

pub(super) fn recover_interrupted_compaction<P, I, C>(
    directory: &Path,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let intent = directory.join(COMPACTION_INTENT_FILE);
    if !intent
        .try_exists()
        .map_err(|source| io_error("inspect compaction intent", source))?
    {
        return cleanup_without_intent(directory);
    }
    let intent_model = validate_intent(&intent, identity, limits)?;
    let bundle = outbox::load_prepared_or_ready(directory, intent_model.commit, identity, limits)?;
    if bundle.placement_after_id(identity) != intent_model.placement_after {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent placement differs from its evidence bundle",
        ));
    }
    let arenas = candidate_paths(directory, ARENA_FILE, ARENA_COMPACTING, ARENA_PREVIOUS)?;
    let roots = candidate_paths(directory, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS)?;
    let (arena, root) = find_valid_pair(&arenas, &roots, intent_model, codec, identity, limits)?;
    install_candidate(directory, &arena, ARENA_FILE, ARENA_PREVIOUS)?;
    install_candidate(directory, &root, ROOT_FILE, ROOTS_PREVIOUS)?;
    sync_store_directory(directory)?;
    let installed = placement_id(
        &directory.join(ARENA_FILE),
        &directory.join(ROOT_FILE),
        intent_model.operation_contract,
        codec,
        identity,
        limits,
    )?;
    if installed != intent_model.placement_after {
        return Err(DurableError::InvalidCompactionEvidence(
            "recovered compaction placement differs from its durable intent",
        ));
    }
    remove_if_exists(&directory.join(INDEX_FILE))?;
    let ready = outbox::mark_ready(directory, intent_model.commit, identity, limits)?;
    if ready != bundle {
        return Err(DurableError::InvalidCompactionEvidence(
            "recovered GC evidence differs from its prepared bundle",
        ));
    }
    finish_compaction(directory)
}

fn validate_intent<I: PersistentObjectIdentity>(
    path: &Path,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionIntent, DurableError> {
    let mut file = open_rw(path)?;
    let mut recovered = None;
    scan_frames(
        &mut file,
        COMPACTION_INTENT_FILE,
        COMPACTION_MAGIC,
        limits,
        |offset, payload| {
            if offset != 0 || recovered.is_some() {
                return Err(DurableError::InvalidCompactionEvidence(
                    "compaction intent is not canonical",
                ));
            }
            let (id, record) = decode_object_frame(payload, identity.scheme()).map_err(|_| {
                DurableError::InvalidCompactionEvidence("compaction intent object is invalid")
            })?;
            if identity.identify(&record) != id
                || encode_object_frame(identity.scheme(), id, &record)? != payload
            {
                return Err(DurableError::InvalidCompactionEvidence(
                    "compaction intent identity or encoding is invalid",
                ));
            }
            recovered = Some(parse_intent_record(&record)?);
            Ok(())
        },
    )?;
    recovered.ok_or(DurableError::InvalidCompactionEvidence(
        "compaction intent must contain one durable frame",
    ))
}

fn intent_record(intent: CompactionIntent) -> Result<ObjectRecord, DurableError> {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        COMPACTION_INTENT_PREFIX.to_vec(),
        vec![
            intent_reference(INTENT_OPERATION_LABEL, intent.operation_contract),
            intent_reference(INTENT_COMMIT_LABEL, intent.commit.object_id()),
            intent_reference(INTENT_PLACEMENT_LABEL, intent.placement_after.object_id()),
        ],
        0,
        ObjectClass::Metadata,
    )
    .map_err(DurableError::Model)
}

fn parse_intent_record(record: &ObjectRecord) -> Result<CompactionIntent, DurableError> {
    if record.kind() != ObjectKind::Evidence
        || record.format_version() != ObjectFormatVersion::V1
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
        || record.canonical_bytes() != COMPACTION_INTENT_PREFIX
        || record.references().len() != 3
    {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent record has an invalid shape",
        ));
    }
    let references = record.references();
    for reference in references {
        if reference.kind() != ReferenceKind::Evidence {
            return Err(DurableError::InvalidCompactionEvidence(
                "compaction intent references must be non-owning Evidence",
            ));
        }
    }
    if references[0].label().as_bytes() != INTENT_OPERATION_LABEL
        || references[1].label().as_bytes() != INTENT_COMMIT_LABEL
        || references[2].label().as_bytes() != INTENT_PLACEMENT_LABEL
    {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent fields are not canonical",
        ));
    }
    let intent = CompactionIntent {
        operation_contract: references[0].target(),
        commit: GcCommitId::new(references[1].target()),
        placement_after: PlacementSetId::new(references[2].target()),
    };
    if intent_record(intent)? != *record {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent does not round-trip canonically",
        ));
    }
    Ok(intent)
}

fn intent_reference(label: &[u8], target: ObjectId) -> ObjectReference {
    ObjectReference::new(
        ReferenceLabel::new(label.to_vec()),
        target,
        ReferenceKind::Evidence,
    )
}

fn candidate_paths(
    directory: &Path,
    active: &'static str,
    compacting: &'static str,
    previous: &'static str,
) -> Result<Vec<PathBuf>, DurableError> {
    let mut paths = Vec::new();
    for name in [compacting, active, previous] {
        let path = directory.join(name);
        if path
            .try_exists()
            .map_err(|source| io_error("inspect compaction generation candidate", source))?
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn find_valid_pair<P, I, C>(
    arenas: &[PathBuf],
    roots: &[PathBuf],
    intent: CompactionIntent,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(PathBuf, PathBuf), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    for arena in arenas {
        for root in roots {
            match placement_id(
                arena,
                root,
                intent.operation_contract,
                codec,
                identity,
                limits,
            ) {
                Ok(actual) if actual == intent.placement_after => {
                    return Ok((arena.clone(), root.clone()));
                },
                Ok(_) | Err(_) => {},
            }
        }
    }
    Err(DurableError::InvalidCompactionEvidence(
        "no authority pair matches the receipted compacted placement",
    ))
}

fn placement_id<P, I, C>(
    arena_path: &Path,
    root_path: &Path,
    operation_contract: astrid_storage_model::ObjectId,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<PlacementSetId, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut arena = open_rw(arena_path)?;
    let mut roots = open_rw(root_path)?;
    let (index, _) = recover_arena(&mut arena, identity, limits)?;
    let (roots_by_principal, _) =
        recover_roots(&mut roots, &mut arena, &index, codec, identity, limits)?;
    let arena_bytes = arena
        .metadata()
        .map_err(|source| io_error("read candidate arena metadata", source))?
        .len();
    let root_journal_bytes = roots
        .metadata()
        .map_err(|source| io_error("read candidate root metadata", source))?
        .len();
    let root_digest = root_journal_digest(&mut roots)?;
    let record = evidence::placement_record(
        &evidence::PlacementView {
            operation_contract,
            arena_bytes,
            root_journal_bytes,
            root_journal_digest: root_digest,
            index: &index,
            roots: &roots_by_principal,
        },
        codec,
    )?;
    Ok(PlacementSetId::new(identity.identify(&record)))
}

fn install_candidate(
    directory: &Path,
    candidate: &Path,
    active_name: &'static str,
    previous_name: &'static str,
) -> Result<(), DurableError> {
    let active = directory.join(active_name);
    if candidate == active {
        return Ok(());
    }
    let previous = directory.join(previous_name);
    if active
        .try_exists()
        .map_err(|source| io_error("inspect active compaction generation", source))?
    {
        if previous
            .try_exists()
            .map_err(|source| io_error("inspect previous compaction generation", source))?
        {
            remove_if_exists(&active)?;
        } else {
            std::fs::rename(&active, &previous)
                .map_err(|source| io_error("preserve active compaction generation", source))?;
        }
    }
    std::fs::rename(candidate, &active)
        .map_err(|source| io_error("install recovered compaction generation", source))
}

fn cleanup_authority_remnants(
    directory: &Path,
    active_name: &'static str,
    compacting_name: &'static str,
    previous_name: &'static str,
) -> Result<(), DurableError> {
    let active = directory.join(active_name);
    let previous = directory.join(previous_name);
    if !active
        .try_exists()
        .map_err(|source| io_error("inspect active compaction file", source))?
        && previous
            .try_exists()
            .map_err(|source| io_error("inspect previous compaction file", source))?
    {
        std::fs::rename(&previous, &active)
            .map_err(|source| io_error("restore previous compaction generation", source))?;
    } else {
        remove_if_exists(&previous)?;
    }
    remove_if_exists(&directory.join(compacting_name))
}

fn remove_if_exists(path: &Path) -> Result<(), DurableError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove compaction remnant", source)),
    }
}
