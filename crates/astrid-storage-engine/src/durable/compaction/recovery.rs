//! Recovery protocol for atomic arena and root-journal generation replacement.

use std::io::ErrorKind;
use std::path::Path;

use astrid_storage_model::{
    GcCommitId, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, PlacementSetId, ReferenceKind, ReferenceLabel,
};

use super::super::representations::RepresentationStore;
use super::super::scan_frames;
use super::{
    ARENA_COMPACTING, ARENA_FILE, ARENA_PREVIOUS, COMPACTION_INTENT_FILE, COMPACTION_INTENT_PREFIX,
    COMPACTION_INTENT_TEMP, COMPACTION_MAGIC, CompactionIntent, DurableError, INDEX_FILE,
    PersistentObjectIdentity, PrincipalCodec, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS,
    RecoveryLimits, append_frame, create_private_file_capability, decode_object_frame,
    encode_object_frame, ensure_payload_limit, evidence, io_error, open_rw_capability, outbox,
    recover_arena, recover_roots, root_journal_digest, sync_store_directory_capability,
};

const INTENT_OPERATION_LABEL: &[u8] = b"00-operation-contract";
const INTENT_COMMIT_LABEL: &[u8] = b"01-gc-commit";
const INTENT_PLACEMENT_LABEL: &[u8] = b"02-placement-after";

pub(super) fn write_compaction_intent<I: PersistentObjectIdentity>(
    directory: &cap_std::fs::Dir,
    intent_model: CompactionIntent,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    remove_capability_file_if_exists(directory, COMPACTION_INTENT_TEMP)?;
    let mut file = create_private_file_capability(directory, Path::new(COMPACTION_INTENT_TEMP))?;
    let record = intent_record(intent_model)?;
    let id = identity.identify(&record);
    let payload = encode_object_frame(identity.scheme(), id, &record)?;
    ensure_payload_limit(COMPACTION_INTENT_FILE, 0, payload.len(), limits)?;
    append_frame(&mut file, COMPACTION_MAGIC, &payload)?;
    file.sync_data()
        .map_err(|source| io_error("flush compaction intent", source))?;
    directory
        .rename(COMPACTION_INTENT_TEMP, directory, COMPACTION_INTENT_FILE)
        .map_err(|source| io_error("publish compaction intent", source))?;
    sync_store_directory_capability(directory)
}

pub(super) fn backup_active(
    directory: &cap_std::fs::Dir,
    active: &'static str,
    previous: &'static str,
) -> Result<(), DurableError> {
    remove_capability_file_if_exists(directory, previous)?;
    directory
        .rename(active, directory, previous)
        .map_err(|source| io_error("backup active compaction generation", source))
}

pub(super) fn promote_compacting(
    directory: &cap_std::fs::Dir,
    compacting: &'static str,
    active: &'static str,
) -> Result<(), DurableError> {
    directory
        .rename(compacting, directory, active)
        .map_err(|source| io_error("promote compacted generation", source))
}

pub(super) fn prepare_finish_compaction(directory: &cap_std::fs::Dir) -> Result<(), DurableError> {
    for file in [
        ARENA_PREVIOUS,
        ROOTS_PREVIOUS,
        ARENA_COMPACTING,
        ROOTS_COMPACTING,
        COMPACTION_INTENT_TEMP,
    ] {
        remove_capability_file_if_exists(directory, file)?;
    }
    sync_store_directory_capability(directory)
}

pub(super) fn remove_compaction_intent(directory: &cap_std::fs::Dir) -> Result<(), DurableError> {
    remove_capability_file_if_exists(directory, COMPACTION_INTENT_FILE)?;
    sync_store_directory_capability(directory)
}

fn finish_compaction(directory: &cap_std::fs::Dir) -> Result<(), DurableError> {
    prepare_finish_compaction(directory)?;
    remove_compaction_intent(directory)
}

pub(super) fn cleanup_without_intent(directory: &cap_std::fs::Dir) -> Result<(), DurableError> {
    if capability_file_exists(directory, COMPACTION_INTENT_FILE)? {
        return Ok(());
    }
    cleanup_authority_remnants(directory, ARENA_FILE, ARENA_COMPACTING, ARENA_PREVIOUS)?;
    cleanup_authority_remnants(directory, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS)?;
    remove_capability_file_if_exists(directory, COMPACTION_INTENT_TEMP)?;
    outbox::cleanup_unpublished(directory)?;
    sync_store_directory_capability(directory)
}

pub(super) fn recover_interrupted_compaction<P, I, C>(
    directory: &Path,
    store_root: &cap_std::fs::Dir,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    if !capability_file_exists(store_root, COMPACTION_INTENT_FILE)? {
        return cleanup_without_intent(store_root);
    }
    let intent_model = validate_intent(store_root, identity, limits)?;
    let bundle = outbox::load_prepared_or_ready(store_root, intent_model.commit, identity, limits)?;
    if bundle.placement_after_id(identity) != intent_model.placement_after {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent placement differs from its evidence bundle",
        ));
    }
    let arenas = candidate_names(store_root, ARENA_FILE, ARENA_COMPACTING, ARENA_PREVIOUS)?;
    let roots = candidate_names(store_root, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS)?;
    let (arena, root) = find_valid_pair(
        store_root,
        &arenas,
        &roots,
        intent_model,
        codec,
        identity,
        limits,
    )?;
    install_candidate(store_root, arena, ARENA_FILE, ARENA_PREVIOUS)?;
    install_candidate(store_root, root, ROOT_FILE, ROOTS_PREVIOUS)?;
    sync_store_directory_capability(store_root)?;
    let installed = placement_id(
        store_root,
        ARENA_FILE,
        ROOT_FILE,
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
    rebase_representation_authority(directory, store_root, identity, limits)?;
    remove_capability_file_if_exists(store_root, INDEX_FILE)?;
    let ready = outbox::mark_ready(store_root, intent_model.commit, identity, limits)?;
    if ready != bundle {
        return Err(DurableError::InvalidCompactionEvidence(
            "recovered GC evidence differs from its prepared bundle",
        ));
    }
    finish_compaction(store_root)
}

fn rebase_representation_authority<I: PersistentObjectIdentity>(
    directory: &Path,
    store_root: &cap_std::fs::Dir,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let Some(mut representations) = RepresentationStore::open(directory, store_root, limits)?
    else {
        return Ok(());
    };
    let mut arena = open_rw_capability(store_root, Path::new(ARENA_FILE), false)?;
    let (index, _) = recover_arena(&mut arena, identity, limits, 0)?;
    representations.rebuild_contiguous_index(&mut arena, &index, identity, limits)?;
    representations.rebase_compacted_arena(&arena, &index, identity, limits)?;
    representations.retire_loose_blobs()
}

fn validate_intent<I: PersistentObjectIdentity>(
    directory: &cap_std::fs::Dir,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionIntent, DurableError> {
    let mut file = open_rw_capability(directory, Path::new(COMPACTION_INTENT_FILE), false)?;
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

fn candidate_names(
    directory: &cap_std::fs::Dir,
    active: &'static str,
    compacting: &'static str,
    previous: &'static str,
) -> Result<Vec<&'static str>, DurableError> {
    let mut paths = Vec::new();
    for name in [compacting, active, previous] {
        match directory.symlink_metadata(name) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                paths.push(name);
            },
            Ok(_) => {
                return Err(DurableError::InvalidCompactionEvidence(
                    "compaction generation candidate is redirected or not a regular file",
                ));
            },
            Err(source) if source.kind() == ErrorKind::NotFound => {},
            Err(source) => {
                return Err(io_error("inspect compaction generation candidate", source));
            },
        }
    }
    Ok(paths)
}

fn find_valid_pair<P, I, C>(
    directory: &cap_std::fs::Dir,
    arenas: &[&'static str],
    roots: &[&'static str],
    intent: CompactionIntent,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(&'static str, &'static str), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    for arena in arenas {
        for root in roots {
            match placement_id(
                directory,
                arena,
                root,
                intent.operation_contract,
                codec,
                identity,
                limits,
            ) {
                Ok(actual) if actual == intent.placement_after => {
                    return Ok((*arena, *root));
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
    directory: &cap_std::fs::Dir,
    arena_name: &str,
    root_name: &str,
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
    let mut arena = open_rw_capability(directory, Path::new(arena_name), false)?;
    let mut roots = open_rw_capability(directory, Path::new(root_name), false)?;
    let (index, _) = recover_arena(&mut arena, identity, limits, 0)?;
    let (roots_by_principal, _) = recover_roots(
        &mut roots, &mut arena, &index, None, codec, identity, limits,
    )?;
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
    directory: &cap_std::fs::Dir,
    candidate: &'static str,
    active_name: &'static str,
    previous_name: &'static str,
) -> Result<(), DurableError> {
    if candidate == active_name {
        return Ok(());
    }
    if capability_file_exists(directory, active_name)? {
        if capability_file_exists(directory, previous_name)? {
            remove_capability_file_if_exists(directory, active_name)?;
        } else {
            directory
                .rename(active_name, directory, previous_name)
                .map_err(|source| io_error("preserve active compaction generation", source))?;
        }
    }
    directory
        .rename(candidate, directory, active_name)
        .map_err(|source| io_error("install recovered compaction generation", source))
}

fn capability_file_exists(directory: &cap_std::fs::Dir, name: &str) -> Result<bool, DurableError> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(DurableError::InvalidCompactionEvidence(
            "compaction authority entry is redirected or not a regular file",
        )),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect compaction authority entry", source)),
    }
}

fn remove_capability_file_if_exists(
    directory: &cap_std::fs::Dir,
    name: &str,
) -> Result<(), DurableError> {
    match directory.remove_file(name) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove compaction capability file", source)),
    }
}

fn cleanup_authority_remnants(
    directory: &cap_std::fs::Dir,
    active_name: &'static str,
    compacting_name: &'static str,
    previous_name: &'static str,
) -> Result<(), DurableError> {
    if !capability_file_exists(directory, active_name)?
        && capability_file_exists(directory, previous_name)?
    {
        directory
            .rename(previous_name, directory, active_name)
            .map_err(|source| io_error("restore previous compaction generation", source))?;
    } else {
        remove_capability_file_if_exists(directory, previous_name)?;
    }
    remove_capability_file_if_exists(directory, compacting_name)
}
