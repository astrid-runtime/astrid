//! Recovery protocol for atomic arena and root-journal generation replacement.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use astrid_storage_model::RootState;

use super::super::scan_frames;
use super::{
    ARENA_COMPACTING, ARENA_FILE, ARENA_PREVIOUS, COMPACTION_INTENT_FILE, COMPACTION_INTENT_TEMP,
    COMPACTION_INTENT_V1, COMPACTION_MAGIC, DurableError, INDEX_FILE, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS, RecoveryLimits, append_frame,
    io_error, open_rw, recover_arena, recover_roots, sync_store_directory,
};

pub(super) fn write_compaction_intent(directory: &Path) -> Result<(), DurableError> {
    let temporary = directory.join(COMPACTION_INTENT_TEMP);
    let intent = directory.join(COMPACTION_INTENT_FILE);
    let mut file = super::create_private_file(&temporary)?;
    append_frame(&mut file, COMPACTION_MAGIC, &COMPACTION_INTENT_V1)?;
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
    validate_intent(&intent, limits)?;
    let arenas = candidate_paths(directory, ARENA_FILE, ARENA_COMPACTING, ARENA_PREVIOUS)?;
    let roots = candidate_paths(directory, ROOT_FILE, ROOTS_COMPACTING, ROOTS_PREVIOUS)?;
    let (arena, root) = find_valid_pair(&arenas, &roots, codec, identity, limits)?;
    install_candidate(directory, &arena, ARENA_FILE, ARENA_PREVIOUS)?;
    install_candidate(directory, &root, ROOT_FILE, ROOTS_PREVIOUS)?;
    sync_store_directory(directory)?;
    validate_candidate_pair(
        &directory.join(ARENA_FILE),
        &directory.join(ROOT_FILE),
        codec,
        identity,
        limits,
    )?;
    remove_if_exists(&directory.join(INDEX_FILE))?;
    finish_compaction(directory)
}

fn validate_intent(path: &Path, limits: RecoveryLimits) -> Result<(), DurableError> {
    let mut file = open_rw(path)?;
    let mut frames = 0_u8;
    scan_frames(
        &mut file,
        COMPACTION_INTENT_FILE,
        COMPACTION_MAGIC,
        limits,
        |offset, payload| {
            if offset != 0 || payload != COMPACTION_INTENT_V1 {
                return Err(DurableError::InvalidCompactionEvidence(
                    "compaction intent is not canonical",
                ));
            }
            frames = frames.saturating_add(1);
            Ok(())
        },
    )?;
    if frames != 1 {
        return Err(DurableError::InvalidCompactionEvidence(
            "compaction intent must contain one durable frame",
        ));
    }
    Ok(())
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
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(PathBuf, PathBuf), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut last_error = None;
    for arena in arenas {
        for root in roots {
            match validate_candidate_pair(arena, root, codec, identity, limits) {
                Ok(()) => return Ok((arena.clone(), root.clone())),
                Err(error) => last_error = Some(error),
            }
        }
    }
    Err(
        last_error.unwrap_or(DurableError::InvalidCompactionEvidence(
            "no complete authority pair survived interrupted compaction",
        )),
    )
}

fn validate_candidate_pair<P, I, C>(
    arena_path: &Path,
    root_path: &Path,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut arena = open_rw(arena_path)?;
    let mut roots = open_rw(root_path)?;
    let (index, _) = recover_arena(&mut arena, identity, limits)?;
    let _: (BTreeMap<P, RootState>, _) =
        recover_roots(&mut roots, &mut arena, &index, codec, identity, limits)?;
    Ok(())
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
