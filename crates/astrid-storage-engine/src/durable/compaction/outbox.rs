//! Crash-safe delivery outbox for independently anchored GC evidence.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use astrid_storage_model::{GcCommitId, ObjectId};

use super::evidence::{CompactionEvidenceBundle, validate_bundle};
use super::{
    DurableError, PersistentObjectIdentity, RecoveryLimits, append_frame, decode_object_frame,
    encode_object_frame, ensure_payload_limit, io_error, scan_frames, sync_store_directory,
};

pub(super) const OUTBOX_DIRECTORY: &str = "gc-outbox";
const OUTBOX_MAGIC: [u8; 8] = *b"ASTGCO1\0";
const OUTBOX_FILE_NAME: &str = "GC evidence outbox";
const PREPARED_SUFFIX: &str = ".prepared";
const READY_SUFFIX: &str = ".ready";
const TEMP_SUFFIX: &str = ".tmp";

pub(super) fn prepare<I: PersistentObjectIdentity>(
    directory: &Path,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let outbox = ensure_outbox_directory(directory)?;
    let ready = bundle_path(&outbox, bundle.commit_id(), READY_SUFFIX);
    if ready.try_exists().map_err(|source| {
        io_error(
            "inspect ready GC evidence before outbox preparation",
            source,
        )
    })? {
        require_same_bundle(&ready, bundle, identity, limits)?;
        return Ok(());
    }

    let prepared = bundle_path(&outbox, bundle.commit_id(), PREPARED_SUFFIX);
    if prepared.try_exists().map_err(|source| {
        io_error(
            "inspect prepared GC evidence before outbox preparation",
            source,
        )
    })? {
        require_same_bundle(&prepared, bundle, identity, limits)?;
        return Ok(());
    }

    let temporary = bundle_path(&outbox, bundle.commit_id(), TEMP_SUFFIX);
    remove_file_if_exists(&temporary, "remove stale GC evidence temporary file")?;
    write_bundle(&temporary, bundle, identity, limits)?;
    std::fs::rename(&temporary, &prepared)
        .map_err(|source| io_error("publish prepared GC evidence", source))?;
    sync_store_directory(&outbox)
}

pub(super) fn mark_ready<I: PersistentObjectIdentity>(
    directory: &Path,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let outbox = require_outbox_directory(directory)?;
    let ready = bundle_path(&outbox, commit, READY_SUFFIX);
    if ready
        .try_exists()
        .map_err(|source| io_error("inspect ready GC evidence", source))?
    {
        let bundle = read_bundle(&ready, Some(commit), identity, limits)?;
        remove_file_if_exists(
            &bundle_path(&outbox, commit, PREPARED_SUFFIX),
            "remove redundant prepared GC evidence",
        )?;
        sync_store_directory(&outbox)?;
        return Ok(bundle);
    }

    let prepared = bundle_path(&outbox, commit, PREPARED_SUFFIX);
    let bundle = read_bundle(&prepared, Some(commit), identity, limits)?;
    std::fs::rename(&prepared, &ready)
        .map_err(|source| io_error("mark GC evidence ready", source))?;
    sync_store_directory(&outbox)?;
    Ok(bundle)
}

pub(super) fn load_prepared_or_ready<I: PersistentObjectIdentity>(
    directory: &Path,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let outbox = require_outbox_directory(directory)?;
    for suffix in [READY_SUFFIX, PREPARED_SUFFIX] {
        let path = bundle_path(&outbox, commit, suffix);
        if path
            .try_exists()
            .map_err(|source| io_error("inspect expected GC evidence", source))?
        {
            return read_bundle(&path, Some(commit), identity, limits);
        }
    }
    Err(DurableError::InvalidCompactionEvidence(
        "durable compaction intent has no matching evidence bundle",
    ))
}

pub(super) fn pending<I: PersistentObjectIdentity>(
    directory: &Path,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<Vec<CompactionEvidenceBundle>, DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(Vec::new());
    };
    let mut entries = std::fs::read_dir(&outbox)
        .map_err(|source| io_error("list ready GC evidence", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error("read GC evidence directory entry", source))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut bundles = Vec::new();
    for entry in entries {
        // Unknown entries fail the entire drain deliberately. Ignoring one
        // would let filesystem corruption or local tampering hide custody
        // ambiguity behind otherwise valid receipts; operator remediation is
        // required before delivery resumes.
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| DurableError::InvalidCompactionEvidence("non-UTF-8 GC outbox name"))?;
        if name.ends_with(PREPARED_SUFFIX) || name.ends_with(TEMP_SUFFIX) {
            continue;
        }
        let commit = parse_bundle_name(&name, READY_SUFFIX)?;
        require_regular_file(&entry.path())?;
        bundles.push(read_bundle(&entry.path(), Some(commit), identity, limits)?);
    }
    Ok(bundles)
}

pub(super) fn acknowledge<I: PersistentObjectIdentity>(
    directory: &Path,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(());
    };
    let ready = bundle_path(&outbox, commit, READY_SUFFIX);
    if !ready
        .try_exists()
        .map_err(|source| io_error("inspect acknowledged GC evidence", source))?
    {
        return Ok(());
    }
    read_bundle(&ready, Some(commit), identity, limits)?;
    remove_file_if_exists(&ready, "acknowledge ready GC evidence")?;
    sync_store_directory(&outbox)
}

pub(super) fn cleanup_unpublished(directory: &Path) -> Result<(), DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(());
    };
    for entry in std::fs::read_dir(&outbox)
        .map_err(|source| io_error("list unpublished GC evidence", source))?
    {
        let entry = entry.map_err(|source| io_error("read GC evidence directory entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| DurableError::InvalidCompactionEvidence("non-UTF-8 GC outbox name"))?;
        if name.ends_with(PREPARED_SUFFIX) || name.ends_with(TEMP_SUFFIX) {
            require_regular_file(&entry.path())?;
            remove_file_if_exists(&entry.path(), "remove unpublished GC evidence")?;
        }
    }
    sync_store_directory(&outbox)
}

fn write_bundle<I: PersistentObjectIdentity>(
    path: &Path,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let mut file = create_private_file(path)?;
    for record in bundle.records() {
        let id = identity.identify(record);
        let payload = encode_object_frame(identity.scheme(), id, record)?;
        ensure_payload_limit(OUTBOX_FILE_NAME, 0, payload.len(), limits)?;
        append_frame(&mut file, OUTBOX_MAGIC, &payload)?;
    }
    file.sync_data()
        .map_err(|source| io_error("flush prepared GC evidence", source))
}

fn read_bundle<I: PersistentObjectIdentity>(
    path: &Path,
    expected: Option<GcCommitId>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    require_regular_file(path)?;
    let mut file = open_existing(path)?;
    let mut records = Vec::new();
    scan_frames(
        &mut file,
        OUTBOX_FILE_NAME,
        OUTBOX_MAGIC,
        limits,
        |offset, payload| {
            let (id, record) = decode_object_frame(payload, identity.scheme())
                .map_err(|_| invalid_outbox("GC outbox object frame is invalid"))?;
            if identity.identify(&record) != id
                || encode_object_frame(identity.scheme(), id, &record)? != payload
            {
                return Err(DurableError::Corrupt {
                    file: OUTBOX_FILE_NAME,
                    offset,
                    detail: "GC outbox object identity or canonical encoding mismatch",
                });
            }
            records.push(record);
            Ok(())
        },
    )?;
    let bundle = validate_bundle(records, identity)?;
    if expected.is_some_and(|expected| expected != bundle.commit_id()) {
        return Err(invalid_outbox("GC outbox filename does not match receipt"));
    }
    Ok(bundle)
}

fn require_same_bundle<I: PersistentObjectIdentity>(
    path: &Path,
    expected: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let actual = read_bundle(path, Some(expected.commit_id()), identity, limits)?;
    if &actual != expected {
        return Err(invalid_outbox(
            "GC receipt identity names a different evidence bundle",
        ));
    }
    Ok(())
}

fn ensure_outbox_directory(directory: &Path) -> Result<PathBuf, DurableError> {
    if let Some(path) = existing_outbox_directory(directory)? {
        return Ok(path);
    }
    let path = directory.join(OUTBOX_DIRECTORY);
    #[cfg(unix)]
    let mut builder = DirBuilder::new();
    #[cfg(not(unix))]
    let builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(&path) {
        Ok(()) => sync_store_directory(directory)?,
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {},
        Err(source) => return Err(io_error("create GC evidence outbox", source)),
    }
    require_outbox_directory(directory)
}

fn require_outbox_directory(directory: &Path) -> Result<PathBuf, DurableError> {
    existing_outbox_directory(directory)?.ok_or(DurableError::InvalidCompactionEvidence(
        "GC evidence outbox is missing",
    ))
}

fn existing_outbox_directory(directory: &Path) -> Result<Option<PathBuf>, DurableError> {
    let path = directory.join(OUTBOX_DIRECTORY);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("inspect GC evidence outbox", source)),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_outbox(
            "GC evidence outbox must be a private directory",
        ));
    }
    Ok(Some(path))
}

fn create_private_file(path: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| io_error("create GC evidence outbox file", source))
}

fn open_existing(path: &Path) -> Result<File, DurableError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error("open GC evidence outbox file", source))
}

fn require_regular_file(path: &Path) -> Result<(), DurableError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect GC evidence outbox file", source))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_outbox(
            "GC evidence outbox entry must be a regular file",
        ));
    }
    Ok(())
}

fn bundle_path(directory: &Path, commit: GcCommitId, suffix: &str) -> PathBuf {
    directory.join(format!(
        "{}{suffix}",
        encode_hex(commit.object_id().as_bytes())
    ))
}

fn parse_bundle_name(name: &str, suffix: &str) -> Result<GcCommitId, DurableError> {
    let digest = name
        .strip_suffix(suffix)
        .ok_or(invalid_outbox("unexpected GC outbox filename"))?;
    let bytes = decode_hex(digest)?;
    Ok(GcCommitId::new(ObjectId::new(bytes)))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<[u8; 32], DurableError> {
    if value.len() != 64 {
        return Err(invalid_outbox(
            "GC outbox receipt name must contain 64 hexadecimal digits",
        ));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, DurableError> {
    match value {
        b'0'..=b'9' => value
            .checked_sub(b'0')
            .ok_or(invalid_outbox("invalid hexadecimal digit")),
        b'a'..=b'f' => value
            .checked_sub(b'a')
            .and_then(|nibble| nibble.checked_add(10))
            .ok_or(invalid_outbox("invalid hexadecimal digit")),
        _ => Err(invalid_outbox(
            "GC outbox receipt name is not canonical lowercase hexadecimal",
        )),
    }
}

fn remove_file_if_exists(path: &Path, operation: &'static str) -> Result<(), DurableError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(operation, source)),
    }
}

const fn invalid_outbox(detail: &'static str) -> DurableError {
    DurableError::InvalidCompactionEvidence(detail)
}
