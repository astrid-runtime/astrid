//! Crash-safe delivery outbox for independently anchored GC evidence.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;

use cap_std::fs::Dir;

use crate::storage_model::{GcCommitId, ObjectId};
use crate::volume::{AstridVolume, VolumeMetadataMutation, VolumeRegion};

use super::evidence::{CompactionEvidenceBundle, validate_bundle};
use super::{
    DurableError, PersistentObjectIdentity, RecoveryLimits, append_frame,
    create_private_file_capability, decode_object_frame, encode_object_frame, ensure_payload_limit,
    io_error, open_directory_capability, open_rw_capability, scan_frames,
    sync_store_directory_capability,
};

pub(super) const OUTBOX_DIRECTORY: &str = "gc-outbox";
const OUTBOX_MAGIC: [u8; 8] = *b"ASTGCO1\0";
const OUTBOX_FILE_NAME: &str = "GC evidence outbox";
const PREPARED_SUFFIX: &str = ".prepared";
const READY_SUFFIX: &str = ".ready";
const TEMP_SUFFIX: &str = ".tmp";
const VOLUME_OUTBOX_PREFIX: &str = "system/gc-outbox/";

pub(super) fn prepare_volume<I: PersistentObjectIdentity>(
    volume: Arc<dyn AstridVolume>,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let ready = volume_bundle_region(bundle.commit_id(), READY_SUFFIX)?;
    if volume
        .region_exists(&ready)
        .map_err(|source| io_error("inspect volume GC evidence", source))?
    {
        return require_same_volume_bundle(volume, &ready, bundle, identity, limits);
    }
    let prepared = volume_bundle_region(bundle.commit_id(), PREPARED_SUFFIX)?;
    if volume
        .region_exists(&prepared)
        .map_err(|source| io_error("inspect volume GC evidence", source))?
    {
        return require_same_volume_bundle(volume, &prepared, bundle, identity, limits);
    }
    write_volume_bundle(volume.clone(), &prepared, bundle, identity, limits)?;
    volume
        .sync()
        .map_err(|source| io_error("flush prepared volume GC evidence", source))
}

pub(super) fn commit_volume_replacement<I: PersistentObjectIdentity>(
    volume: Arc<dyn AstridVolume>,
    source: VolumeRegion,
    destination: VolumeRegion,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let prepared = volume_bundle_region(bundle.commit_id(), PREPARED_SUFFIX)?;
    require_same_volume_bundle(Arc::clone(&volume), &prepared, bundle, identity, limits)?;
    let ready = volume_bundle_region(bundle.commit_id(), READY_SUFFIX)?;
    volume
        .commit_metadata(&[
            VolumeMetadataMutation::Replace {
                source,
                destination,
            },
            VolumeMetadataMutation::Rename {
                source: prepared,
                destination: ready.clone(),
            },
        ])
        .map_err(|source| io_error("commit volume compaction transaction", source))?;
    volume
        .sync()
        .map_err(|source| io_error("flush volume compaction transaction", source))?;
    require_same_volume_bundle(volume, &ready, bundle, identity, limits)
}

pub(super) fn pending_volume<I: PersistentObjectIdentity>(
    volume: &Arc<dyn AstridVolume>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<Vec<CompactionEvidenceBundle>, DurableError> {
    let mut regions = volume
        .list_regions(VOLUME_OUTBOX_PREFIX)
        .map_err(|source| io_error("list volume GC evidence", source))?;
    regions.sort();
    regions
        .into_iter()
        .filter(|region| region.as_str().ends_with(READY_SUFFIX))
        .map(|region| {
            let name = region
                .as_str()
                .strip_prefix(VOLUME_OUTBOX_PREFIX)
                .ok_or(invalid_outbox("invalid volume GC outbox region"))?;
            let commit = parse_bundle_name(name, READY_SUFFIX)?;
            read_volume_bundle(volume.clone(), &region, Some(commit), identity, limits)
        })
        .collect()
}

pub(super) fn acknowledge_volume<I: PersistentObjectIdentity>(
    volume: &Arc<dyn AstridVolume>,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let ready = volume_bundle_region(commit, READY_SUFFIX)?;
    if !volume
        .region_exists(&ready)
        .map_err(|source| io_error("inspect volume GC evidence", source))?
    {
        return Ok(());
    }
    read_volume_bundle(volume.clone(), &ready, Some(commit), identity, limits)?;
    volume
        .remove_region(&ready)
        .map_err(|source| io_error("acknowledge volume GC evidence", source))?;
    volume
        .sync()
        .map_err(|source| io_error("flush volume GC acknowledgement", source))
}

pub(super) fn prepare<I: PersistentObjectIdentity>(
    directory: &Dir,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let outbox = ensure_outbox_directory(directory)?;
    let ready = bundle_name(bundle.commit_id(), READY_SUFFIX);
    if entry_exists(&outbox, &ready)? {
        require_same_bundle(&outbox, &ready, bundle, identity, limits)?;
        return Ok(());
    }

    let prepared = bundle_name(bundle.commit_id(), PREPARED_SUFFIX);
    if entry_exists(&outbox, &prepared)? {
        require_same_bundle(&outbox, &prepared, bundle, identity, limits)?;
        return Ok(());
    }

    let temporary = bundle_name(bundle.commit_id(), TEMP_SUFFIX);
    remove_file_if_exists(
        &outbox,
        &temporary,
        "remove stale GC evidence temporary file",
    )?;
    write_bundle(&outbox, &temporary, bundle, identity, limits)?;
    outbox
        .rename(&temporary, &outbox, &prepared)
        .map_err(|source| io_error("publish prepared GC evidence", source))?;
    sync_store_directory_capability(&outbox)
}

pub(super) fn mark_ready<I: PersistentObjectIdentity>(
    directory: &Dir,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let outbox = require_outbox_directory(directory)?;
    let ready = bundle_name(commit, READY_SUFFIX);
    if entry_exists(&outbox, &ready)? {
        let bundle = read_bundle(&outbox, &ready, Some(commit), identity, limits)?;
        remove_file_if_exists(
            &outbox,
            &bundle_name(commit, PREPARED_SUFFIX),
            "remove redundant prepared GC evidence",
        )?;
        sync_store_directory_capability(&outbox)?;
        return Ok(bundle);
    }

    let prepared = bundle_name(commit, PREPARED_SUFFIX);
    let bundle = read_bundle(&outbox, &prepared, Some(commit), identity, limits)?;
    outbox
        .rename(&prepared, &outbox, &ready)
        .map_err(|source| io_error("mark GC evidence ready", source))?;
    sync_store_directory_capability(&outbox)?;
    Ok(bundle)
}

pub(super) fn load_prepared_or_ready<I: PersistentObjectIdentity>(
    directory: &Dir,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let outbox = require_outbox_directory(directory)?;
    for suffix in [READY_SUFFIX, PREPARED_SUFFIX] {
        let name = bundle_name(commit, suffix);
        if entry_exists(&outbox, &name)? {
            return read_bundle(&outbox, &name, Some(commit), identity, limits);
        }
    }
    Err(DurableError::InvalidCompactionEvidence(
        "durable compaction intent has no matching evidence bundle",
    ))
}

pub(super) fn pending<I: PersistentObjectIdentity>(
    directory: &Dir,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<Vec<CompactionEvidenceBundle>, DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(Vec::new());
    };
    let mut entries = outbox
        .entries()
        .map_err(|source| io_error("list ready GC evidence", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error("read GC evidence directory entry", source))?;
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);

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
        bundles.push(read_bundle(&outbox, &name, Some(commit), identity, limits)?);
    }
    Ok(bundles)
}

pub(super) fn acknowledge<I: PersistentObjectIdentity>(
    directory: &Dir,
    commit: GcCommitId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(());
    };
    let ready = bundle_name(commit, READY_SUFFIX);
    if !entry_exists(&outbox, &ready)? {
        return Ok(());
    }
    read_bundle(&outbox, &ready, Some(commit), identity, limits)?;
    remove_file_if_exists(&outbox, &ready, "acknowledge ready GC evidence")?;
    sync_store_directory_capability(&outbox)
}

pub(super) fn cleanup_unpublished(directory: &Dir) -> Result<(), DurableError> {
    let Some(outbox) = existing_outbox_directory(directory)? else {
        return Ok(());
    };
    for entry in outbox
        .entries()
        .map_err(|source| io_error("list unpublished GC evidence", source))?
    {
        let entry = entry.map_err(|source| io_error("read GC evidence directory entry", source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| DurableError::InvalidCompactionEvidence("non-UTF-8 GC outbox name"))?;
        if name.ends_with(PREPARED_SUFFIX) || name.ends_with(TEMP_SUFFIX) {
            open_rw_capability(&outbox, Path::new(&name), false)?;
            remove_file_if_exists(&outbox, &name, "remove unpublished GC evidence")?;
        }
    }
    sync_store_directory_capability(&outbox)
}

fn write_bundle<I: PersistentObjectIdentity>(
    directory: &Dir,
    name: &str,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let mut file = create_private_file_capability(directory, Path::new(name))?;
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
    directory: &Dir,
    name: &str,
    expected: Option<GcCommitId>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let mut file = open_rw_capability(directory, Path::new(name), false)?;
    read_bundle_file(&mut file, expected, identity, limits)
}

fn read_bundle_file<I: PersistentObjectIdentity, F: super::super::DurableIo>(
    file: &mut F,
    expected: Option<GcCommitId>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let mut records = Vec::new();
    scan_frames(
        file,
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
    directory: &Dir,
    name: &str,
    expected: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let actual = read_bundle(
        directory,
        name,
        Some(expected.commit_id()),
        identity,
        limits,
    )?;
    if &actual != expected {
        return Err(invalid_outbox(
            "GC receipt identity names a different evidence bundle",
        ));
    }
    Ok(())
}

fn volume_bundle_region(commit: GcCommitId, suffix: &str) -> Result<VolumeRegion, DurableError> {
    VolumeRegion::new(format!(
        "{VOLUME_OUTBOX_PREFIX}{}",
        bundle_name(commit, suffix)
    ))
    .map_err(|source| io_error("validate volume GC evidence region", source))
}

fn write_volume_bundle<I: PersistentObjectIdentity>(
    volume: Arc<dyn AstridVolume>,
    region: &VolumeRegion,
    bundle: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    if volume
        .region_exists(region)
        .map_err(|source| io_error("inspect volume GC bundle", source))?
    {
        volume
            .remove_region(region)
            .map_err(|source| io_error("remove stale volume GC bundle", source))?;
    }
    let mut file = super::super::File::volume(volume, region.as_str(), true)?;
    for record in bundle.records() {
        let id = identity.identify(record);
        let payload = encode_object_frame(identity.scheme(), id, record)?;
        ensure_payload_limit(OUTBOX_FILE_NAME, 0, payload.len(), limits)?;
        append_frame(&mut file, OUTBOX_MAGIC, &payload)?;
    }
    file.sync_data()
        .map_err(|source| io_error("flush volume GC bundle", source))
}

fn read_volume_bundle<I: PersistentObjectIdentity>(
    volume: Arc<dyn AstridVolume>,
    region: &VolumeRegion,
    expected: Option<GcCommitId>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<CompactionEvidenceBundle, DurableError> {
    let mut file = super::super::File::volume(volume, region.as_str(), false)?;
    read_bundle_file(&mut file, expected, identity, limits)
}

fn require_same_volume_bundle<I: PersistentObjectIdentity>(
    volume: Arc<dyn AstridVolume>,
    region: &VolumeRegion,
    expected: &CompactionEvidenceBundle,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let actual = read_volume_bundle(volume, region, Some(expected.commit_id()), identity, limits)?;
    if &actual != expected {
        return Err(invalid_outbox(
            "GC receipt identity names a different evidence bundle",
        ));
    }
    Ok(())
}

fn ensure_outbox_directory(directory: &Dir) -> Result<Dir, DurableError> {
    open_directory_capability(directory, Path::new(OUTBOX_DIRECTORY), true)?.ok_or(
        DurableError::InvalidCompactionEvidence("GC evidence outbox is missing after creation"),
    )
}

fn require_outbox_directory(directory: &Dir) -> Result<Dir, DurableError> {
    existing_outbox_directory(directory)?.ok_or(DurableError::InvalidCompactionEvidence(
        "GC evidence outbox is missing",
    ))
}

fn existing_outbox_directory(directory: &Dir) -> Result<Option<Dir>, DurableError> {
    open_directory_capability(directory, Path::new(OUTBOX_DIRECTORY), false)
}

fn bundle_name(commit: GcCommitId, suffix: &str) -> String {
    format!("{}{suffix}", encode_hex(commit.object_id().as_bytes()))
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

fn entry_exists(directory: &Dir, name: &str) -> Result<bool, DurableError> {
    match directory.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect GC evidence outbox entry", source)),
    }
}

fn remove_file_if_exists(
    directory: &Dir,
    name: &str,
    operation: &'static str,
) -> Result<(), DurableError> {
    match directory.remove_file(name) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(operation, source)),
    }
}

const fn invalid_outbox(detail: &'static str) -> DurableError {
    DurableError::InvalidCompactionEvidence(detail)
}
