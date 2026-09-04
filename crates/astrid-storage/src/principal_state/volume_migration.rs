//! Verified cutover from the released directory store to Astrid volume media.

use std::sync::Arc;

use crate::engine::{DurableEnginePolicy, PrincipalCodec, RecoveryLimits, RootSnapshot};
use crate::error::{StorageError, StorageResult};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
use astrid_core::dirs::AstridHome;

use super::{Blake3ObjectIdentityV1, RuntimeEngine, StateOwner, StateOwnerCodecV2};

const CUTOVER_RECEIPT_REGION: &str = "system/migrations/directory-store-to-volume-v1";
const MAX_CUTOVER_RECEIPT_BYTES: u64 = 256;

pub(super) fn existing_volume_available(home: &AstridHome) -> StorageResult<bool> {
    Ok(promote_legacy_volume(home)?.is_some())
}

pub(super) fn open_existing(
    home: &AstridHome,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<Option<(RuntimeEngine, String)>> {
    let Some(path) = promote_legacy_volume(home)? else {
        return Ok(None);
    };
    let volume = HostedFileVolume::open(&path).map_err(|error| {
        connection(format!(
            "open Astrid storage volume {}: {error}",
            path.display()
        ))
    })?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .map_err(|error| connection(format!("recover Astrid storage volume: {error}")))?;
    // The receipt binds the one-time directory-store cutover. Live roots are
    // expected to advance after that boundary, so ordinary reopen validates
    // the durable marker without comparing it to the current mutable roots.
    let receipt = require_cutover_receipt(volume.as_ref(), None)?;
    Ok(Some((engine, receipt)))
}

/// Resolve the canonical volume and promote a released legacy path once.
///
/// Promotion happens before recovery so the runtime-tree admission walk can
/// exclude the canonical media file and cannot mistake the legacy file for
/// ordinary content. Seeing both paths is ambiguous and fails closed.
fn promote_legacy_volume(home: &AstridHome) -> StorageResult<Option<std::path::PathBuf>> {
    let canonical = home.storage_volume_path();
    let legacy = legacy_volume_path(home)?;
    let canonical_present = inspect_volume_entry(&canonical)?;
    let legacy_present = inspect_volume_entry(&legacy)?;

    match (canonical_present, legacy_present) {
        (true, true) => Err(connection(format!(
            "Astrid storage has both canonical and legacy volumes: {} and {}",
            canonical.display(),
            legacy.display()
        ))),
        (true, false) => Ok(Some(canonical)),
        (false, true) => {
            super::native_io::rename_private_entry(&legacy, &canonical)?;
            let legacy_parent = legacy.parent().ok_or_else(|| {
                connection(format!(
                    "legacy Astrid volume has no parent: {}",
                    legacy.display()
                ))
            })?;
            super::native_io::sync_directory(legacy_parent)?;
            super::native_io::sync_directory(home.root())?;
            Ok(Some(canonical))
        },
        (false, false) => Ok(None),
    }
}

/// Choose the older media path while refusing ambiguous simultaneous inputs.
fn legacy_volume_path(home: &AstridHome) -> StorageResult<std::path::PathBuf> {
    let var_path = home.legacy_storage_volume_path();
    let root_path = home.retired_root_storage_volume_path();
    let var_present = inspect_volume_entry(&var_path)?;
    let root_present = inspect_volume_entry(&root_path)?;
    if var_present && root_present {
        return Err(connection(format!(
            "Astrid storage has both released legacy volumes: {} and {}",
            var_path.display(),
            root_path.display()
        )));
    }
    Ok(if root_present { root_path } else { var_path })
}

/// Create and verify a fresh empty durable volume.
pub(super) fn initialize_volume(
    home: &AstridHome,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<(RuntimeEngine, String)> {
    let destination = home.storage_volume_path();
    let temporary = destination.with_extension("migrating");
    if temporary.exists() {
        return Err(connection(format!(
            "incomplete Astrid volume already exists: {}",
            temporary.display()
        )));
    }
    let volume = HostedFileVolume::open(&temporary).map_err(|error| {
        connection(format!(
            "create fresh Astrid volume {}: {error}",
            temporary.display()
        ))
    })?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .map_err(|error| connection(format!("open fresh Astrid volume: {error}")))?;
    for bootstrap in super::bootstrap::RuntimeBootstrapObject::registered() {
        let record = bootstrap.record()?;
        engine
            .persist_standalone_object(&record)
            .map_err(|error| connection(format!("persist volume bootstrap object: {error}")))?;
    }
    engine
        .flush()
        .map_err(|error| connection(format!("flush fresh Astrid volume: {error}")))?;
    write_cutover_receipt(volume.as_ref(), &[])?;
    engine
        .close()
        .map_err(|error| connection(format!("close fresh Astrid volume: {error}")))?;
    drop(engine);
    drop(volume);

    super::native_io::rename_private_entry(&temporary, &destination)?;
    super::native_io::sync_directory(home.root())?;
    let volume = HostedFileVolume::open(&destination).map_err(|error| {
        connection(format!(
            "reopen fresh Astrid volume {}: {error}",
            destination.display()
        ))
    })?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .map_err(|error| connection(format!("open verified fresh Astrid volume: {error}")))?;
    let receipt = require_cutover_receipt(volume.as_ref(), Some(&[]))?;
    Ok((engine, receipt))
}

fn inspect_volume_entry(path: &std::path::Path) -> StorageResult<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(connection(format!(
                "Astrid storage volume is redirected or not a regular file: {}",
                path.display()
            )))
        },
        Ok(_) => Ok(true),
        Err(error) => Err(connection(format!(
            "inspect Astrid storage volume {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn migrate_directory_store(
    home: &AstridHome,
    source: Arc<RuntimeEngine>,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<(RuntimeEngine, String)> {
    let snapshots = snapshots(&source)?;
    let destination = home.storage_volume_path();
    let temporary = destination.with_extension("migrating");
    if temporary.exists() {
        std::fs::remove_file(&temporary).map_err(|error| {
            connection(format!(
                "remove incomplete Astrid volume {}: {error}",
                temporary.display()
            ))
        })?;
    }

    let volume = HostedFileVolume::open(&temporary).map_err(|error| {
        connection(format!(
            "create migrating Astrid volume {}: {error}",
            temporary.display()
        ))
    })?;
    let migrated = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )
    .map_err(|error| connection(format!("open migrating Astrid volume: {error}")))?;
    for bootstrap in super::bootstrap::RuntimeBootstrapObject::registered() {
        let record = bootstrap.record()?;
        migrated
            .persist_standalone_object(&record)
            .map_err(|error| connection(format!("persist volume bootstrap object: {error}")))?;
    }
    migrated
        .restore_snapshots(snapshots.clone())
        .map_err(|error| connection(format!("restore roots into Astrid volume: {error}")))?;
    migrated
        .flush()
        .map_err(|error| connection(format!("flush migrated Astrid volume: {error}")))?;
    verify_snapshots(&migrated, &snapshots)?;
    write_cutover_receipt(volume.as_ref(), &snapshots)?;
    migrated
        .close()
        .map_err(|error| connection(format!("close migrating Astrid volume: {error}")))?;
    drop(migrated);
    drop(volume);

    super::native_io::rename_private_entry(&temporary, &destination)?;
    super::native_io::sync_directory(home.root())?;

    let volume = HostedFileVolume::open(&destination).map_err(|error| {
        connection(format!(
            "reopen Astrid volume {}: {error}",
            destination.display()
        ))
    })?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .map_err(|error| connection(format!("verify promoted Astrid volume: {error}")))?;
    verify_snapshots(&engine, &snapshots)?;
    let receipt = require_cutover_receipt(volume.as_ref(), Some(&snapshots))?;

    source
        .close()
        .map_err(|error| connection(format!("close retired directory store: {error}")))?;
    drop(source);
    Ok((engine, receipt))
}

pub(super) fn retire_verified_directory_if_present(
    home: &AstridHome,
    expected_receipt: &str,
) -> StorageResult<()> {
    let path = home.principal_store_path();
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(connection(format!(
                "surviving directory store is redirected or not a directory: {}",
                path.display()
            )));
        },
        Ok(_) => {
            let source = RuntimeEngine::open_with_policy(
                &path,
                Blake3ObjectIdentityV1,
                StateOwnerCodecV2,
                RecoveryLimits::process_addressable(),
                DurableEnginePolicy::default(),
            )
            .map_err(|error| connection(format!("reopen surviving directory store: {error}")))?;
            let source_snapshots = snapshots(&source)?;
            if cutover_receipt(&source_snapshots) != expected_receipt {
                return Err(connection(
                    "Astrid volume cutover receipt does not match its independently recomputed roots",
                ));
            }
            source.close().map_err(|error| {
                connection(format!("close verified surviving directory store: {error}"))
            })?;
            drop(source);
            astrid_core::dirs::retire_legacy_source_tree(&path).map_err(|error| {
                connection(format!(
                    "retire verified directory store {}: {error}",
                    path.display()
                ))
            })?;
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(connection(format!(
                "inspect retired directory store {}: {error}",
                path.display()
            )));
        },
    }
    Ok(())
}

fn snapshots(engine: &RuntimeEngine) -> StorageResult<Vec<(StateOwner, RootSnapshot)>> {
    engine
        .roots()
        .map_err(|error| connection(format!("enumerate directory-store roots: {error}")))?
        .into_iter()
        .map(|(owner, _)| {
            engine
                .snapshot(&owner)
                .map_err(|error| connection(format!("snapshot directory-store owner: {error}")))?
                .map(|snapshot| (owner, snapshot))
                .ok_or_else(|| connection("directory-store root disappeared during snapshot"))
        })
        .collect()
}

fn verify_snapshots(
    engine: &RuntimeEngine,
    expected: &[(StateOwner, RootSnapshot)],
) -> StorageResult<()> {
    let actual = snapshots(engine)?;
    if actual != expected {
        return Err(connection(
            "Astrid volume roots differ from the verified directory store",
        ));
    }
    Ok(())
}

fn write_cutover_receipt(
    volume: &dyn AstridVolume,
    snapshots: &[(StateOwner, RootSnapshot)],
) -> StorageResult<()> {
    let region = VolumeRegion::new(CUTOVER_RECEIPT_REGION)
        .map_err(|error| connection(format!("validate cutover receipt region: {error}")))?;
    volume
        .create_region(&region, false)
        .map_err(|error| connection(format!("create cutover receipt region: {error}")))?;
    let receipt = cutover_receipt(snapshots);
    volume
        .set_region_len(&region, 0)
        .map_err(|error| connection(format!("truncate cutover receipt: {error}")))?;
    volume
        .write_region_at(&region, 0, receipt.as_bytes())
        .map_err(|error| connection(format!("write cutover receipt: {error}")))?;
    volume
        .sync()
        .map_err(|error| connection(format!("flush cutover receipt: {error}")))
}

fn require_cutover_receipt(
    volume: &dyn AstridVolume,
    expected_snapshots: Option<&[(StateOwner, RootSnapshot)]>,
) -> StorageResult<String> {
    let region = VolumeRegion::new(CUTOVER_RECEIPT_REGION)
        .map_err(|error| connection(format!("validate cutover receipt region: {error}")))?;
    if !volume
        .region_exists(&region)
        .map_err(|error| connection(format!("inspect cutover receipt region: {error}")))?
    {
        return Err(connection(
            "Astrid volume has no verified directory-store cutover receipt",
        ));
    }
    let length = volume
        .region_len(&region)
        .map_err(|error| connection(format!("read cutover receipt length: {error}")))?;
    if length > MAX_CUTOVER_RECEIPT_BYTES {
        return Err(connection("Astrid volume cutover receipt is too large"));
    }
    let length = usize::try_from(length)
        .map_err(|_| connection("Astrid volume cutover receipt is too large"))?;
    let mut actual = vec![0; length];
    let read = volume
        .read_region_at(&region, 0, &mut actual)
        .map_err(|error| connection(format!("read cutover receipt: {error}")))?;
    let text = std::str::from_utf8(&actual)
        .map_err(|_| connection("Astrid volume cutover receipt is not UTF-8"))?;
    let lines = text
        .strip_suffix('\n')
        .map(|body| body.lines().collect::<Vec<_>>());
    let valid = read == actual.len()
        && lines.is_some_and(|lines| {
            lines.len() == 4
                && lines[0] == "migration=directory-store-to-astrid-volume"
                && lines[1] == "version=1"
                && lines[2]
                    .strip_prefix("owners=")
                    .and_then(|owners| owners.parse::<u64>().ok().map(|parsed| (owners, parsed)))
                    .is_some_and(|(owners, parsed)| owners == parsed.to_string())
                && lines[3].strip_prefix("digest=").is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        });
    if !valid {
        return Err(connection("Astrid volume cutover receipt is not canonical"));
    }
    if expected_snapshots.is_some_and(|snapshots| text != cutover_receipt(snapshots)) {
        return Err(connection(
            "Astrid volume cutover receipt does not match its independently recomputed roots",
        ));
    }
    Ok(text.to_owned())
}

fn cutover_receipt(snapshots: &[(StateOwner, RootSnapshot)]) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(b"astrid-directory-store-to-volume-v1\0");
    for (owner, snapshot) in snapshots {
        material.extend_from_slice(&StateOwnerCodecV2.encode(owner));
        material.extend_from_slice(&snapshot.root().generation.get().to_le_bytes());
        material.extend_from_slice(snapshot.root().commit.as_bytes());
        for (id, _) in snapshot.records() {
            material.extend_from_slice(id.as_bytes());
        }
    }
    let digest = blake3::derive_key("astrid volume cutover receipt v1", &material);
    format!(
        "migration=directory-store-to-astrid-volume\nversion=1\nowners={}\ndigest={}\n",
        snapshots.len(),
        hex::encode(digest)
    )
}

fn connection(message: impl Into<String>) -> StorageError {
    StorageError::Connection(message.into())
}
