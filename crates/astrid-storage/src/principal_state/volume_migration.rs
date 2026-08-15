//! Verified cutover from the released directory store to Astrid volume media.

use std::path::Path;
use std::sync::Arc;

use crate::engine::{DurableEnginePolicy, PrincipalCodec, RecoveryLimits, RootSnapshot};
use crate::error::{StorageError, StorageResult};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
use astrid_core::dirs::AstridHome;

use super::{Blake3ObjectIdentityV1, RuntimeEngine, StateOwner, StateOwnerCodecV2};

const CUTOVER_RECEIPT_REGION: &str = "system/migrations/directory-store-to-volume-v1";
const MAX_CUTOVER_RECEIPT_BYTES: u64 = 256;

pub(super) fn open_existing(
    home: &AstridHome,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<Option<RuntimeEngine>> {
    let path = home.storage_volume_path();
    if !path.exists() {
        return Ok(None);
    }
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
    require_cutover_receipt(volume.as_ref())?;
    Ok(Some(engine))
}

pub(super) fn migrate_directory_store(
    home: &AstridHome,
    source: Arc<RuntimeEngine>,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<RuntimeEngine> {
    let snapshots = snapshots(&source)?;
    let destination = home.storage_volume_path();
    let temporary = destination.with_extension("volume.migrating");
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
    super::native_io::sync_directory(home.var_dir().as_path())?;

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
    require_cutover_receipt(volume.as_ref())?;

    source
        .close()
        .map_err(|error| connection(format!("close retired directory store: {error}")))?;
    drop(source);
    retire_directory_store(home.principal_store_path().as_path())?;
    Ok(engine)
}

pub(super) fn retire_verified_directory_if_present(home: &AstridHome) -> StorageResult<()> {
    let path = home.principal_store_path();
    match std::fs::symlink_metadata(&path) {
        Ok(_) => retire_directory_store(&path)?,
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

fn require_cutover_receipt(volume: &dyn AstridVolume) -> StorageResult<()> {
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
    Ok(())
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

fn retire_directory_store(path: &Path) -> StorageResult<()> {
    astrid_core::platform_fs::verify_no_redirects(path)
        .map_err(|error| connection(format!("verify retired directory store: {error}")))?;
    let retired = super::native_io::quarantine_directory(path, "volume-retired")?;
    std::fs::remove_dir_all(&retired).map_err(|error| {
        connection(format!(
            "delete verified directory store {}: {error}",
            retired.display()
        ))
    })?;
    let parent = retired
        .parent()
        .ok_or_else(|| connection("retired directory store has no parent"))?;
    super::native_io::sync_directory(parent)
}

fn connection(message: impl Into<String>) -> StorageError {
    StorageError::Connection(message.into())
}
