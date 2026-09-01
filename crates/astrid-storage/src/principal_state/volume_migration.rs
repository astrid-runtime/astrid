//! Verified cutover from the released directory store to Astrid volume media.

use std::sync::Arc;

use crate::engine::durable::{
    OwnerObservations, inspect_volume_root_history_without_repair,
    inspect_volume_wal_owners_without_repair,
};
use crate::engine::{
    DurableEnginePolicy, PersistentObjectIdentity, PrincipalCodec, RecoveryLimits, RootSnapshot,
};
use crate::error::{StorageError, StorageResult};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeRegion};
use crate::volume::{HostedArtifactProof, HostedProofDecision, HostedProofPhase};
use astrid_core::dirs::AstridHome;

use super::{
    Blake3ObjectIdentityV1, RuntimeEngine, RuntimeStateOwnerCodecV2, StateOwner, StateOwnerCodecV2,
};

const CUTOVER_RECEIPT_REGION: &str = "system/migrations/directory-store-to-volume-v1";
const MAX_CUTOVER_RECEIPT_BYTES: u64 = 256;

pub(super) fn existing_volume_available(home: &AstridHome) -> StorageResult<bool> {
    let canonical = home.storage_volume_path();
    let legacy = home.legacy_storage_volume_path();
    let canonical_present = inspect_volume_entry(&canonical)?;
    let legacy_present = inspect_volume_entry(&legacy)?;
    if canonical_present && legacy_present {
        return Err(connection(format!(
            "Astrid storage has both canonical and legacy volumes: {} and {}",
            canonical.display(),
            legacy.display()
        )));
    }
    Ok(canonical_present || legacy_present)
}

pub(super) fn open_existing(
    home: &AstridHome,
    policy: DurableEnginePolicy<StateOwner>,
) -> StorageResult<Option<(RuntimeEngine, String)>> {
    let canonical = home.storage_volume_path();
    let legacy = home.legacy_storage_volume_path();
    let canonical_present = inspect_volume_entry(&canonical)?;
    let legacy_present = inspect_volume_entry(&legacy)?;
    if canonical_present && legacy_present {
        return Err(connection(format!(
            "Astrid storage has both canonical and legacy volumes: {} and {}",
            canonical.display(),
            legacy.display()
        )));
    }
    if !canonical_present && !legacy_present {
        return Ok(None);
    }
    let source = legacy_present.then_some(legacy.clone());
    let volume = open_proved_volume(&canonical, source.as_deref())?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
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

fn reject_volume_owners(volume: &Arc<dyn AstridVolume>) -> StorageResult<()> {
    let roots: OwnerObservations<StateOwner> =
        inspect_volume_root_history_without_repair::<StateOwner, StateOwnerCodecV2>(
            volume,
            Blake3ObjectIdentityV1.scheme(),
            &StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .map_err(|error| {
            connection(format!(
                "Astrid storage volume root preflight failed: {error}"
            ))
        })?;
    let wal_owners = inspect_volume_wal_owners_without_repair::<StateOwner, _, _>(
        volume,
        &Blake3ObjectIdentityV1,
        &StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .map_err(|error| {
        connection(format!(
            "Astrid storage volume WAL preflight failed: {error}"
        ))
    })?;
    if roots
        .owners
        .iter()
        .any(|owner| matches!(owner, StateOwner::User(_)))
    {
        return Err(connection(
            "Astrid storage volume contains an explicit user StateOwner; mutation is refused before durable recovery",
        ));
    }
    if wal_owners
        .owners
        .iter()
        .any(|owner| matches!(owner, StateOwner::User(_)))
    {
        return Err(connection(
            "Astrid storage volume contains a user-owned WAL transaction; mutation is refused before durable recovery",
        ));
    }
    if let Some(error) = roots.scan_error.or(wal_owners.scan_error) {
        return Err(connection(format!(
            "Astrid storage volume owner preflight could not prove complete coverage: {error}"
        )));
    }
    Ok(())
}

fn open_proved_volume(
    destination: &std::path::Path,
    legacy: Option<&std::path::Path>,
) -> StorageResult<Arc<HostedFileVolume>> {
    let map_error = |error| {
        connection(format!(
            "inspect Astrid storage volume without repair {}: {error}",
            destination.display()
        ))
    };
    let classify = |phase, artifacts: &[HostedArtifactProof]| {
        for artifact in artifacts {
            let volume: Arc<dyn AstridVolume> = artifact.volume();
            if let Err(error) = reject_volume_owners(&volume) {
                return Ok(HostedProofDecision::Reject(error));
            }
        }
        match phase {
            HostedProofPhase::Artifacts | HostedProofPhase::Selected => {},
        }
        Ok(HostedProofDecision::Accept)
    };
    match HostedFileVolume::open_with_owner_proof(destination, legacy, map_error, classify)? {
        crate::volume::HostedProof::Accepted(volume) => Ok(volume),
        crate::volume::HostedProof::Rejected(error) => Err(error),
    }
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
        // Owner proof must precede any namespace change, including cleanup.
        // A valid-but-unexpected artifact is retained and blocks cutover.
        open_proved_volume(&temporary, None)?;
        return Err(connection(format!(
            "incomplete Astrid volume already exists: {}",
            temporary.display()
        )));
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
        RuntimeStateOwnerCodecV2,
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

    let volume = open_proved_volume(&destination, None)?;
    let engine = RuntimeEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        RuntimeStateOwnerCodecV2,
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
            super::recovery_preflight::directory_store_owners(&path)?;
            let source = RuntimeEngine::open_with_policy(
                &path,
                Blake3ObjectIdentityV1,
                RuntimeStateOwnerCodecV2,
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

pub(super) fn write_cutover_receipt(
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
        material.extend_from_slice(&RuntimeStateOwnerCodecV2.encode(owner));
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
