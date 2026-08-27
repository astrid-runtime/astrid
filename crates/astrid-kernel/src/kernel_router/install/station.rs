//! Station-bound artifact staging and lock commit.
//!
//! The caller's archive is opened once, rejected when it is a symlink or not
//! a regular file, hashed while it is copied into daemon-owned private
//! storage, and never reopened from the caller path. The Station lock that
//! names those bytes commits in the same owner/capsule critical section as
//! the package mutation, guarded by [`crate::Kernel::lock_capsule_view`].

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use astrid_core::kernel_api::StationInstallBinding;
use astrid_core::principal::PrincipalId;

use super::super::admin::station_store;
use crate::Kernel;

const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Deterministic test hook fired after the caller fd is pinned but before the
/// staging copy begins, so regression tests can mutate the caller path
/// mid-operation and prove the staged bytes stay verified-original.
#[cfg(test)]
pub(super) mod stage_gate {
    use std::sync::Mutex;

    static WAITERS: Mutex<Vec<tokio::sync::oneshot::Receiver<()>>> = Mutex::new(Vec::new());

    pub(crate) fn arm(receiver: tokio::sync::oneshot::Receiver<()>) {
        WAITERS.lock().unwrap().push(receiver);
    }

    pub(crate) async fn before_stage() {
        let waiter = WAITERS.lock().unwrap().pop();
        if let Some(waiter) = waiter {
            let _ = waiter.await;
        }
    }
}

/// Owner/capsule guard held from expectation verification through lock
/// commit. Dropping the lease releases the view mutex.
pub(super) struct StationLease {
    // Held for its Drop release of the owner/capsule critical section.
    #[expect(dead_code)]
    view_guard: crate::CapsuleViewGuard,
    previous_physical: Option<Vec<u8>>,
}

/// Daemon-private retained copy of the verified artifact bytes.
pub(super) struct StagedArchive {
    pub(super) file: tempfile::NamedTempFile,
    pub(super) source_blake3: String,
}

fn validate_binding(binding: &StationInstallBinding) -> Result<(), String> {
    if binding.lock.coordinate.name != binding.capsule {
        return Err(
            "Station install binding capsule disagrees with the lock coordinate".to_owned(),
        );
    }
    station_store::validate_station_lock(binding.lock.as_ref())?;
    if let Some(expected_hash) = &binding.expected_hash
        && !station_store::is_blake3_digest(expected_hash)
    {
        return Err("expected_hash must be a canonical blake3:<64-hex> digest".to_owned());
    }
    Ok(())
}

/// Acquire the owner/capsule guard, verify the expected prior lock state, and
/// stage the exact locked artifact bytes into private storage.
pub(super) async fn acquire_verified(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    binding: &StationInstallBinding,
    source: &Path,
) -> Result<(StationLease, StagedArchive), String> {
    validate_binding(binding)?;
    let capsule_id = station_store::parse_capsule_id(&binding.capsule)?;
    let view_guard = kernel.lock_capsule_view(principal, &capsule_id).await;
    let store = station_store::principal_control_store(kernel, principal)?;
    let previous_physical = station_store::read_physical(&store, binding.capsule.as_str()).await?;
    let current_hash = station_store::logical_state(previous_physical.as_ref());
    let mismatch = match (binding.expected_hash.as_deref(), current_hash.as_deref()) {
        (None, None) => None,
        (Some(expected), Some(current)) if expected == current => None,
        (None, Some(current)) => Some(format!(
            "Station lock for '{}' already exists ({current}); absence was required",
            binding.capsule
        )),
        (Some(_), _) => Some(format!(
            "Station lock changed; retry with a fresh expected_hash for '{}'",
            binding.capsule
        )),
    };
    if let Some(message) = mismatch {
        return Err(message);
    }

    #[cfg(test)]
    stage_gate::before_stage().await;

    let staged_source = source.to_path_buf();
    let artifact_size = binding.lock.artifact_size;
    let expected_sha256 = binding.lock.artifact_sha256.clone();
    let expected_blake3 = binding.lock.artifact_blake3.clone();
    let expected_name = binding.lock.coordinate.name.clone();
    let expected_version = binding.lock.version.clone();
    let staged = tokio::task::spawn_blocking(move || {
        stage_once(
            &staged_source,
            artifact_size,
            &expected_sha256,
            &expected_blake3,
            &expected_name,
            &expected_version,
        )
    })
    .await
    .map_err(|error| format!("station staging task panicked: {error}"))?
    .map_err(|error| error.to_string())?;
    Ok((
        StationLease {
            view_guard,
            previous_physical,
        },
        staged,
    ))
}

/// Persist the bound lock exactly once at commit time. Runs while the lease
/// still holds the owner/capsule guard; the prior physical bytes captured
/// under that guard authorize this compare-and-swap.
pub(super) async fn commit(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    binding: &StationInstallBinding,
    lease: StationLease,
) -> Result<(), String> {
    let encoded = station_store::encode_lock(binding.lock.as_ref())?;
    let store = station_store::principal_control_store(kernel, principal)?;
    let applied = station_store::compare_and_swap_write(
        &store,
        binding.capsule.as_str(),
        lease.previous_physical.as_deref(),
        encoded,
    )
    .await?;
    if !applied {
        return Err(format!(
            "committing the '{}' Station lock lost a concurrent update; retry the install",
            binding.capsule
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum StageError {
    Io(String),
    Rejected(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "stage Station artifact: {message}"),
            Self::Rejected(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for StageError {}

fn stage_once(
    source: &Path,
    expected_size: u64,
    expected_sha256: &str,
    expected_blake3: &str,
    expected_name: &str,
    expected_version: &str,
) -> Result<StagedArchive, StageError> {
    use sha2::Digest as _;

    // The fast path rejects an obvious symlink before opening; the fstat on
    // the opened descriptor is authoritative against races afterwards.
    let pre_metadata = std::fs::symlink_metadata(source)
        .map_err(|error| StageError::Io(format!("{}: {error}", source.display())))?;
    if pre_metadata.file_type().is_symlink() {
        return Err(StageError::Rejected(format!(
            "Station artifact must be a regular file, not a symlink: {}",
            source.display()
        )));
    }
    let mut input = std::fs::File::open(source)
        .map_err(|error| StageError::Io(format!("open {}: {error}", source.display())))?;
    let opened_metadata = input
        .metadata()
        .map_err(|error| StageError::Io(format!("fstat {}: {error}", source.display())))?;
    if !opened_metadata.is_file() {
        return Err(StageError::Rejected(format!(
            "Station artifact must be a regular file: {}",
            source.display()
        )));
    }
    if opened_metadata.len() != expected_size
        || opened_metadata.len() > station_store::MAX_ARTIFACT_BYTES
    {
        return Err(StageError::Rejected(
            "Station artifact size disagrees with the lock or exceeds the size limit".to_owned(),
        ));
    }

    let mut staged = tempfile::Builder::new()
        .prefix("astrid-station-install-")
        .suffix(".capsule")
        .tempfile()
        .map_err(|error| StageError::Io(format!("create private staged archive: {error}")))?;
    let mut sha256 = sha2::Sha256::new();
    let mut blake3_hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| StageError::Io(format!("read {}: {error}", source.display())))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| StageError::Rejected("Station artifact size overflow".to_owned()))?;
        if total > station_store::MAX_ARTIFACT_BYTES {
            return Err(StageError::Rejected(format!(
                "Station artifact exceeds the {}-byte size limit",
                station_store::MAX_ARTIFACT_BYTES
            )));
        }
        staged
            .as_file_mut()
            .write_all(&buffer[..read])
            .map_err(|error| StageError::Io(format!("write staged archive: {error}")))?;
        sha256.update(&buffer[..read]);
        blake3_hasher.update(&buffer[..read]);
    }
    staged
        .as_file_mut()
        .sync_all()
        .map_err(|error| StageError::Io(format!("sync staged archive: {error}")))?;
    if total != expected_size {
        return Err(StageError::Rejected(
            "Station artifact size disagrees with the lock".to_owned(),
        ));
    }
    let actual_sha256 = format!("sha256:{}", hex::encode(sha256.finalize()));
    let actual_blake3 = format!("blake3:{}", blake3_hasher.finalize().to_hex());
    if actual_sha256 != expected_sha256 {
        return Err(StageError::Rejected(
            "Station artifact SHA-256 disagrees with the lock".to_owned(),
        ));
    }
    if actual_blake3 != expected_blake3 {
        return Err(StageError::Rejected(
            "Station artifact BLAKE3 disagrees with the lock".to_owned(),
        ));
    }
    verify_manifest_binding(staged.path(), expected_name, expected_version)?;
    Ok(StagedArchive {
        file: staged,
        source_blake3: actual_blake3,
    })
}

fn verify_manifest_binding(
    staged_path: &Path,
    expected_name: &str,
    expected_version: &str,
) -> Result<(), StageError> {
    let manifest = astrid_capsule_install::read_archive_manifest(staged_path).map_err(|error| {
        StageError::Rejected(format!("validate Station archive manifest: {error:#}"))
    })?;
    if manifest.package.name != expected_name {
        return Err(StageError::Rejected(
            "Station lock capsule name disagrees with the archive manifest".to_owned(),
        ));
    }
    let built_version = manifest.package.version.clone();
    if built_version != *expected_version {
        return Err(StageError::Rejected(
            "Station lock version disagrees with the archive manifest".to_owned(),
        ));
    }
    Ok(())
}
