//! Durable Windows update transaction validation, persistence, and cleanup.

use std::io::Read as _;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};

use super::{
    MAX_BINARY_BYTES, MAX_RECEIPT_DETAIL_BYTES, MAX_TRANSACTION_BYTES, PENDING_TRANSACTION,
    RECOVERY_ARMED, ReceiptState, STAGE_PREFIX, TRANSACTION, TRANSACTION_SCHEMA_VERSION,
    Transaction, UpdateReceipt, WINDOWS_MANAGED_BINARIES,
};

pub(super) fn cleanup_completed_payload(
    transaction_path: &Path,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    cleanup_staged_payload(transaction_path, transaction)?;
    schedule_delete(&transaction.helper);
    Ok(())
}

pub(super) fn validate_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    validate_transaction_at(path, transaction, TRANSACTION)
}

pub(super) fn validate_pending_transaction(
    path: &Path,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    validate_transaction_at(path, transaction, PENDING_TRANSACTION)
}

pub(super) fn validate_transaction_at(
    path: &Path,
    transaction: &Transaction,
    expected_name: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        transaction.schema_version == TRANSACTION_SCHEMA_VERSION,
        "unsupported Windows update transaction schema"
    );
    anyhow::ensure!(
        transaction.id.len() == 32 && uuid::Uuid::parse_str(&transaction.id).is_ok(),
        "invalid Windows update transaction ID"
    );
    anyhow::ensure!(
        !transaction.target_version.is_empty() && transaction.target_version.len() <= 128,
        "invalid Windows update target version"
    );
    anyhow::ensure!(
        transaction.parent_pid != 0,
        "invalid zero parent process ID"
    );
    anyhow::ensure!(
        transaction.parent_creation_time.0 != 0,
        "invalid zero parent process creation token"
    );
    anyhow::ensure!(
        transaction.entries.len() == WINDOWS_MANAGED_BINARIES.len(),
        "Windows update must contain the complete executable set"
    );
    anyhow::ensure!(
        path == transaction.staging_dir.join(expected_name),
        "transaction is not the canonical file in its staging directory"
    );
    anyhow::ensure!(
        transaction.staging_dir.parent() == Some(transaction.install_dir.as_path()),
        "staging directory is outside its install directory"
    );
    anyhow::ensure!(
        transaction.helper == transaction.staging_dir.join("helper.exe"),
        "helper is not the canonical executable in its staging directory"
    );
    let expected_stage_name = format!("{STAGE_PREFIX}{}", transaction.id);
    anyhow::ensure!(
        transaction.staging_dir.file_name() == Some(std::ffi::OsStr::new(&expected_stage_name)),
        "staging directory is not bound to the transaction ID"
    );
    for (entry, expected_name) in transaction.entries.iter().zip(WINDOWS_MANAGED_BINARIES) {
        anyhow::ensure!(
            entry.name == expected_name,
            "Windows update executable set or replacement order is invalid"
        );
        anyhow::ensure!(
            entry.blake3.len() == 64 && entry.blake3.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Windows update executable digest is invalid"
        );
    }
    Ok(())
}

pub(super) fn copy_and_sync(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut source_file = std::fs::File::open(source)
        .with_context(|| format!("failed to open staged source {}", source.display()))?;
    anyhow::ensure!(
        source_file.metadata()?.len() <= MAX_BINARY_BYTES,
        "{} exceeds update size limit",
        source.display()
    );
    let mut destination_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("failed to stage {}", destination.display()))?;
    std::io::copy(&mut source_file, &mut destination_file)?;
    destination_file.sync_all()?;
    Ok(())
}

pub(super) fn digest_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_BINARY_BYTES,
        "{} exceeds update size limit",
        path.display()
    );
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn write_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(transaction)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    astrid_core::platform_fs::atomic_write_private_file(path, &bytes)?;
    Ok(())
}

pub(super) fn read_transaction(path: &Path) -> anyhow::Result<Transaction> {
    let bytes = astrid_core::platform_fs::read_private_file_to_string(path)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    Ok(serde_json::from_str(&bytes)?)
}

pub(super) fn receipt_path(transaction: &Transaction) -> PathBuf {
    transaction.staging_dir.join("result.json")
}

pub(super) fn bounded_detail(error: &anyhow::Error) -> String {
    let detail = format!("{error:#}");
    if detail.len() <= MAX_RECEIPT_DETAIL_BYTES {
        return detail;
    }
    const TRUNCATION_MARKER: &str = "…";
    let mut end = MAX_RECEIPT_DETAIL_BYTES.saturating_sub(TRUNCATION_MARKER.len());
    while !detail.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut bounded = detail[..end].to_owned();
    bounded.push_str(TRUNCATION_MARKER);
    bounded
}

pub(super) fn receipt_for(
    transaction: &Transaction,
    state: ReceiptState,
    detail: Option<&anyhow::Error>,
) -> UpdateReceipt {
    UpdateReceipt {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: transaction.id.clone(),
        target_version: transaction.target_version.clone(),
        state,
        detail: detail.map(bounded_detail),
        reported: false,
    }
}

pub(super) fn write_receipt(
    transaction: &Transaction,
    receipt: &UpdateReceipt,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(receipt)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update receipt is too large"
    );
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path(transaction), &bytes)?;
    Ok(())
}

pub(super) fn read_receipt(path: &Path) -> anyhow::Result<UpdateReceipt> {
    let bytes = astrid_core::platform_fs::read_private_file_to_string(path)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update receipt is too large"
    );
    Ok(serde_json::from_str(&bytes)?)
}

pub(super) fn cleanup_unlaunched(path: &Path, transaction: &Transaction) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(&transaction.helper);
    let _ = std::fs::remove_dir_all(&transaction.staging_dir);
}

pub(super) fn cleanup_staged_payload(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    for entry in &transaction.entries {
        remove_file_if_exists(&transaction.staging_dir.join(&entry.name)).with_context(|| {
            format!(
                "failed to remove staged Windows update executable {}",
                entry.name
            )
        })?;
    }
    remove_file_if_exists(&transaction.staging_dir.join("armed"))
        .context("failed to remove Windows update armed marker")?;
    remove_file_if_exists(&transaction.staging_dir.join(RECOVERY_ARMED))
        .context("failed to remove Windows update recovery marker")?;
    // Remove the transaction last. If an earlier deletion fails, the durable
    // receipt and transaction retain everything needed for a later retry.
    remove_file_if_exists(path).context("failed to remove Windows update transaction")?;
    Ok(())
}

pub(super) fn cleanup_abandoned_pending(
    pending_path: &Path,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    cleanup_staged_payload(pending_path, transaction)
        .context("failed to clean an abandoned provisional Windows update")?;
    if remove_file_if_exists(&transaction.helper).is_err() {
        // A helper which was already mapped can briefly outlive its parent
        // without owning the stage lock. The provisional authority is gone;
        // schedule only this inert executable remnant for deferred deletion.
        schedule_delete(&transaction.helper);
    }
    Ok(())
}

pub(super) fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn cleanup_stale_stages(install_dir: &Path) -> anyhow::Result<()> {
    let stages = match std::fs::read_dir(install_dir) {
        Ok(stages) => stages,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for stage in stages {
        let stage = stage?;
        let path = stage.path();
        if !stage.file_name().to_str().is_some_and(valid_stage_name) {
            continue;
        }
        anyhow::ensure!(
            stage.file_type()?.is_dir(),
            "Windows update stage is not a directory: {}",
            path.display()
        );
        astrid_core::platform_fs::verify_no_redirects(&path)
            .context("Windows update stage crosses an untrusted filesystem boundary")?;
        cleanup_stale_stage(&path);
    }
    Ok(())
}

pub(super) fn cleanup_stale_stage(stage: &Path) {
    if stage.join(TRANSACTION).exists()
        || stage.join(PENDING_TRANSACTION).exists()
        || stage.join("result.json").exists()
        || !stage_contains_only_cleanup_remnants(stage)
    {
        return;
    }
    let _ = std::fs::remove_dir_all(stage);
}

pub(super) fn valid_stage_name(name: &str) -> bool {
    name.strip_prefix(STAGE_PREFIX)
        .is_some_and(|suffix| suffix.len() == 32 && uuid::Uuid::parse_str(suffix).is_ok())
}

pub(super) fn stage_contains_only_cleanup_remnants(stage: &Path) -> bool {
    let Ok(mut entries) = std::fs::read_dir(stage) else {
        return false;
    };
    entries.all(|entry| {
        entry.is_ok_and(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && matches!(
                    entry.file_name().to_str(),
                    Some(
                        "helper.exe"
                            | "armed"
                            | "recovery-armed"
                            | "helper.lock"
                            | ".astrid-private-write.lock"
                    )
                )
        })
    })
}

pub(super) fn schedule_delete(path: &Path) {
    let path = wide_null(path);
    // SAFETY: source is NUL-terminated; null destination with
    // DELAY_UNTIL_REBOOT requests best-effort deletion at the next reboot.
    // Per-user invocations may be denied this operation, and Windows does not
    // guarantee deferred directory removal, so ordinary CLI invocations also
    // remove validated, transaction-free stage remnants.
    let _ = unsafe { MoveFileExW(path.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

pub(super) fn wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
