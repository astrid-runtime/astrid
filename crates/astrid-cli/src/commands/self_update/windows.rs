//! Exit-time Windows self-update transaction.
//!
//! Windows does not permit replacing the currently executing `astrid.exe`.
//! The verified new CLI is therefore copied to a distinct helper executable.
//! The parent publishes only a provisional handoff. The helper promotes it to
//! the canonical recovery transaction while holding the stage lock, opens and
//! waits on the exact parent process handle, verifies the staged digests again,
//! replaces the daemon first and CLI last, and restores every backup if any
//! replacement fails.

use std::io::Read as _;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

const INTERNAL_MODE: &str = "__complete-windows-update";
const INTERNAL_RECOVERY_MODE: &str = "__recover-windows-update";
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024;
const MAX_RECEIPT_DETAIL_BYTES: usize = 4 * 1024;
const MAX_BINARY_BYTES: u64 = 100 * 1024 * 1024;
const PARENT_EXIT_TIMEOUT_MS: u32 = 5 * 60 * 1_000;
const HELPER_ARM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HELPER_ARM_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const HELPER_REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const STAGE_PREFIX: &str = ".astrid-update-stage.";
const STAGE_LOCK: &str = "helper.lock";
const RECOVERY_ARMED: &str = "recovery-armed";
const PENDING_TRANSACTION: &str = "transaction.pending.json";
const TRANSACTION: &str = "transaction.json";
const TRANSACTION_SCHEMA_VERSION: u32 = 2;
const WINDOWS_MANAGED_BINARIES: [&str; 4] = [
    "astrid-daemon.exe",
    "astrid-build.exe",
    "astrid-emit.exe",
    "astrid.exe",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    schema_version: u32,
    transaction_id: String,
    target_version: String,
    parent_pid: u32,
    parent_creation_time: ProcessCreationToken,
    install_dir: PathBuf,
    staging_dir: PathBuf,
    helper: PathBuf,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct ProcessCreationToken(u64);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    blake3: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptState {
    Armed,
    Applying,
    Succeeded,
    FailedBeforeMutation,
    FailedRecovered,
    RecoveryPending,
}

impl ReceiptState {
    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::FailedBeforeMutation | Self::FailedRecovered
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateReceipt {
    schema_version: u32,
    transaction_id: String,
    target_version: String,
    state: ReceiptState,
    detail: Option<String>,
    reported: bool,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one successful OpenProcess handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(super) enum HelperRequest {
    Complete(PathBuf),
    Recover {
        transaction: PathBuf,
        parent_pid: u32,
        parent_creation_time: ProcessCreationToken,
    },
}

pub(super) fn internal_helper_request() -> Option<anyhow::Result<HelperRequest>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next()?;
    match arguments.next().as_deref() {
        Some(mode) if mode == std::ffi::OsStr::new(INTERNAL_MODE) => {
            let transaction = arguments.next().map(PathBuf::from).ok_or_else(|| {
                anyhow::anyhow!("internal Windows update helper requires a transaction path")
            });
            Some(transaction.and_then(|path| {
                anyhow::ensure!(
                    arguments.next().is_none(),
                    "internal Windows update helper received unexpected arguments"
                );
                Ok(HelperRequest::Complete(path))
            }))
        },
        Some(mode) if mode == std::ffi::OsStr::new(INTERNAL_RECOVERY_MODE) => {
            let request = (|| {
                let transaction = arguments.next().map(PathBuf::from).ok_or_else(|| {
                    anyhow::anyhow!("internal Windows update recovery requires a transaction path")
                })?;
                let parent_pid = arguments
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<u32>().ok()))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "internal Windows update recovery requires a parent process ID"
                        )
                    })?;
                let parent_creation_time = arguments
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
                    .map(ProcessCreationToken)
                    .filter(|token| token.0 != 0)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "internal Windows update recovery requires a parent creation token"
                        )
                    })?;
                anyhow::ensure!(
                    arguments.next().is_none(),
                    "internal Windows update recovery received unexpected arguments"
                );
                Ok(HelperRequest::Recover {
                    transaction,
                    parent_pid,
                    parent_creation_time,
                })
            })();
            Some(request)
        },
        _ => None,
    }
}

pub(super) fn run_helper_request(request: HelperRequest) -> anyhow::Result<()> {
    match request {
        HelperRequest::Complete(path) => complete(&path),
        HelperRequest::Recover {
            transaction,
            parent_pid,
            parent_creation_time,
        } => recover(&transaction, parent_pid, parent_creation_time),
    }
}

pub(super) fn stage_and_launch(
    install_dir: &Path,
    extract_dir: &Path,
    target_version: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !target_version.is_empty() && target_version.len() <= 128,
        "Windows update target version is invalid"
    );
    let parent_pid = std::process::id();
    let parent_creation_time = current_process_creation_token()
        .context("failed to bind the Windows update to its exact parent process")?;
    cleanup_stale_stages(install_dir)?;
    for name in WINDOWS_MANAGED_BINARIES {
        anyhow::ensure!(
            extract_dir.join(name).is_file(),
            "release archive is missing '{name}'"
        );
    }

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let staging_dir = install_dir.join(format!("{STAGE_PREFIX}{nonce}"));
    astrid_core::platform_fs::ensure_private_directory(&staging_dir)
        .context("failed to create private Windows update staging directory")?;

    let mut entries = Vec::with_capacity(WINDOWS_MANAGED_BINARIES.len());
    let stage_result = (|| -> anyhow::Result<()> {
        for name in WINDOWS_MANAGED_BINARIES {
            let staged = staging_dir.join(name);
            copy_and_sync(&extract_dir.join(name), &staged)?;
            entries.push(Entry {
                name: name.to_owned(),
                blake3: digest_file(&staged)?,
            });
        }
        Ok(())
    })();
    if let Err(error) = stage_result {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    let helper = staging_dir.join("helper.exe");
    // Run the helper protocol implemented by the currently executing, trusted
    // CLI. A future release is authenticated as update payload, but it is not
    // assumed to retain this private transaction format.
    let current_exe = match std::env::current_exe() {
        Ok(current_exe) => current_exe,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(error).context("failed to resolve current Windows updater");
        },
    };
    if let Err(error) = copy_and_sync(&current_exe, &helper) {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error);
    }
    let transaction_path = staging_dir.join(PENDING_TRANSACTION);
    let transaction = Transaction {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: nonce,
        target_version: target_version.to_owned(),
        parent_pid,
        parent_creation_time,
        install_dir: install_dir.to_path_buf(),
        staging_dir,
        helper: helper.clone(),
        entries,
    };
    if let Err(error) = write_transaction(&transaction_path, &transaction) {
        cleanup_unlaunched(&transaction_path, &transaction);
        return Err(error);
    }

    let mut command = std::process::Command::new(&helper);
    command
        .arg(INTERNAL_MODE)
        .arg(&transaction_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            cleanup_unlaunched(&transaction_path, &transaction);
            return Err(error).context("failed to launch Windows update helper");
        },
    };
    if let Err(error) = wait_for_helper_armed(&mut child, &transaction.staging_dir.join("armed")) {
        if let Err(cleanup_error) = terminate_child_bounded(child) {
            return Err(error.context(format!(
                "the failed Windows update helper could not be reaped; its stage was retained: {cleanup_error:#}"
            )));
        }
        cleanup_unlaunched(&transaction_path, &transaction);
        return Err(error);
    }
    detach_running_child(child)
}

pub(super) fn complete(transaction_path: &Path) -> anyhow::Result<()> {
    let staging_dir = stage_for_named_transaction_path(transaction_path, PENDING_TRANSACTION)?;
    let _stage_lock = acquire_stage_lock(staging_dir, HELPER_ARM_TIMEOUT)?;
    let canonical_path = staging_dir.join(TRANSACTION);
    anyhow::ensure!(
        !canonical_path.exists(),
        "Windows update handoff conflicts with an existing canonical transaction"
    );
    std::fs::rename(transaction_path, &canonical_path)
        .context("failed to publish the canonical Windows update transaction")?;
    let transaction = read_transaction(&canonical_path)?;
    validate_transaction(&canonical_path, &transaction)?;
    let parent = open_parent(transaction.parent_pid, transaction.parent_creation_time)?;
    write_receipt(
        &transaction,
        &receipt_for(&transaction, ReceiptState::Armed, None),
    )
    .context("failed to publish durable Windows update readiness")?;
    astrid_core::platform_fs::atomic_write_private_file(
        &transaction.staging_dir.join("armed"),
        b"v1\n",
    )
    .context("failed to publish Windows update helper readiness")?;
    if let Err(error) = wait_for_parent(&parent).and_then(|()| verify_staged_payload(&transaction))
    {
        write_receipt(
            &transaction,
            &receipt_for(
                &transaction,
                ReceiptState::FailedBeforeMutation,
                Some(&error),
            ),
        )
        .context("failed to preserve the Windows update failure receipt")?;
        cleanup_completed_payload(&canonical_path, &transaction)
            .context("failed to clean the rejected Windows update payload")?;
        return Err(error);
    }

    write_receipt(
        &transaction,
        &receipt_for(&transaction, ReceiptState::Applying, None),
    )
    .context("failed to persist the Windows update applying state")?;
    match replace_transaction(&transaction) {
        Ok(()) => {
            write_receipt(
                &transaction,
                &receipt_for(&transaction, ReceiptState::Succeeded, None),
            )
            .context("executables were installed but the success receipt could not be persisted")?;
            cleanup_completed_payload(&canonical_path, &transaction)
                .context("failed to clean the completed Windows update payload")?;
            Ok(())
        },
        Err(replacement_error) => {
            let replacement_error = anyhow::Error::new(replacement_error)
                .context("failed to replace authenticated Astrid executables");
            match astrid_core::platform_fs::recover_executable_set(&transaction.install_dir) {
                Ok(_) => {
                    write_receipt(
                        &transaction,
                        &receipt_for(
                            &transaction,
                            ReceiptState::FailedRecovered,
                            Some(&replacement_error),
                        ),
                    )
                    .context("failed to preserve the recovered Windows update failure receipt")?;
                    cleanup_completed_payload(&canonical_path, &transaction)
                        .context("failed to clean the recovered Windows update payload")?;
                    Err(replacement_error)
                },
                Err(recovery_error) => {
                    let error = replacement_error.context(format!(
                        "automatic recovery remains pending: {recovery_error}"
                    ));
                    write_receipt(
                        &transaction,
                        &receipt_for(&transaction, ReceiptState::RecoveryPending, Some(&error)),
                    )
                    .context(
                        "recovery remains pending and its durable receipt could not be updated",
                    )?;
                    Err(error)
                },
            }
        },
    }
}

fn acquire_stage_lock(
    staging_dir: &Path,
    timeout: std::time::Duration,
) -> anyhow::Result<std::fs::File> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .context("Windows update stage-lock deadline overflow")?;
    loop {
        match try_acquire_stage_lock(staging_dir)? {
            Some(file) => return Ok(file),
            None => {
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for the active Windows update helper"
                );
                std::thread::sleep(HELPER_ARM_POLL);
            },
        }
    }
}

fn try_acquire_stage_lock(staging_dir: &Path) -> anyhow::Result<Option<std::fs::File>> {
    let lock_path = staging_dir.join(STAGE_LOCK);
    astrid_core::platform_fs::try_acquire_private_file_lock(
        &lock_path,
        "another Windows update helper",
    )
    .with_context(|| {
        format!(
            "failed to acquire private Windows update stage lock {}",
            lock_path.display()
        )
    })
}

fn recover(
    transaction_path: &Path,
    parent_pid: u32,
    parent_creation_time: ProcessCreationToken,
) -> anyhow::Result<()> {
    let staging_dir = stage_for_named_transaction_path(transaction_path, TRANSACTION)?;
    let _stage_lock = acquire_stage_lock(staging_dir, HELPER_ARM_TIMEOUT)?;
    let transaction = read_transaction(transaction_path)?;
    validate_transaction(transaction_path, &transaction)?;
    let parent = open_parent(parent_pid, parent_creation_time)?;
    astrid_core::platform_fs::atomic_write_private_file(
        &transaction.staging_dir.join(RECOVERY_ARMED),
        b"v1\n",
    )
    .context("failed to publish Windows update recovery readiness")?;
    wait_for_parent(&parent)?;

    match astrid_core::platform_fs::recover_executable_set(&transaction.install_dir) {
        Ok(astrid_core::platform_fs::ExecutableRecoveryOutcome::Restored) => {
            let detail = anyhow::anyhow!(
                "an interrupted Windows update was rolled back to the prior executable set"
            );
            write_receipt(
                &transaction,
                &receipt_for(&transaction, ReceiptState::FailedRecovered, Some(&detail)),
            )?;
            cleanup_completed_payload(transaction_path, &transaction)
                .context("failed to clean the recovered Windows update payload")?;
            Ok(())
        },
        Ok(astrid_core::platform_fs::ExecutableRecoveryOutcome::NotNeeded) => {
            let state = if installed_payload_matches(&transaction)? {
                ReceiptState::Succeeded
            } else {
                ReceiptState::FailedRecovered
            };
            let detail = (state == ReceiptState::FailedRecovered).then(|| {
                anyhow::anyhow!(
                    "the interrupted Windows update made no journaled executable changes"
                )
            });
            write_receipt(
                &transaction,
                &receipt_for(&transaction, state, detail.as_ref()),
            )?;
            cleanup_completed_payload(transaction_path, &transaction)
                .context("failed to clean the completed Windows update payload")?;
            Ok(())
        },
        Ok(outcome) => anyhow::bail!(
            "this Astrid CLI cannot safely interpret executable recovery outcome {outcome:?}"
        ),
        Err(recovery_error) => {
            let error = anyhow::Error::new(recovery_error)
                .context("Windows executable recovery remains pending");
            write_receipt(
                &transaction,
                &receipt_for(&transaction, ReceiptState::RecoveryPending, Some(&error)),
            )
            .context("failed to persist the pending Windows recovery receipt")?;
            Err(error)
        },
    }
}

fn installed_payload_matches(transaction: &Transaction) -> anyhow::Result<bool> {
    for entry in &transaction.entries {
        let live = transaction.install_dir.join(&entry.name);
        match digest_file(&live) {
            Ok(digest) if digest == entry.blake3 => {},
            Ok(_) => return Ok(false),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            },
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn stage_for_named_transaction_path<'a>(
    transaction_path: &'a Path,
    expected_name: &str,
) -> anyhow::Result<&'a Path> {
    anyhow::ensure!(
        transaction_path.file_name() == Some(std::ffi::OsStr::new(expected_name)),
        "Windows update transaction path is not canonical"
    );
    let stage = transaction_path
        .parent()
        .context("Windows update transaction has no staging directory")?;
    anyhow::ensure!(
        stage
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(valid_stage_name),
        "Windows update transaction is not in a canonical staging directory"
    );
    astrid_core::platform_fs::verify_no_redirects(stage)
        .context("Windows update stage crosses an untrusted filesystem boundary")?;
    Ok(stage)
}

pub(super) fn reconcile_previous_update() -> anyhow::Result<bool> {
    let executable = std::env::current_exe().context("failed to resolve the Astrid executable")?;
    let install_dir = executable
        .parent()
        .context("Astrid executable has no install directory")?;
    let stages = match std::fs::read_dir(install_dir) {
        Ok(stages) => stages,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("failed to inspect Windows update stages"),
    };
    let mut stage_paths = Vec::new();
    for entry in stages {
        let entry = entry.context("failed to inspect a Windows update stage entry")?;
        if !entry.file_name().to_str().is_some_and(valid_stage_name) {
            continue;
        }
        anyhow::ensure!(
            entry.file_type()?.is_dir(),
            "Windows update stage is not a directory: {}",
            entry.path().display()
        );
        astrid_core::platform_fs::verify_no_redirects(&entry.path())
            .context("Windows update stage crosses an untrusted filesystem boundary")?;
        stage_paths.push(entry.path());
    }
    let mut stages = stage_paths;
    stages.sort();

    let mut recovery = None;
    for stage in stages {
        let stage_lock = match try_acquire_stage_lock(&stage) {
            Ok(Some(stage_lock)) => stage_lock,
            Ok(None) => {
                eprintln!("A Windows update is still being finalized; rerun this command shortly.");
                return Ok(true);
            },
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            },
            Err(error) => return Err(error),
        };
        let result_path = stage.join("result.json");
        let transaction_path = stage.join(TRANSACTION);
        let pending_path = stage.join(PENDING_TRANSACTION);
        if pending_path.exists() {
            anyhow::ensure!(
                !transaction_path.exists() && !result_path.exists(),
                "Windows update stage contains conflicting pending and published state: {}",
                stage.display()
            );
            let transaction = read_transaction(&pending_path).with_context(|| {
                format!(
                    "invalid provisional Windows update transaction at {}",
                    pending_path.display()
                )
            })?;
            validate_pending_transaction(&pending_path, &transaction)?;
            match recorded_process_state(transaction.parent_pid, transaction.parent_creation_time)?
            {
                RecordedProcessState::Alive => {
                    drop(stage_lock);
                    eprintln!(
                        "A Windows update handoff is still being finalized; rerun this command shortly."
                    );
                    return Ok(true);
                },
                RecordedProcessState::Gone => {
                    cleanup_abandoned_pending(&pending_path, &transaction)?;
                    drop(stage_lock);
                    cleanup_stale_stage(&stage);
                    continue;
                },
            }
        }
        if result_path.exists() {
            let receipt = read_receipt(&result_path).with_context(|| {
                format!(
                    "invalid Windows update receipt at {}",
                    result_path.display()
                )
            })?;
            validate_receipt(&stage, &receipt)?;
            if receipt.state.is_terminal() {
                report_terminal_receipt(&stage, &result_path, receipt, stage_lock)?;
                continue;
            }
            anyhow::ensure!(
                transaction_path.exists(),
                "nonterminal Windows update receipt has no recovery transaction at {}",
                stage.display()
            );
        }
        if transaction_path.exists() {
            anyhow::ensure!(
                recovery.is_none(),
                "multiple interrupted Windows updates require recovery; preserved stages: {} and {}",
                recovery
                    .as_ref()
                    .map(|(path, _, _): &(PathBuf, Transaction, std::fs::File)| {
                        path.display().to_string()
                    })
                    .unwrap_or_default(),
                stage.display()
            );
            let transaction = read_transaction(&transaction_path)?;
            validate_transaction(&transaction_path, &transaction)?;
            recovery = Some((transaction_path, transaction, stage_lock));
        } else if !result_path.exists() {
            drop(stage_lock);
            cleanup_stale_stage(&stage);
        } else {
            drop(stage_lock);
        }
    }

    let Some((transaction_path, transaction, stage_lock)) = recovery else {
        return Ok(false);
    };
    launch_recovery_helper(&transaction_path, &transaction, stage_lock)?;
    eprintln!(
        "An interrupted Windows update to v{} is being recovered; rerun this command after recovery completes.",
        transaction.target_version
    );
    Ok(true)
}

fn validate_receipt(stage: &Path, receipt: &UpdateReceipt) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.schema_version == TRANSACTION_SCHEMA_VERSION,
        "unsupported Windows update receipt schema in {}",
        stage.display()
    );
    let expected_id = stage
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|name| name.strip_prefix(STAGE_PREFIX))
        .unwrap_or_default();
    anyhow::ensure!(
        receipt.transaction_id == expected_id,
        "Windows update receipt is not bound to its stage at {}",
        stage.display()
    );
    anyhow::ensure!(
        !receipt.target_version.is_empty() && receipt.target_version.len() <= 128,
        "Windows update receipt target version is invalid"
    );
    anyhow::ensure!(
        receipt
            .detail
            .as_ref()
            .is_none_or(|detail| detail.len() <= MAX_RECEIPT_DETAIL_BYTES + '…'.len_utf8()),
        "Windows update receipt detail is too large"
    );
    Ok(())
}

fn report_terminal_receipt(
    stage: &Path,
    result_path: &Path,
    mut receipt: UpdateReceipt,
    stage_lock: std::fs::File,
) -> anyhow::Result<()> {
    if !receipt.reported {
        match receipt.state {
            ReceiptState::Succeeded => eprintln!(
                "Windows update to v{} completed successfully.",
                receipt.target_version
            ),
            ReceiptState::FailedBeforeMutation | ReceiptState::FailedRecovered => eprintln!(
                "Windows update to v{} failed safely; the prior executable set is active.{}",
                receipt.target_version,
                receipt
                    .detail
                    .as_deref()
                    .map(|detail| format!(" {detail}"))
                    .unwrap_or_default()
            ),
            ReceiptState::Armed | ReceiptState::Applying | ReceiptState::RecoveryPending => {
                unreachable!("terminal receipt reporting received a nonterminal state")
            },
        }
        receipt.reported = true;
        let bytes = serde_json::to_vec(&receipt)?;
        astrid_core::platform_fs::atomic_write_private_file(result_path, &bytes)?;
    }

    let transaction_path = stage.join(TRANSACTION);
    if transaction_path.exists() {
        let transaction = read_transaction(&transaction_path)?;
        validate_transaction(&transaction_path, &transaction)?;
        cleanup_completed_payload(&transaction_path, &transaction)
            .context("failed to clean the terminal Windows update payload")?;
    }
    remove_file_if_exists(result_path)
        .context("failed to remove the reported Windows update receipt")?;
    drop(stage_lock);
    cleanup_stale_stage(stage);
    Ok(())
}

fn launch_recovery_helper(
    transaction_path: &Path,
    transaction: &Transaction,
    stage_lock: std::fs::File,
) -> anyhow::Result<()> {
    let marker = transaction.staging_dir.join(RECOVERY_ARMED);
    match std::fs::remove_file(&marker) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let mut command = std::process::Command::new(&transaction.helper);
    let recovery_parent_creation_time = current_process_creation_token()
        .context("failed to bind Windows recovery to its exact parent process")?;
    command
        .arg(INTERNAL_RECOVERY_MODE)
        .arg(transaction_path)
        .arg(std::process::id().to_string())
        .arg(recovery_parent_creation_time.0.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    let mut child = command
        .spawn()
        .context("failed to launch detached Windows update recovery helper")?;
    drop(stage_lock);
    if let Err(error) =
        wait_for_helper_marker(&mut child, &marker, "Windows update recovery helper")
    {
        if let Err(cleanup_error) = terminate_child_bounded(child) {
            return Err(error.context(format!(
                "the failed Windows update recovery helper could not be reaped: {cleanup_error:#}"
            )));
        }
        return Err(error);
    }
    detach_running_child(child)
}

fn detach_running_child(mut child: std::process::Child) -> anyhow::Result<()> {
    anyhow::ensure!(
        child.try_wait()?.is_none(),
        "detached Windows update helper exited unexpectedly after arming"
    );
    drop(child);
    Ok(())
}

fn verify_staged_payload(transaction: &Transaction) -> anyhow::Result<()> {
    for entry in &transaction.entries {
        let staged = transaction.staging_dir.join(&entry.name);
        anyhow::ensure!(
            digest_file(&staged)? == entry.blake3,
            "staged update digest changed for {}",
            staged.display()
        );
    }
    Ok(())
}

fn replace_transaction(transaction: &Transaction) -> std::io::Result<()> {
    let names = transaction
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    astrid_core::platform_fs::replace_executable_set(
        &transaction.install_dir,
        &transaction.staging_dir,
        &names,
    )
}

#[cfg(test)]
fn apply_transaction(transaction_path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    verify_staged_payload(transaction)?;
    replace_transaction(transaction)
        .context("failed to replace authenticated Astrid executables")?;
    cleanup_completed_payload(transaction_path, transaction)?;
    Ok(())
}

fn cleanup_completed_payload(
    transaction_path: &Path,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    cleanup_staged_payload(transaction_path, transaction)?;
    schedule_delete(&transaction.helper);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordedProcessState {
    Alive,
    Gone,
}

fn open_process_identity(process_id: u32) -> std::io::Result<OwnedHandle> {
    if process_id == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid zero process ID",
        ));
    }
    // SAFETY: scalar process ID and access mask; a successful handle is owned
    // by the wrapper for exact-handle identity queries and waits.
    let handle = unsafe {
        OpenProcess(
            SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

fn process_creation_token(handle: &OwnedHandle) -> std::io::Result<ProcessCreationToken> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: all pointers reference initialized FILETIME storage and the
    // retained handle has PROCESS_QUERY_LIMITED_INFORMATION access.
    if unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if token == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned a zero process creation time",
        ));
    }
    Ok(ProcessCreationToken(token))
}

fn current_process_creation_token() -> anyhow::Result<ProcessCreationToken> {
    let process = open_process_identity(std::process::id())
        .context("failed to open the current Windows process")?;
    process_creation_token(&process).context("failed to query the current Windows process identity")
}

fn open_parent(
    parent_pid: u32,
    expected_creation_time: ProcessCreationToken,
) -> anyhow::Result<OwnedHandle> {
    anyhow::ensure!(
        expected_creation_time.0 != 0,
        "invalid zero parent process creation token"
    );
    let parent =
        open_process_identity(parent_pid).context("failed to open exact parent update process")?;
    let actual_creation_time = process_creation_token(&parent)
        .context("failed to query exact parent update process identity")?;
    anyhow::ensure!(
        actual_creation_time == expected_creation_time,
        "parent update process identity changed before helper handoff"
    );
    Ok(parent)
}

fn recorded_process_state(
    process_id: u32,
    expected_creation_time: ProcessCreationToken,
) -> anyhow::Result<RecordedProcessState> {
    let process = match open_process_identity(process_id) {
        Ok(process) => process,
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => {
            return Ok(RecordedProcessState::Gone);
        },
        Err(error) => {
            return Err(error).context(
                "could not determine whether the provisional Windows update parent is alive",
            );
        },
    };
    let actual_creation_time = process_creation_token(&process)
        .context("failed to query provisional Windows update parent identity")?;
    if actual_creation_time != expected_creation_time {
        return Ok(RecordedProcessState::Gone);
    }
    // SAFETY: the exact process handle remains owned for this zero-duration
    // state probe, so PID reuse cannot alter the result.
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_TIMEOUT => Ok(RecordedProcessState::Alive),
        WAIT_OBJECT_0 => Ok(RecordedProcessState::Gone),
        WAIT_FAILED => Err(std::io::Error::last_os_error())
            .context("failed probing provisional Windows update parent state"),
        other => anyhow::bail!("unexpected provisional parent wait result: {other:#010x}"),
    }
}

fn wait_for_parent(parent: &OwnedHandle) -> anyhow::Result<()> {
    // SAFETY: the exact parent handle remains owned for this bounded wait.
    classify_parent_wait_result(unsafe { WaitForSingleObject(parent.0, PARENT_EXIT_TIMEOUT_MS) })
}

fn classify_parent_wait_result(result: u32) -> anyhow::Result<()> {
    match result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => anyhow::bail!("timed out waiting for the parent updater to exit"),
        WAIT_FAILED => Err(std::io::Error::last_os_error())
            .context("failed waiting for the parent updater to exit"),
        other => anyhow::bail!("unexpected parent updater wait result: {other:#010x}"),
    }
}

fn wait_for_helper_armed(child: &mut std::process::Child, armed_path: &Path) -> anyhow::Result<()> {
    wait_for_helper_marker(child, armed_path, "Windows update helper")
}

fn wait_for_helper_marker(
    child: &mut std::process::Child,
    marker_path: &Path,
    helper_name: &str,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now()
        .checked_add(HELPER_ARM_TIMEOUT)
        .context("Windows update helper arming deadline overflow")?;
    loop {
        if astrid_core::platform_fs::read_private_file_to_string(marker_path)
            .is_ok_and(|contents| contents == "v1\n")
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("{helper_name} exited before arming parent wait: {status}");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {helper_name} to arm parent wait");
        }
        std::thread::sleep(HELPER_ARM_POLL);
    }
}

fn terminate_child_bounded(mut child: std::process::Child) -> anyhow::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Err(kill_error) = child.kill() {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        return Err(kill_error).context("failed to terminate Windows update helper");
    }

    let deadline = std::time::Instant::now()
        .checked_add(HELPER_REAP_TIMEOUT)
        .context("Windows update helper reap deadline overflow")?;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out reaping the terminated Windows update helper"
        );
        std::thread::sleep(HELPER_ARM_POLL);
    }
}

fn validate_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    validate_transaction_at(path, transaction, TRANSACTION)
}

fn validate_pending_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    validate_transaction_at(path, transaction, PENDING_TRANSACTION)
}

fn validate_transaction_at(
    path: &Path,
    transaction: &Transaction,
    expected_name: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        transaction.schema_version == TRANSACTION_SCHEMA_VERSION,
        "unsupported Windows update transaction schema"
    );
    anyhow::ensure!(
        transaction.transaction_id.len() == 32
            && uuid::Uuid::parse_str(&transaction.transaction_id).is_ok(),
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
    let expected_stage_name = format!("{STAGE_PREFIX}{}", transaction.transaction_id);
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

fn copy_and_sync(source: &Path, destination: &Path) -> anyhow::Result<()> {
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

fn digest_file(path: &Path) -> anyhow::Result<String> {
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

fn write_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(transaction)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    astrid_core::platform_fs::atomic_write_private_file(path, &bytes)?;
    Ok(())
}

fn read_transaction(path: &Path) -> anyhow::Result<Transaction> {
    let bytes = astrid_core::platform_fs::read_private_file_to_string(path)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    Ok(serde_json::from_str(&bytes)?)
}

fn receipt_path(transaction: &Transaction) -> PathBuf {
    transaction.staging_dir.join("result.json")
}

fn bounded_detail(error: &anyhow::Error) -> String {
    let detail = format!("{error:#}");
    if detail.len() <= MAX_RECEIPT_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_RECEIPT_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &detail[..end])
}

fn receipt_for(
    transaction: &Transaction,
    state: ReceiptState,
    detail: Option<&anyhow::Error>,
) -> UpdateReceipt {
    UpdateReceipt {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_id: transaction.transaction_id.clone(),
        target_version: transaction.target_version.clone(),
        state,
        detail: detail.map(bounded_detail),
        reported: false,
    }
}

fn write_receipt(transaction: &Transaction, receipt: &UpdateReceipt) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(receipt)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update receipt is too large"
    );
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path(transaction), &bytes)?;
    Ok(())
}

fn read_receipt(path: &Path) -> anyhow::Result<UpdateReceipt> {
    let bytes = astrid_core::platform_fs::read_private_file_to_string(path)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update receipt is too large"
    );
    Ok(serde_json::from_str(&bytes)?)
}

fn cleanup_unlaunched(path: &Path, transaction: &Transaction) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(&transaction.helper);
    let _ = std::fs::remove_dir_all(&transaction.staging_dir);
}

fn cleanup_staged_payload(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
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

fn cleanup_abandoned_pending(pending_path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
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

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn cleanup_stale_stages(install_dir: &Path) -> anyhow::Result<()> {
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

fn cleanup_stale_stage(stage: &Path) {
    if stage.join(TRANSACTION).exists()
        || stage.join(PENDING_TRANSACTION).exists()
        || stage.join("result.json").exists()
        || !stage_contains_only_cleanup_remnants(stage)
    {
        return;
    }
    let _ = std::fs::remove_dir_all(stage);
}

fn valid_stage_name(name: &str) -> bool {
    name.strip_prefix(STAGE_PREFIX)
        .is_some_and(|suffix| suffix.len() == 32 && uuid::Uuid::parse_str(suffix).is_ok())
}

fn stage_contains_only_cleanup_remnants(stage: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(stage) else {
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

fn schedule_delete(path: &Path) {
    let path = wide_null(path);
    // SAFETY: source is NUL-terminated; null destination with
    // DELAY_UNTIL_REBOOT requests best-effort deletion at the next reboot.
    // Per-user invocations may be denied this operation, and Windows does not
    // guarantee deferred directory removal, so ordinary CLI invocations also
    // remove validated, transaction-free stage remnants.
    let _ = unsafe { MoveFileExW(path.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

fn wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_STAGE_NAME: &str = ".astrid-update-stage.00000000000000000000000000000001";
    const TEST_PARENT_ENV: &str = "ASTRID_WINDOWS_UPDATE_UNIT_TEST_PARENT";

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn entry(staging_dir: &Path, name: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            blake3: digest_file(&staging_dir.join(name)).unwrap(),
        }
    }

    fn blank_entries() -> Vec<Entry> {
        WINDOWS_MANAGED_BINARIES
            .iter()
            .map(|name| Entry {
                name: (*name).to_owned(),
                blake3: "0".repeat(64),
            })
            .collect()
    }

    fn transaction(install: &Path, staging: &Path, parent_pid: u32) -> Transaction {
        Transaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            transaction_id: staging
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .and_then(|name| name.strip_prefix(STAGE_PREFIX))
                .unwrap()
                .to_owned(),
            target_version: "1.2.3".to_owned(),
            parent_pid,
            parent_creation_time: ProcessCreationToken(1),
            install_dir: install.to_path_buf(),
            staging_dir: staging.to_path_buf(),
            helper: staging.join("helper.exe"),
            entries: blank_entries(),
        }
    }

    fn private_staging_dir(install: &Path) -> PathBuf {
        astrid_core::platform_fs::ensure_private_directory(install).unwrap();
        let staging = install.join(TEST_STAGE_NAME);
        astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();
        staging
    }

    fn transaction_path(staging_dir: &Path) -> PathBuf {
        staging_dir.join(TRANSACTION)
    }

    fn pending_transaction_path(staging_dir: &Path) -> PathBuf {
        staging_dir.join(PENDING_TRANSACTION)
    }

    fn spawn_test_parent() -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "windows_update_test_parent_unit"])
            .env(TEST_PARENT_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    #[ignore = "leaf process used by Windows updater unit tests"]
    fn windows_update_test_parent_unit() {
        if std::env::var(TEST_PARENT_ENV).as_deref() != Ok("1") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    #[test]
    fn canonical_transaction_replaces_cli_last() {
        assert_eq!(WINDOWS_MANAGED_BINARIES.last(), Some(&"astrid.exe"));
        assert_eq!(
            WINDOWS_MANAGED_BINARIES,
            [
                "astrid-daemon.exe",
                "astrid-build.exe",
                "astrid-emit.exe",
                "astrid.exe"
            ]
        );
    }

    #[test]
    fn transaction_accepts_only_the_versioned_complete_executable_set() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let path = transaction_path(&staging);
        let transaction = transaction(install, &staging, 1);
        validate_transaction(&path, &transaction).unwrap();

        let mut missing = transaction(install, &staging, 1);
        missing.entries.remove(1);
        assert!(
            validate_transaction(&path, &missing)
                .unwrap_err()
                .to_string()
                .contains("complete executable set")
        );

        let mut reordered = transaction(install, &staging, 1);
        reordered.entries.swap(0, 1);
        assert!(
            validate_transaction(&path, &reordered)
                .unwrap_err()
                .to_string()
                .contains("replacement order")
        );

        let mut wrong_schema = transaction(install, &staging, 1);
        wrong_schema.schema_version += 1;
        assert!(
            validate_transaction(&path, &wrong_schema)
                .unwrap_err()
                .to_string()
                .contains("schema")
        );

        let mut wrong_digest = transaction(install, &staging, 1);
        wrong_digest.entries[2].blake3 = "not-a-digest".to_owned();
        assert!(
            validate_transaction(&path, &wrong_digest)
                .unwrap_err()
                .to_string()
                .contains("digest")
        );

        let mut missing_parent_identity = transaction(install, &staging, 1);
        missing_parent_identity.parent_creation_time = ProcessCreationToken(0);
        assert!(
            validate_transaction(&path, &missing_parent_identity)
                .unwrap_err()
                .to_string()
                .contains("creation token")
        );
    }

    #[test]
    fn completion_helper_requires_the_provisional_handoff_path() {
        let directory = crate::test_support::private_tempdir();
        let staging = private_staging_dir(directory.path());
        let canonical_path = transaction_path(&staging);

        assert!(
            complete(&canonical_path)
                .unwrap_err()
                .to_string()
                .contains("not canonical")
        );
    }

    #[test]
    fn stage_lock_reopens_privately_and_excludes_a_second_owner() {
        let directory = crate::test_support::private_tempdir();
        let staging = private_staging_dir(directory.path());

        let first = try_acquire_stage_lock(&staging).unwrap().unwrap();
        assert!(
            try_acquire_stage_lock(&staging).unwrap().is_none(),
            "second updater unexpectedly acquired an owned stage lock"
        );
        drop(first);
        assert!(
            try_acquire_stage_lock(&staging).unwrap().is_some(),
            "private stage lock could not be reopened after owner exit"
        );
    }

    #[test]
    fn parent_wait_tracks_the_exact_child_until_exit() {
        let mut child = spawn_test_parent();
        let identity = process_creation_token(&open_process_identity(child.id()).unwrap()).unwrap();
        let stale_identity = ProcessCreationToken(identity.0.wrapping_add(1));
        assert_eq!(
            recorded_process_state(child.id(), stale_identity).unwrap(),
            RecordedProcessState::Gone,
            "PID reuse identity mismatch was treated as the recorded parent"
        );
        assert!(open_parent(child.id(), stale_identity).is_err());
        let parent = open_parent(child.id(), identity).unwrap();
        wait_for_parent(&parent).unwrap();
        assert!(child.wait().unwrap().code().is_some());
    }

    #[test]
    fn parent_wait_result_distinguishes_timeout_and_api_failure() {
        assert!(classify_parent_wait_result(WAIT_OBJECT_0).is_ok());
        assert!(
            classify_parent_wait_result(WAIT_TIMEOUT)
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(
            classify_parent_wait_result(WAIT_FAILED)
                .unwrap_err()
                .to_string()
                .contains("failed waiting")
        );
        assert!(
            classify_parent_wait_result(7)
                .unwrap_err()
                .to_string()
                .contains("unexpected parent updater wait result")
        );
    }

    #[test]
    fn complete_transaction_swaps_all_binaries_and_keeps_backups() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        for name in WINDOWS_MANAGED_BINARIES {
            write(&install.join(name), format!("old {name}").as_bytes());
            write(&staging.join(name), format!("new {name}").as_bytes());
        }
        let mut transaction = transaction(install, &staging, 1);
        transaction.entries = WINDOWS_MANAGED_BINARIES
            .iter()
            .map(|name| entry(&staging, name))
            .collect();
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();

        apply_transaction(&path, &transaction).unwrap();

        for name in WINDOWS_MANAGED_BINARIES {
            assert_eq!(
                std::fs::read(install.join(name)).unwrap(),
                format!("new {name}").as_bytes()
            );
            assert_eq!(
                std::fs::read(install.join(format!("{name}.bak"))).unwrap(),
                format!("old {name}").as_bytes()
            );
        }
    }

    #[test]
    fn digest_tamper_refuses_before_replacing_any_binary() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        for name in WINDOWS_MANAGED_BINARIES {
            write(&install.join(name), b"old");
            write(&staging.join(name), format!("verified {name}").as_bytes());
        }
        let mut transaction = transaction(install, &staging, 1);
        transaction.entries = WINDOWS_MANAGED_BINARIES
            .iter()
            .map(|name| entry(&staging, name))
            .collect();
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();
        write(&staging.join("astrid-build.exe"), b"tampered");

        assert!(
            apply_transaction(&path, &transaction)
                .unwrap_err()
                .to_string()
                .contains("digest")
        );
        for name in WINDOWS_MANAGED_BINARIES {
            assert_eq!(std::fs::read(install.join(name)).unwrap(), b"old");
        }
    }

    #[test]
    fn invalid_second_target_refuses_before_replacing_first() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        for name in WINDOWS_MANAGED_BINARIES {
            write(&staging.join(name), format!("new {name}").as_bytes());
            if name == "astrid-build.exe" {
                std::fs::create_dir(install.join(name)).unwrap();
            } else {
                write(&install.join(name), format!("old {name}").as_bytes());
            }
        }
        let mut transaction = transaction(install, &staging, 1);
        transaction.entries = WINDOWS_MANAGED_BINARIES
            .iter()
            .map(|name| entry(&staging, name))
            .collect();
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();

        apply_transaction(&path, &transaction).unwrap_err();

        assert_eq!(
            std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
            b"old astrid-daemon.exe"
        );
    }

    #[test]
    fn detached_completion_persists_success_before_cleanup() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        for name in WINDOWS_MANAGED_BINARIES {
            write(&install.join(name), format!("old {name}").as_bytes());
            write(&staging.join(name), format!("new {name}").as_bytes());
        }
        let mut parent = spawn_test_parent();
        let mut transaction = transaction(install, &staging, parent.id());
        transaction.parent_creation_time =
            process_creation_token(&open_process_identity(parent.id()).unwrap()).unwrap();
        transaction.entries = WINDOWS_MANAGED_BINARIES
            .iter()
            .map(|name| entry(&staging, name))
            .collect();
        let path = pending_transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();

        complete(&path).unwrap();
        let _ = parent.wait().unwrap();

        let receipt = read_receipt(&receipt_path(&transaction)).unwrap();
        assert_eq!(receipt.state, ReceiptState::Succeeded);
        assert!(!receipt.reported);
        assert!(!path.exists());
        for name in WINDOWS_MANAGED_BINARIES {
            assert_eq!(
                std::fs::read(install.join(name)).unwrap(),
                format!("new {name}").as_bytes()
            );
            assert_eq!(
                std::fs::read(install.join(format!("{name}.bak"))).unwrap(),
                format!("old {name}").as_bytes()
            );
        }
    }

    #[test]
    fn terminal_receipt_survives_until_next_invocation_reports_it() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let transaction = transaction(install, &staging, 1);
        let result_path = receipt_path(&transaction);
        write(&staging.join("helper.exe"), b"retired updater");
        write_receipt(
            &transaction,
            &receipt_for(&transaction, ReceiptState::Succeeded, None),
        )
        .unwrap();

        cleanup_stale_stages(install).unwrap();
        assert!(result_path.exists());

        let receipt = read_receipt(&result_path).unwrap();
        let stage_lock = try_acquire_stage_lock(&staging).unwrap().unwrap();
        report_terminal_receipt(&staging, &result_path, receipt, stage_lock).unwrap();
        assert!(!staging.exists());
    }

    #[test]
    fn terminal_cleanup_failure_retains_receipt_and_transaction_for_retry() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let transaction = transaction(install, &staging, 1);
        let transaction_path = transaction_path(&staging);
        let result_path = receipt_path(&transaction);
        write_transaction(&transaction_path, &transaction).unwrap();
        write_receipt(
            &transaction,
            &receipt_for(&transaction, ReceiptState::Succeeded, None),
        )
        .unwrap();
        // A directory at a staged executable path makes file removal fail on
        // Windows. The transaction must remain because cleanup removes it last.
        std::fs::create_dir(staging.join(WINDOWS_MANAGED_BINARIES[0])).unwrap();

        let receipt = read_receipt(&result_path).unwrap();
        let stage_lock = try_acquire_stage_lock(&staging).unwrap().unwrap();
        report_terminal_receipt(&staging, &result_path, receipt, stage_lock).unwrap_err();

        assert!(
            result_path.exists(),
            "durable result evidence was discarded"
        );
        assert!(
            transaction_path.exists(),
            "cleanup discarded the transaction needed for a later retry"
        );
        assert!(
            read_receipt(&result_path).unwrap().reported,
            "cleanup retry evidence did not preserve its reporting state"
        );
    }

    #[test]
    fn transaction_rejects_staging_directory_outside_install_directory() {
        let directory = crate::test_support::private_tempdir();
        let outside = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = outside.path().join(TEST_STAGE_NAME);
        let transaction = transaction(install, &staging, 1);
        let path = transaction_path(&staging);

        assert!(
            validate_transaction(&path, &transaction)
                .unwrap_err()
                .to_string()
                .contains("outside its install directory")
        );
    }

    #[test]
    fn transaction_rejects_executable_name_with_parent_traversal() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = install.join(TEST_STAGE_NAME);
        let mut transaction = transaction(install, &staging, 1);
        transaction.entries[0].name = "../astrid-daemon.exe".to_owned();

        assert!(
            validate_transaction(&transaction_path(&staging), &transaction)
                .unwrap_err()
                .to_string()
                .contains("invalid")
        );
    }

    #[test]
    fn next_invocation_removes_completed_stage_remnants_without_admin_rights() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        write(&staging.join("helper.exe"), b"old updater");

        cleanup_stale_stages(install).unwrap();

        assert!(!staging.exists());
    }

    #[test]
    fn next_invocation_preserves_an_active_transaction() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        write(&staging.join("helper.exe"), b"updater");
        write(&staging.join(TRANSACTION), b"active");

        cleanup_stale_stages(install).unwrap();

        assert!(staging.exists());
    }

    #[test]
    fn next_invocation_preserves_a_pending_transaction_handoff() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = private_staging_dir(install);
        write(&staging.join("helper.exe"), b"updater");
        write(&staging.join(PENDING_TRANSACTION), b"pending");

        cleanup_stale_stages(install).unwrap();

        assert!(staging.exists());
    }

    #[test]
    fn next_invocation_ignores_unrecognized_stage_directories() {
        let directory = crate::test_support::private_tempdir();
        let install = directory.path();
        let staging = install.join(".astrid-update-stage.not-a-uuid");
        std::fs::create_dir(&staging).unwrap();
        write(&staging.join("helper.exe"), b"untrusted");

        cleanup_stale_stages(install).unwrap();

        assert!(staging.exists());
    }
}
