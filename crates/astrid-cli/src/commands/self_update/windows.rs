//! Exit-time Windows self-update transaction.
//!
//! Windows does not permit replacing the currently executing `astrid.exe`.
//! The verified new CLI is therefore copied to a distinct helper executable.
//! The parent publishes only a provisional handoff. The helper promotes it to
//! the canonical recovery transaction while holding the stage lock, opens and
//! waits on the exact parent process handle, verifies the staged digests again,
//! replaces the daemon first and CLI last, and restores every backup if any
//! replacement fails.

use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

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
    #[serde(rename = "transaction_id")]
    id: String,
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
        id: nonce,
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
        if let Some(file) = try_acquire_stage_lock(staging_dir)? {
            return Ok(file);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the active Windows update helper"
        );
        std::thread::sleep(HELPER_ARM_POLL);
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
            finish_recovery_without_journal(transaction_path, &transaction)
        },
        Ok(outcome) => anyhow::bail!(
            "this Astrid CLI cannot safely interpret executable recovery outcome {outcome:?}"
        ),
        Err(recovery_error) => {
            let error = anyhow::Error::new(recovery_error)
                .context("Windows executable recovery remains pending");
            preserve_recovery_pending(&transaction, error)
        },
    }
}

fn finish_recovery_without_journal(
    transaction_path: &Path,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    let state = match installed_payload_matches(transaction) {
        Ok(true) => ReceiptState::Succeeded,
        Ok(false) => ReceiptState::FailedBeforeMutation,
        Err(error) => {
            return preserve_recovery_pending(
                transaction,
                error.context(
                    "could not determine the installed payload after Windows update recovery",
                ),
            );
        },
    };
    let detail = (state == ReceiptState::FailedBeforeMutation).then(|| {
        anyhow::anyhow!("the interrupted Windows update made no journaled executable changes")
    });
    write_receipt(
        transaction,
        &receipt_for(transaction, state, detail.as_ref()),
    )?;
    cleanup_completed_payload(transaction_path, transaction)
        .context("failed to clean the completed Windows update payload")
}

fn preserve_recovery_pending(
    transaction: &Transaction,
    error: anyhow::Error,
) -> anyhow::Result<()> {
    if let Err(persistence_error) = write_receipt(
        transaction,
        &receipt_for(transaction, ReceiptState::RecoveryPending, Some(&error)),
    ) {
        return Err(persistence_error.context(format!(
            "failed to persist the pending Windows recovery receipt; \
             original recovery error: {error:#}"
        )));
    }
    Err(error)
}

fn installed_payload_matches(transaction: &Transaction) -> anyhow::Result<bool> {
    let mut all_match = true;
    for entry in &transaction.entries {
        let live = transaction.install_dir.join(&entry.name);
        if digest_file(&live)? != entry.blake3 {
            all_match = false;
        }
    }
    Ok(all_match)
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

type PendingRecovery = (PathBuf, Transaction, std::fs::File);

fn update_stage_paths(install_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let stages = match std::fs::read_dir(install_dir) {
        Ok(stages) => stages,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("failed to inspect Windows update stages"),
    };
    let mut paths = Vec::new();
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
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

fn reconcile_stage(stage: &Path, recovery: &mut Option<PendingRecovery>) -> anyhow::Result<bool> {
    let stage_lock = match try_acquire_stage_lock(stage) {
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
            return Ok(false);
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
        match recorded_process_state(transaction.parent_pid, transaction.parent_creation_time)? {
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
                cleanup_stale_stage(stage);
                return Ok(false);
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
        validate_receipt(stage, &receipt)?;
        if receipt.state.is_terminal() {
            report_terminal_receipt(stage, &result_path, receipt, stage_lock)?;
            return Ok(false);
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
                .map(|(path, _, _)| path.display().to_string())
                .unwrap_or_default(),
            stage.display()
        );
        let transaction = read_transaction(&transaction_path)?;
        validate_transaction(&transaction_path, &transaction)?;
        *recovery = Some((transaction_path, transaction, stage_lock));
    } else if !result_path.exists() {
        drop(stage_lock);
        cleanup_stale_stage(stage);
    } else {
        drop(stage_lock);
    }
    Ok(false)
}

pub(super) fn reconcile_previous_update() -> anyhow::Result<bool> {
    let executable = std::env::current_exe().context("failed to resolve the Astrid executable")?;
    let install_dir = executable
        .parent()
        .context("Astrid executable has no install directory")?;
    let mut recovery = None;
    for stage in update_stage_paths(install_dir)? {
        if reconcile_stage(&stage, &mut recovery)? {
            return Ok(true);
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
            .is_none_or(|detail| detail.len() <= MAX_RECEIPT_DETAIL_BYTES),
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

#[path = "windows/process.rs"]
mod process;
#[path = "windows/storage.rs"]
mod storage;

use process::{
    RecordedProcessState, current_process_creation_token, open_parent, recorded_process_state,
    terminate_child_bounded, wait_for_helper_armed, wait_for_helper_marker, wait_for_parent,
};
#[cfg(test)]
use process::{classify_parent_wait_result, open_process_identity, process_creation_token};
#[cfg(test)]
use storage::receipt_path;
use storage::{
    cleanup_abandoned_pending, cleanup_completed_payload, cleanup_stale_stage,
    cleanup_stale_stages, cleanup_unlaunched, copy_and_sync, digest_file, read_receipt,
    read_transaction, receipt_for, remove_file_if_exists, valid_stage_name,
    validate_pending_transaction, validate_transaction, write_receipt, write_transaction,
};

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
