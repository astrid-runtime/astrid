//! Exit-time Windows self-update transaction.
//!
//! Windows does not permit replacing the currently executing `astrid.exe`.
//! The verified new CLI is therefore copied to a distinct helper executable.
//! That helper opens and waits on the exact parent process handle, verifies the
//! staged digests again, replaces the daemon first and CLI last, and restores
//! every backup if any replacement fails.

use std::collections::HashSet;
use std::io::Read as _;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

const INTERNAL_MODE: &str = "__complete-windows-update";
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 100 * 1024 * 1024;
const PARENT_EXIT_TIMEOUT_MS: u32 = 5 * 60 * 1_000;
const HELPER_ARM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HELPER_ARM_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const STAGE_PREFIX: &str = ".astrid-update-stage.";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    parent_pid: u32,
    install_dir: PathBuf,
    staging_dir: PathBuf,
    helper: PathBuf,
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    blake3: String,
    cli_entrypoint: bool,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one successful OpenProcess handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn internal_helper_request() -> Option<anyhow::Result<PathBuf>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next()?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(INTERNAL_MODE)) {
        if let Ok(exe) = std::env::current_exe()
            && let Some(install_dir) = exe.parent()
        {
            cleanup_stale_stages(install_dir);
        }
        return None;
    }
    let transaction = arguments.next().map(PathBuf::from).ok_or_else(|| {
        anyhow::anyhow!("internal Windows update helper requires a transaction path")
    });
    Some(transaction.and_then(|path| {
        anyhow::ensure!(
            arguments.next().is_none(),
            "internal Windows update helper received unexpected arguments"
        );
        Ok(path)
    }))
}

pub(super) fn stage_and_launch(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> anyhow::Result<()> {
    anyhow::ensure!(names.len() >= 2, "Windows update requires CLI and daemon");
    cleanup_stale_stages(install_dir);
    for name in names {
        anyhow::ensure!(
            extract_dir.join(name).is_file(),
            "release archive is missing '{name}'"
        );
    }

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let staging_dir = install_dir.join(format!("{STAGE_PREFIX}{nonce}"));
    astrid_core::platform_fs::ensure_private_directory(&staging_dir)
        .context("failed to create private Windows update staging directory")?;

    let mut entries = Vec::with_capacity(names.len());
    let stage_result = (|| -> anyhow::Result<()> {
        for name in names {
            let staged = staging_dir.join(name);
            copy_and_sync(&extract_dir.join(name), &staged)?;
            entries.push(Entry {
                name: (*name).to_owned(),
                blake3: digest_file(&staged)?,
                cli_entrypoint: *name == names[0],
            });
        }
        Ok(())
    })();
    if let Err(error) = stage_result {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    // Publish the CLI entrypoint last. Until then any concurrent invocation
    // still sees the old CLI, and the stopped daemon cannot expose mixed code.
    sort_cli_last(&mut entries);

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
    let transaction_path = staging_dir.join("transaction.json");
    let transaction = Transaction {
        parent_pid: std::process::id(),
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
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            cleanup_unlaunched(&transaction_path, &transaction);
            return Err(error).context("failed to launch Windows update helper");
        },
    };
    if let Err(error) = wait_for_helper_armed(&mut child, &transaction.staging_dir.join("armed")) {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_unlaunched(&transaction_path, &transaction);
        return Err(error);
    }
    Ok(())
}

fn sort_cli_last(entries: &mut [Entry]) {
    entries.sort_by_key(|entry| entry.cli_entrypoint);
}

pub(super) fn complete(transaction_path: &Path) -> anyhow::Result<()> {
    let transaction = read_transaction(transaction_path)?;
    validate_transaction(transaction_path, &transaction)?;
    let result = (|| {
        let parent = open_parent(transaction.parent_pid)?;
        astrid_core::platform_fs::atomic_write_private_file(
            &transaction.staging_dir.join("armed"),
            b"v1\n",
        )
        .context("failed to publish Windows update helper readiness")?;
        wait_for_parent(&parent)?;
        apply_transaction(transaction_path, &transaction)
    })();
    if result.is_err() {
        cleanup_after_helper(transaction_path, &transaction);
    }
    result
}

fn apply_transaction(transaction_path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    for entry in &transaction.entries {
        let staged = transaction.staging_dir.join(&entry.name);
        anyhow::ensure!(
            digest_file(&staged)? == entry.blake3,
            "staged update digest changed for {}",
            staged.display()
        );
    }

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
    .context("failed to replace authenticated Astrid executables")?;

    cleanup_staged_payload(transaction_path, transaction);
    schedule_delete(&transaction.helper);
    schedule_delete(&transaction.staging_dir);
    Ok(())
}

fn open_parent(parent_pid: u32) -> anyhow::Result<OwnedHandle> {
    anyhow::ensure!(parent_pid != 0, "invalid zero parent process ID");
    // SAFETY: scalar process ID and access mask; a successful handle is owned
    // by the wrapper for the exact parent process object, surviving PID reuse.
    let handle = unsafe { OpenProcess(SYNCHRONIZE_ACCESS, 0, parent_pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("failed to open exact parent update process");
    }
    Ok(OwnedHandle(handle))
}

fn wait_for_parent(parent: &OwnedHandle) -> anyhow::Result<()> {
    // SAFETY: the exact parent handle remains owned for this bounded wait.
    anyhow::ensure!(
        unsafe { WaitForSingleObject(parent.0, PARENT_EXIT_TIMEOUT_MS) } == WAIT_OBJECT_0,
        "timed out waiting for the parent updater to exit"
    );
    Ok(())
}

fn wait_for_helper_armed(child: &mut std::process::Child, armed_path: &Path) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + HELPER_ARM_TIMEOUT;
    loop {
        if astrid_core::platform_fs::validate_private_file(armed_path).is_ok()
            && std::fs::read(armed_path).is_ok_and(|contents| contents == b"v1\n")
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Windows update helper exited before arming parent wait: {status}");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for Windows update helper to arm parent wait");
        }
        std::thread::sleep(HELPER_ARM_POLL);
    }
}

fn validate_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    anyhow::ensure!(
        transaction.parent_pid != 0,
        "invalid zero parent process ID"
    );
    anyhow::ensure!(
        transaction.entries.len() >= 2 && transaction.entries.len() <= 8,
        "invalid Windows update entry count"
    );
    anyhow::ensure!(
        path == transaction.staging_dir.join("transaction.json"),
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
    anyhow::ensure!(
        valid_stage_name(
            transaction
                .staging_dir
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default()
        ),
        "staging directory name is invalid"
    );
    let mut names = HashSet::with_capacity(transaction.entries.len());
    anyhow::ensure!(
        transaction.entries.iter().all(|entry| {
            let mut components = Path::new(&entry.name).components();
            matches!(components.next(), Some(std::path::Component::Normal(_)))
                && components.next().is_none()
                && names.insert(entry.name.as_str())
        }),
        "update entry has an invalid or duplicate executable name"
    );
    anyhow::ensure!(
        transaction
            .entries
            .last()
            .is_some_and(|entry| entry.cli_entrypoint)
            && transaction
                .entries
                .iter()
                .filter(|entry| entry.cli_entrypoint)
                .count()
                == 1,
        "CLI entrypoint must be replaced exactly once and last"
    );
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
    let mut buffer = [0_u8; 64 * 1024];
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
    let file = std::fs::File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    let mut bytes = Vec::new();
    file.take(MAX_TRANSACTION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_TRANSACTION_BYTES,
        "Windows update transaction is too large"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn cleanup_unlaunched(path: &Path, transaction: &Transaction) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(&transaction.helper);
    let _ = std::fs::remove_dir_all(&transaction.staging_dir);
}

fn cleanup_after_helper(path: &Path, transaction: &Transaction) {
    cleanup_staged_payload(path, transaction);
    schedule_delete(&transaction.helper);
    schedule_delete(&transaction.staging_dir);
}

fn cleanup_staged_payload(path: &Path, transaction: &Transaction) {
    let _ = std::fs::remove_file(path);
    for entry in &transaction.entries {
        let _ = std::fs::remove_file(transaction.staging_dir.join(&entry.name));
    }
    let _ = std::fs::remove_file(transaction.staging_dir.join("armed"));
}

fn cleanup_stale_stages(install_dir: &Path) {
    let Ok(stages) = std::fs::read_dir(install_dir) else {
        return;
    };
    for stage in stages.filter_map(Result::ok) {
        let path = stage.path();
        if !stage.file_type().is_ok_and(|kind| kind.is_dir())
            || !stage.file_name().to_str().is_some_and(valid_stage_name)
            || path.join("transaction.json").exists()
            || !stage_contains_only_cleanup_remnants(&path)
        {
            continue;
        }
        let _ = std::fs::remove_dir_all(path);
    }
}

fn valid_stage_name(name: &str) -> bool {
    name.strip_prefix(STAGE_PREFIX)
        .is_some_and(|suffix| suffix.len() == 32 && uuid::Uuid::parse_str(suffix).is_ok())
}

fn stage_contains_only_cleanup_remnants(stage: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(stage) else {
        return false;
    };
    entries.filter_map(Result::ok).all(|entry| {
        entry.file_type().is_ok_and(|kind| kind.is_file())
            && matches!(entry.file_name().to_str(), Some("helper.exe" | "armed"))
    })
}

fn schedule_delete(path: &Path) {
    let path = wide_null(path);
    // SAFETY: source is NUL-terminated; null destination with
    // DELAY_UNTIL_REBOOT requests deletion after this helper exits. Normal
    // per-user invocations may be denied this operation, so every ordinary CLI
    // invocation also removes validated, transaction-free stage remnants.
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

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn entry(staging_dir: &Path, name: &str, cli_entrypoint: bool) -> Entry {
        Entry {
            name: name.to_owned(),
            blake3: digest_file(&staging_dir.join(name)).unwrap(),
            cli_entrypoint,
        }
    }

    fn private_staging_dir(install: &Path) -> PathBuf {
        astrid_core::platform_fs::ensure_private_directory(install).unwrap();
        let staging = install.join(TEST_STAGE_NAME);
        astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();
        staging
    }

    fn transaction_path(staging_dir: &Path) -> PathBuf {
        staging_dir.join("transaction.json")
    }

    #[test]
    fn cli_entrypoint_is_ordered_last() {
        let mut entries = vec![
            Entry {
                name: "astrid.exe".to_owned(),
                blake3: String::new(),
                cli_entrypoint: true,
            },
            Entry {
                name: "astrid-daemon.exe".to_owned(),
                blake3: String::new(),
                cli_entrypoint: false,
            },
        ];
        sort_cli_last(&mut entries);
        assert!(!entries[0].cli_entrypoint);
        assert!(entries[1].cli_entrypoint);
    }

    #[test]
    fn parent_wait_tracks_the_exact_child_until_exit() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 2 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        let parent = open_parent(child.id()).unwrap();
        wait_for_parent(&parent).unwrap();
        assert!(child.wait().unwrap().code().is_some());
    }

    #[test]
    fn two_binary_transaction_swaps_daemon_then_cli_and_keeps_backups() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let daemon = install.join("astrid-daemon.exe");
        let daemon_backup = install.join("astrid-daemon.exe.bak");
        let daemon_staged = staging.join("astrid-daemon.exe");
        let cli = install.join("astrid.exe");
        let cli_backup = install.join("astrid.exe.bak");
        let cli_staged = staging.join("astrid.exe");
        write(&daemon, b"old daemon");
        write(&daemon_staged, b"new daemon");
        write(&cli, b"old cli");
        write(&cli_staged, b"new cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            staging_dir: staging.clone(),
            helper: staging.join("helper.exe"),
            entries: vec![
                entry(&staging, "astrid-daemon.exe", false),
                entry(&staging, "astrid.exe", true),
            ],
        };
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();

        apply_transaction(&path, &transaction).unwrap();

        assert_eq!(std::fs::read(&daemon).unwrap(), b"new daemon");
        assert_eq!(std::fs::read(&cli).unwrap(), b"new cli");
        assert_eq!(std::fs::read(&daemon_backup).unwrap(), b"old daemon");
        assert_eq!(std::fs::read(&cli_backup).unwrap(), b"old cli");
    }

    #[test]
    fn digest_tamper_refuses_before_replacing_any_binary() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let daemon = install.join("astrid-daemon.exe");
        let daemon_staged = staging.join("astrid-daemon.exe");
        let cli = install.join("astrid.exe");
        let cli_staged = staging.join("astrid.exe");
        for path in [&daemon, &cli] {
            write(path, b"old");
        }
        write(&daemon_staged, b"verified daemon");
        write(&cli_staged, b"verified cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            staging_dir: staging.clone(),
            helper: staging.join("helper.exe"),
            entries: vec![
                entry(&staging, "astrid-daemon.exe", false),
                entry(&staging, "astrid.exe", true),
            ],
        };
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();
        write(&daemon_staged, b"tampered");

        assert!(
            apply_transaction(&path, &transaction)
                .unwrap_err()
                .to_string()
                .contains("digest")
        );
        assert_eq!(std::fs::read(&daemon).unwrap(), b"old");
        assert_eq!(std::fs::read(&cli).unwrap(), b"old");
    }

    #[test]
    fn invalid_second_target_refuses_before_replacing_first() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = private_staging_dir(install);
        let daemon = install.join("astrid-daemon.exe");
        let daemon_staged = staging.join("astrid-daemon.exe");
        let cli_directory = install.join("astrid.exe");
        let cli_staged = staging.join("astrid.exe");
        write(&daemon, b"old daemon");
        write(&daemon_staged, b"new daemon");
        std::fs::create_dir(&cli_directory).unwrap();
        write(&cli_staged, b"new cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            staging_dir: staging.clone(),
            helper: staging.join("helper.exe"),
            entries: vec![
                entry(&staging, "astrid-daemon.exe", false),
                entry(&staging, "astrid.exe", true),
            ],
        };
        let path = transaction_path(&staging);
        write_transaction(&path, &transaction).unwrap();

        apply_transaction(&path, &transaction).unwrap_err();

        assert_eq!(std::fs::read(&daemon).unwrap(), b"old daemon");
    }

    #[test]
    fn transaction_rejects_staging_directory_outside_install_directory() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = outside.path().join(TEST_STAGE_NAME);
        let transaction = Transaction {
            parent_pid: 1,
            install_dir: install.to_path_buf(),
            staging_dir: staging.clone(),
            helper: staging.join("helper.exe"),
            entries: vec![
                Entry {
                    name: "astrid-daemon.exe".to_owned(),
                    blake3: String::new(),
                    cli_entrypoint: false,
                },
                Entry {
                    name: "astrid.exe".to_owned(),
                    blake3: String::new(),
                    cli_entrypoint: true,
                },
            ],
        };
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
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = install.join(TEST_STAGE_NAME);
        let transaction = Transaction {
            parent_pid: 1,
            install_dir: install.to_path_buf(),
            staging_dir: staging.clone(),
            helper: staging.join("helper.exe"),
            entries: vec![
                Entry {
                    name: "../astrid-daemon.exe".to_owned(),
                    blake3: String::new(),
                    cli_entrypoint: false,
                },
                Entry {
                    name: "astrid.exe".to_owned(),
                    blake3: String::new(),
                    cli_entrypoint: true,
                },
            ],
        };

        assert!(
            validate_transaction(&transaction_path(&staging), &transaction)
                .unwrap_err()
                .to_string()
                .contains("invalid")
        );
    }

    #[test]
    fn next_invocation_removes_completed_stage_remnants_without_admin_rights() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = private_staging_dir(install);
        write(&staging.join("helper.exe"), b"old updater");

        cleanup_stale_stages(install);

        assert!(!staging.exists());
    }

    #[test]
    fn next_invocation_preserves_an_active_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = private_staging_dir(install);
        write(&staging.join("helper.exe"), b"updater");
        write(&staging.join("transaction.json"), b"active");

        cleanup_stale_stages(install);

        assert!(staging.exists());
    }

    #[test]
    fn next_invocation_ignores_unrecognized_stage_directories() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let staging = install.join(".astrid-update-stage.not-a-uuid");
        std::fs::create_dir(&staging).unwrap();
        write(&staging.join("helper.exe"), b"untrusted");

        cleanup_stale_stages(install);

        assert!(staging.exists());
    }
}
