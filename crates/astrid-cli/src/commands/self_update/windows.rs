//! Exit-time Windows self-update transaction.
//!
//! Windows does not permit replacing the currently executing `astrid.exe`.
//! The verified new CLI is therefore copied to a distinct helper executable.
//! That helper opens and waits on the exact parent process handle, verifies the
//! staged digests again, replaces the daemon first and CLI last, and restores
//! every backup if any replacement fails.

use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

const INTERNAL_MODE: &str = "__complete-windows-update";
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 100 * 1024 * 1024;
const PARENT_EXIT_TIMEOUT_MS: u32 = 5 * 60 * 1_000;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

#[derive(Debug, Serialize, Deserialize)]
struct Transaction {
    parent_pid: u32,
    install_dir: PathBuf,
    helper: PathBuf,
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    staged: PathBuf,
    live: PathBuf,
    backup: Option<PathBuf>,
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
    for name in names {
        anyhow::ensure!(
            extract_dir.join(name).is_file(),
            "release archive is missing '{name}'"
        );
    }

    let nonce = std::process::id();
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let live = install_dir.join(name);
        let backup = live
            .is_file()
            .then(|| install_dir.join(format!("{name}.bak")));
        if let Some(backup) = &backup {
            copy_and_sync(&live, backup)?;
        }
        let staged = install_dir.join(format!(".{name}.new.{nonce}"));
        copy_and_sync(&extract_dir.join(name), &staged)?;
        entries.push(Entry {
            blake3: digest_file(&staged)?,
            staged,
            live,
            backup,
            cli_entrypoint: *name == names[0],
        });
    }
    // Publish the CLI entrypoint last. Until then any concurrent invocation
    // still sees the old CLI, and the stopped daemon cannot expose mixed code.
    sort_cli_last(&mut entries);

    let helper = install_dir.join(format!(".astrid-update-helper.{nonce}.exe"));
    // Run the helper protocol implemented by the currently executing, trusted
    // CLI. A future release is authenticated as update payload, but it is not
    // assumed to retain this private transaction format.
    copy_and_sync(&std::env::current_exe()?, &helper)?;
    let transaction_path = install_dir.join(format!(".astrid-update.{nonce}.json"));
    let transaction = Transaction {
        parent_pid: std::process::id(),
        install_dir: install_dir.to_path_buf(),
        helper: helper.clone(),
        entries,
    };
    write_transaction(&transaction_path, &transaction)?;

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
    if let Err(error) = command.spawn() {
        cleanup_unlaunched(&transaction_path, &transaction);
        return Err(error).context("failed to launch Windows update helper");
    }
    Ok(())
}

fn sort_cli_last(entries: &mut [Entry]) {
    entries.sort_by_key(|entry| entry.cli_entrypoint);
}

pub(super) fn complete(transaction_path: &Path) -> anyhow::Result<()> {
    let transaction = read_transaction(transaction_path)?;
    validate_transaction(transaction_path, &transaction)?;
    wait_for_parent(transaction.parent_pid)?;
    for entry in &transaction.entries {
        anyhow::ensure!(
            digest_file(&entry.staged)? == entry.blake3,
            "staged update digest changed for {}",
            entry.live.display()
        );
    }

    let mut replaced = Vec::new();
    for entry in &transaction.entries {
        if let Err(error) = replace_file(&entry.staged, &entry.live) {
            let rollback = rollback(&transaction.entries, &replaced);
            return Err(error).context(match rollback {
                Ok(()) => format!(
                    "failed to install {}; rollback succeeded",
                    entry.live.display()
                ),
                Err(rollback_error) => format!(
                    "failed to install {}; rollback also failed: {rollback_error:#}",
                    entry.live.display()
                ),
            });
        }
        replaced.push(entry.live.clone());
    }

    let _ = std::fs::remove_file(transaction_path);
    schedule_delete(&transaction.helper);
    Ok(())
}

pub(super) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = wide_null(source);
    let destination = wide_null(destination);
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wait_for_parent(parent_pid: u32) -> anyhow::Result<()> {
    // SAFETY: scalar process ID and access mask; a successful handle is owned
    // by the wrapper for the exact parent process object, surviving PID reuse.
    let handle = unsafe { OpenProcess(SYNCHRONIZE_ACCESS, 0, parent_pid) };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
            == Some(ERROR_INVALID_PARAMETER)
        {
            return Ok(());
        }
        return Err(error).context("failed to open parent update process");
    }
    let handle = OwnedHandle(handle);
    // SAFETY: the exact parent handle remains owned for this bounded wait.
    anyhow::ensure!(
        unsafe { WaitForSingleObject(handle.0, PARENT_EXIT_TIMEOUT_MS) } == WAIT_OBJECT_0,
        "timed out waiting for the parent updater to exit"
    );
    Ok(())
}

fn validate_transaction(path: &Path, transaction: &Transaction) -> anyhow::Result<()> {
    anyhow::ensure!(
        transaction.entries.len() >= 2 && transaction.entries.len() <= 8,
        "invalid Windows update entry count"
    );
    anyhow::ensure!(
        path.parent() == Some(transaction.install_dir.as_path()),
        "transaction is outside its install directory"
    );
    anyhow::ensure!(
        transaction.helper.parent() == Some(transaction.install_dir.as_path()),
        "helper is outside its install directory"
    );
    anyhow::ensure!(
        transaction.entries.iter().all(|entry| entry.staged.parent()
            == Some(transaction.install_dir.as_path())
            && entry.live.parent() == Some(transaction.install_dir.as_path())
            && entry
                .backup
                .as_ref()
                .is_none_or(|backup| backup.parent() == Some(transaction.install_dir.as_path()))),
        "update entry escapes its install directory"
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

fn rollback(entries: &[Entry], replaced: &[PathBuf]) -> anyhow::Result<()> {
    let mut failures = Vec::new();
    for entry in entries.iter().rev() {
        if !replaced.contains(&entry.live) {
            continue;
        }
        let Some(backup) = &entry.backup else {
            if let Err(error) = std::fs::remove_file(&entry.live) {
                failures.push(format!("{}: {error}", entry.live.display()));
            }
            continue;
        };
        if let Err(error) = replace_file(backup, &entry.live) {
            failures.push(format!("{}: {error}", entry.live.display()));
        }
    }
    anyhow::ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

fn copy_and_sync(source: &Path, destination: &Path) -> anyhow::Result<()> {
    std::fs::copy(source, destination)
        .with_context(|| format!("failed to stage {}", destination.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(destination)?
        .sync_all()?;
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
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
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
    for entry in &transaction.entries {
        let _ = std::fs::remove_file(&entry.staged);
    }
}

fn schedule_delete(path: &Path) {
    let path = wide_null(path);
    // SAFETY: source is NUL-terminated; null destination with
    // DELAY_UNTIL_REBOOT requests deletion after this helper exits.
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

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn entry(
        staged: PathBuf,
        live: PathBuf,
        backup: Option<PathBuf>,
        cli_entrypoint: bool,
    ) -> Entry {
        Entry {
            blake3: digest_file(&staged).unwrap(),
            staged,
            live,
            backup,
            cli_entrypoint,
        }
    }

    fn transaction_path(directory: &Path) -> PathBuf {
        directory.join(".astrid-update.test.json")
    }

    #[test]
    fn cli_entrypoint_is_ordered_last() {
        let mut entries = vec![
            Entry {
                staged: "cli-new".into(),
                live: "cli".into(),
                backup: None,
                blake3: String::new(),
                cli_entrypoint: true,
            },
            Entry {
                staged: "daemon-new".into(),
                live: "daemon".into(),
                backup: None,
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
        wait_for_parent(child.id()).unwrap();
        assert!(child.wait().unwrap().code().is_some());
    }

    #[test]
    fn two_binary_transaction_swaps_daemon_then_cli_and_keeps_backups() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let daemon = install.join("astrid-daemon.exe");
        let daemon_backup = install.join("astrid-daemon.exe.bak");
        let daemon_staged = install.join(".astrid-daemon.exe.new");
        let cli = install.join("astrid.exe");
        let cli_backup = install.join("astrid.exe.bak");
        let cli_staged = install.join(".astrid.exe.new");
        write(&daemon, b"old daemon");
        write(&daemon_backup, b"old daemon");
        write(&daemon_staged, b"new daemon");
        write(&cli, b"old cli");
        write(&cli_backup, b"old cli");
        write(&cli_staged, b"new cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            helper: install.join(".gone-helper.exe"),
            entries: vec![
                entry(
                    daemon_staged,
                    daemon.clone(),
                    Some(daemon_backup.clone()),
                    false,
                ),
                entry(cli_staged, cli.clone(), Some(cli_backup.clone()), true),
            ],
        };
        let path = transaction_path(install);
        write_transaction(&path, &transaction).unwrap();

        complete(&path).unwrap();

        assert_eq!(std::fs::read(&daemon).unwrap(), b"new daemon");
        assert_eq!(std::fs::read(&cli).unwrap(), b"new cli");
        assert_eq!(std::fs::read(&daemon_backup).unwrap(), b"old daemon");
        assert_eq!(std::fs::read(&cli_backup).unwrap(), b"old cli");
    }

    #[test]
    fn digest_tamper_refuses_before_replacing_any_binary() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let daemon = install.join("astrid-daemon.exe");
        let daemon_backup = install.join("astrid-daemon.exe.bak");
        let daemon_staged = install.join(".astrid-daemon.exe.new");
        let cli = install.join("astrid.exe");
        let cli_backup = install.join("astrid.exe.bak");
        let cli_staged = install.join(".astrid.exe.new");
        for path in [&daemon, &daemon_backup, &cli, &cli_backup] {
            write(path, b"old");
        }
        write(&daemon_staged, b"verified daemon");
        write(&cli_staged, b"verified cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            helper: install.join(".gone-helper.exe"),
            entries: vec![
                entry(
                    daemon_staged.clone(),
                    daemon.clone(),
                    Some(daemon_backup),
                    false,
                ),
                entry(cli_staged, cli.clone(), Some(cli_backup), true),
            ],
        };
        let path = transaction_path(install);
        write_transaction(&path, &transaction).unwrap();
        write(&daemon_staged, b"tampered");

        assert!(complete(&path).unwrap_err().to_string().contains("digest"));
        assert_eq!(std::fs::read(&daemon).unwrap(), b"old");
        assert_eq!(std::fs::read(&cli).unwrap(), b"old");
    }

    #[test]
    fn failed_second_replace_removes_new_target_that_had_no_backup() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path();
        let daemon = install.join("new-daemon.exe");
        let daemon_staged = install.join(".new-daemon.exe.new");
        let cli_directory = install.join("astrid.exe");
        let cli_staged = install.join(".astrid.exe.new");
        write(&daemon_staged, b"new daemon");
        std::fs::create_dir(&cli_directory).unwrap();
        write(&cli_staged, b"new cli");
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            helper: install.join(".gone-helper.exe"),
            entries: vec![
                entry(daemon_staged, daemon.clone(), None, false),
                entry(cli_staged, cli_directory, None, true),
            ],
        };
        let path = transaction_path(install);
        write_transaction(&path, &transaction).unwrap();

        let error = complete(&path).unwrap_err();

        assert!(error.to_string().contains("rollback succeeded"));
        assert!(
            !daemon.exists(),
            "new target without backup must be removed"
        );
    }

    #[test]
    fn transaction_rejects_paths_outside_install_directory() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let install = directory.path();
        let transaction = Transaction {
            parent_pid: 0,
            install_dir: install.to_path_buf(),
            helper: install.join(".helper.exe"),
            entries: vec![
                Entry {
                    staged: outside.path().join("daemon.new"),
                    live: install.join("daemon.exe"),
                    backup: None,
                    blake3: String::new(),
                    cli_entrypoint: false,
                },
                Entry {
                    staged: install.join("cli.new"),
                    live: install.join("astrid.exe"),
                    backup: None,
                    blake3: String::new(),
                    cli_entrypoint: true,
                },
            ],
        };
        let path = transaction_path(install);

        assert!(
            validate_transaction(&path, &transaction)
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
    }
}
