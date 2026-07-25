#![cfg(windows)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

const BINARIES: [&str; 4] = [
    "astrid-daemon.exe",
    "astrid-build.exe",
    "astrid-emit.exe",
    "astrid.exe",
];
const TEST_PARENT_ENV: &str = "ASTRID_WINDOWS_UPDATE_TEST_PARENT";
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_DIAGNOSTIC_BYTES: u64 = 16_384;
const MAX_DIAGNOSTIC_ENTRIES: usize = 64;
const MAX_DIRECTORY_DIAGNOSTIC_BYTES: usize = 8_192;
static UPDATER_INTEGRATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Serialize)]
struct Transaction {
    schema_version: u32,
    #[serde(rename = "transaction_id")]
    id: String,
    target_version: String,
    parent_pid: u32,
    parent_creation_time: u64,
    install_dir: PathBuf,
    staging_dir: PathBuf,
    helper: PathBuf,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    blake3: String,
}

#[derive(Serialize)]
struct Receipt {
    schema_version: u32,
    transaction_id: String,
    target_version: String,
    state: &'static str,
    detail: Option<String>,
    reported: bool,
}

struct DirectoryGuard(PathBuf);

impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(std::process::Child);

struct ProcessHandle(HANDLE);

fn updater_integration_guard() -> std::sync::MutexGuard<'static, ()> {
    UPDATER_INTEGRATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// Exact handle ownership requires one audited Win32 close at this FFI edge.
#[allow(unsafe_code)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: this guard owns one successful OpenProcess handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = terminate_child_bounded_sync(&mut self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    astrid_core::platform_fs::atomic_write_private_file(path, bytes).unwrap();
}

fn wait_for_private_marker(path: &Path, expected: &str, timeout: Duration) {
    let deadline = deadline_after(timeout);
    loop {
        if astrid_core::platform_fs::read_private_file_to_string(path)
            .is_ok_and(|contents| contents == expected)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_child(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = deadline_after(timeout);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_child_bounded_sync(child);
            panic!("timed out waiting for Windows update helper; cleanup result: {cleanup:?}");
        }
        std::thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn open_private_stderr(path: &Path) -> std::fs::File {
    write_private(path, b"");
    std::fs::OpenOptions::new().append(true).open(path).unwrap()
}

fn read_bounded_diagnostic(path: &Path) -> String {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return format!("<failed to open {}: {error}>", path.display()),
    };
    let length = file.metadata().map(|metadata| metadata.len()).ok();
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_DIAGNOSTIC_BYTES);
    if let Err(error) = limited.read_to_end(&mut bytes) {
        return format!("<failed to read {}: {error}>", path.display());
    }
    let suffix = if length.is_some_and(|length| length > MAX_DIAGNOSTIC_BYTES) {
        "\n<truncated>"
    } else {
        ""
    };
    format!("{}{suffix}", String::from_utf8_lossy(&bytes))
}

fn path_diagnostic(path: &Path) -> String {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_file() {
                "file"
            } else if file_type.is_dir() {
                "directory"
            } else if file_type.is_symlink() {
                "symlink"
            } else {
                "other"
            };
            format!("{kind}:{}", metadata.len())
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) => format!("metadata-error:{error}"),
    }
}

fn directory_diagnostic(path: &Path) -> String {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => return format!("<failed to read {}: {error}>", path.display()),
    };
    let mut snapshot = entries
        .take(MAX_DIAGNOSTIC_ENTRIES.saturating_add(1))
        .map(|entry| match entry {
            Ok(entry) => format!(
                "{}={}",
                entry.file_name().to_string_lossy(),
                path_diagnostic(&entry.path())
            ),
            Err(error) => format!("<entry-error:{error}>"),
        })
        .collect::<Vec<_>>();
    let truncated_entries = snapshot.len() > MAX_DIAGNOSTIC_ENTRIES;
    snapshot.truncate(MAX_DIAGNOSTIC_ENTRIES);
    snapshot.sort_unstable();
    if truncated_entries {
        snapshot.push("<entries-truncated>".to_owned());
    }
    let mut rendered = snapshot.join(", ");
    if rendered.len() > MAX_DIRECTORY_DIAGNOSTIC_BYTES {
        let mut end = MAX_DIRECTORY_DIAGNOSTIC_BYTES;
        while !rendered.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        rendered.truncate(end);
        rendered.push_str("<output-truncated>");
    }
    rendered
}

fn update_helper_diagnostic(staging: &Path) -> String {
    let receipt_path = staging.join("result.json");
    let receipt = read_bounded_diagnostic(&receipt_path);
    let receipt_summary = match serde_json::from_str::<serde_json::Value>(&receipt) {
        Ok(value) => format!("state={} detail={}", value["state"], value["detail"]),
        Err(error) => format!("unparseable:{error}"),
    };
    let control_files = [
        "transaction.pending.json",
        "transaction.json",
        "result.json",
        "armed",
        "recovery-armed",
        "helper.lock",
    ]
    .map(|name| format!("{name}={}", path_diagnostic(&staging.join(name))))
    .join(", ");
    let install = staging.parent().unwrap_or(staging);
    format!(
        "receipt=({receipt_summary}) raw-receipt={receipt:?}; \
         controls=[{control_files}]; staging=[{}]; install=[{}]",
        directory_diagnostic(staging),
        directory_diagnostic(install)
    )
}

fn wait_for_update_helper(
    child: &mut std::process::Child,
    staging: &Path,
    stderr_path: &Path,
    timeout: Duration,
) -> std::process::ExitStatus {
    let started = Instant::now();
    let deadline = deadline_after(timeout);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let elapsed_at_deadline = started.elapsed();
            let cleanup = terminate_child_bounded_sync(child);
            let final_status = child.try_wait();
            let stderr = read_bounded_diagnostic(stderr_path);
            let snapshot = update_helper_diagnostic(staging);
            panic!(
                "timed out waiting for Windows update helper after {:?}; \
                 cleanup={cleanup:?}; final-status={final_status:?}; \
                 stderr={stderr:?}; snapshot={snapshot}",
                elapsed_at_deadline
            );
        }
        std::thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn terminate_child_bounded_sync(child: &mut std::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Err(kill_error) = child.kill() {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        return Err(kill_error);
    }

    let deadline = deadline_after(CHILD_REAP_TIMEOUT);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reaping Windows updater test child",
            ));
        }
        std::thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn private_test_root() -> (PathBuf, DirectoryGuard) {
    let runtime_root = astrid_core::platform_fs::default_astrid_home_root().unwrap();
    let local_app_data = runtime_root
        .parent()
        .and_then(Path::parent)
        .expect("Astrid runtime root is below Windows LocalAppData");
    let root = local_app_data.join(format!(
        "AstridUpdateTest-{}",
        uuid::Uuid::new_v4().simple()
    ));
    astrid_core::platform_fs::ensure_private_directory(&root).unwrap();
    (root.clone(), DirectoryGuard(root))
}

fn deadline_after(duration: Duration) -> Instant {
    Instant::now()
        .checked_add(duration)
        .expect("Windows updater test deadline overflow")
}

fn read_receipt_state(path: &Path) -> Option<String> {
    let value: serde_json::Value =
        serde_json::from_str(&astrid_core::platform_fs::read_private_file_to_string(path).ok()?)
            .ok()?;
    value["state"].as_str().map(str::to_owned)
}

fn digest(path: &Path) -> String {
    blake3::hash(&std::fs::read(path).unwrap())
        .to_hex()
        .to_string()
}

// This helper is the only test FFI boundary for binding a PID to its creation
// token; access is query-only and the retained handle owns the entire query.
#[allow(unsafe_code)]
fn process_creation_time(process_id: u32) -> u64 {
    // SAFETY: scalar PID and query-only access; a successful handle is owned
    // by ProcessHandle for the duration of GetProcessTimes.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    assert!(!handle.is_null(), "failed to open test process identity");
    let handle = ProcessHandle(handle);
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: the retained handle has query access and every output pointer
    // references initialized FILETIME storage.
    assert_ne!(
        unsafe {
            GetProcessTimes(
                handle.0,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        },
        0,
        "failed to query test process identity"
    );
    let token = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    assert_ne!(token, 0, "Windows returned a zero test process identity");
    token
}

fn spawn_test_parent() -> ChildGuard {
    ChildGuard(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "windows_update_test_parent"])
            .env(TEST_PARENT_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn spawn_installed_cli(install: &Path) -> ChildGuard {
    ChildGuard(
        std::process::Command::new(install.join("astrid.exe"))
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn invoke_installed_cli(install: &Path) -> std::process::ExitStatus {
    let mut invocation = spawn_installed_cli(install);
    wait_for_child(&mut invocation.0, Duration::from_secs(15))
}

fn run_update_helper_after_parent_exit(
    parent: &mut ChildGuard,
    helper: &Path,
    transaction_path: &Path,
    staging: &Path,
    stderr_path: &Path,
) -> std::process::ExitStatus {
    let mut completion = ChildGuard(
        std::process::Command::new(helper)
            .arg("__complete-windows-update")
            .arg(transaction_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(open_private_stderr(stderr_path))
            .spawn()
            .unwrap(),
    );
    wait_for_private_marker(&staging.join("armed"), "v1\n", Duration::from_secs(15));
    terminate_child_bounded_sync(&mut parent.0).unwrap();
    wait_for_update_helper(
        &mut completion.0,
        staging,
        stderr_path,
        Duration::from_secs(30),
    )
}

fn assert_complete_executable_set_replaced(
    install: &Path,
    staging: &Path,
    original_cli_digest: &str,
    staged_cli_digest: &str,
) {
    let receipt: serde_json::Value = serde_json::from_str(
        &astrid_core::platform_fs::read_private_file_to_string(&staging.join("result.json"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["state"], "succeeded");
    assert_eq!(receipt["reported"], false);

    for name in BINARIES {
        if name == "astrid.exe" {
            assert_eq!(digest(&install.join(name)), staged_cli_digest);
            assert_eq!(
                digest(&install.join(format!("{name}.bak"))),
                original_cli_digest
            );
        } else {
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
}

fn wait_for_receipt_state(path: &Path, expected: &str, timeout: Duration) {
    let deadline = deadline_after(timeout);
    loop {
        if read_receipt_state(path).as_deref() == Some(expected) {
            return;
        }
        if Instant::now() >= deadline {
            let staging = path.parent().unwrap_or(path);
            panic!(
                "timed out waiting for update receipt state {expected}; snapshot={}",
                update_helper_diagnostic(staging)
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_recovered_stage_cleanup(install: &Path, staging: &Path, timeout: Duration) {
    let deadline = deadline_after(timeout);
    while staging.exists() {
        assert!(
            invoke_installed_cli(install).success(),
            "normal command did not resume after recovery; snapshot={}",
            update_helper_diagnostic(staging)
        );
        if Instant::now() >= deadline {
            panic!(
                "reported recovery stage was not cleaned; snapshot={}",
                update_helper_diagnostic(staging)
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "leaf process used by Windows updater integration tests"]
fn windows_update_test_parent() {
    if std::env::var(TEST_PARENT_ENV).as_deref() != Ok("1") {
        return;
    }
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn real_hidden_helper_replaces_the_complete_executable_set() {
    let _serial = updater_integration_guard();
    let (root, _root_guard) = private_test_root();
    let install = root.join("install");
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staging = install.join(format!(".astrid-update-stage.{transaction_id}"));
    astrid_core::platform_fs::ensure_private_directory(&install).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();

    let test_astrid = PathBuf::from(env!("CARGO_BIN_EXE_astrid"));
    for name in BINARIES {
        if name == "astrid.exe" {
            std::fs::copy(&test_astrid, install.join(name)).unwrap();
            std::fs::copy(&test_astrid, staging.join(name)).unwrap();
            astrid_core::platform_fs::restrict_private_file(&install.join(name)).unwrap();
            astrid_core::platform_fs::restrict_private_file(&staging.join(name)).unwrap();
        } else {
            write_private(&install.join(name), format!("old {name}").as_bytes());
            write_private(&staging.join(name), format!("new {name}").as_bytes());
        }
    }
    let original_cli_digest = digest(&test_astrid);
    let staged_cli = staging.join("astrid.exe");
    let mut staged_cli_file = std::fs::OpenOptions::new()
        .append(true)
        .open(&staged_cli)
        .unwrap();
    staged_cli_file
        .write_all(format!("\nASTRID-UPDATE-OVERLAY-{transaction_id}\n").as_bytes())
        .unwrap();
    staged_cli_file.sync_all().unwrap();
    drop(staged_cli_file);
    let staged_cli_digest = digest(&staged_cli);
    assert_ne!(
        staged_cli_digest, original_cli_digest,
        "staged CLI proof must exercise a real replacement"
    );
    let helper = staging.join("helper.exe");
    std::fs::copy(&test_astrid, &helper).unwrap();
    astrid_core::platform_fs::restrict_private_file(&helper).unwrap();
    let helper_stderr = root.join("success-helper.stderr.log");

    let mut parent = spawn_test_parent();
    let transaction = Transaction {
        schema_version: 2,
        id: transaction_id,
        target_version: "test-version".to_owned(),
        parent_pid: parent.0.id(),
        parent_creation_time: process_creation_time(parent.0.id()),
        install_dir: install.clone(),
        staging_dir: staging.clone(),
        helper: helper.clone(),
        entries: BINARIES
            .iter()
            .map(|name| Entry {
                name: (*name).to_owned(),
                blake3: digest(&staging.join(name)),
            })
            .collect(),
    };
    let transaction_path = staging.join("transaction.pending.json");
    write_private(
        &transaction_path,
        &serde_json::to_vec(&transaction).unwrap(),
    );

    let status = run_update_helper_after_parent_exit(
        &mut parent,
        &helper,
        &transaction_path,
        &staging,
        &helper_stderr,
    );
    assert!(
        status.success(),
        "helper failed with {status}; stderr={:?}; snapshot={}",
        read_bounded_diagnostic(&helper_stderr),
        update_helper_diagnostic(&staging)
    );

    assert_complete_executable_set_replaced(
        &install,
        &staging,
        &original_cli_digest,
        &staged_cli_digest,
    );
    assert!(
        invoke_installed_cli(&install).success(),
        "installed CLI did not report and reconcile the completed update"
    );
    assert!(
        !staging.exists(),
        "completed update stage survived terminal receipt reporting"
    );
}

#[test]
fn tampered_payload_keeps_all_live_binaries_and_is_reported_by_real_cli() {
    let _serial = updater_integration_guard();
    let (root, _root_guard) = private_test_root();
    let install = root.join("install");
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staging = install.join(format!(".astrid-update-stage.{transaction_id}"));
    astrid_core::platform_fs::ensure_private_directory(&install).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();

    let test_astrid = PathBuf::from(env!("CARGO_BIN_EXE_astrid"));
    for name in BINARIES {
        if name == "astrid.exe" {
            std::fs::copy(&test_astrid, install.join(name)).unwrap();
            std::fs::copy(&test_astrid, staging.join(name)).unwrap();
            astrid_core::platform_fs::restrict_private_file(&install.join(name)).unwrap();
            astrid_core::platform_fs::restrict_private_file(&staging.join(name)).unwrap();
        } else {
            write_private(&install.join(name), format!("old {name}").as_bytes());
            write_private(
                &staging.join(name),
                format!("authenticated new {name}").as_bytes(),
            );
        }
    }
    let original_live_digests = BINARIES
        .iter()
        .map(|name| ((*name).to_owned(), digest(&install.join(name))))
        .collect::<Vec<_>>();
    let helper = staging.join("helper.exe");
    std::fs::copy(&test_astrid, &helper).unwrap();
    astrid_core::platform_fs::restrict_private_file(&helper).unwrap();
    let helper_stderr = root.join("tampered-helper.stderr.log");

    let mut parent = spawn_test_parent();
    let transaction = Transaction {
        schema_version: 2,
        id: transaction_id,
        target_version: "tamper-test".to_owned(),
        parent_pid: parent.0.id(),
        parent_creation_time: process_creation_time(parent.0.id()),
        install_dir: install.clone(),
        staging_dir: staging.clone(),
        helper: helper.clone(),
        entries: BINARIES
            .iter()
            .map(|name| Entry {
                name: (*name).to_owned(),
                blake3: digest(&staging.join(name)),
            })
            .collect(),
    };
    let transaction_path = staging.join("transaction.pending.json");
    write_private(
        &transaction_path,
        &serde_json::to_vec(&transaction).unwrap(),
    );
    write_private(&staging.join("astrid-build.exe"), b"tampered after signing");

    let status = run_update_helper_after_parent_exit(
        &mut parent,
        &helper,
        &transaction_path,
        &staging,
        &helper_stderr,
    );
    assert!(
        !status.success(),
        "tampered update helper unexpectedly succeeded; stderr={:?}; snapshot={}",
        read_bounded_diagnostic(&helper_stderr),
        update_helper_diagnostic(&staging)
    );

    let receipt_path = staging.join("result.json");
    assert_eq!(
        read_receipt_state(&receipt_path).as_deref(),
        Some("failed_before_mutation"),
        "tampered helper failed for the wrong reason; stderr={:?}; snapshot={}",
        read_bounded_diagnostic(&helper_stderr),
        update_helper_diagnostic(&staging)
    );
    for (name, expected_digest) in original_live_digests {
        assert_eq!(
            digest(&install.join(&name)),
            expected_digest,
            "{name} changed despite pre-mutation authentication failure"
        );
    }
    assert!(
        invoke_installed_cli(&install).success(),
        "live CLI did not report the safely rejected update"
    );
    assert!(
        !staging.exists(),
        "rejected update stage survived terminal receipt reporting"
    );
}

#[test]
fn ordinary_invocation_never_recovers_a_provisional_handoff() {
    let _serial = updater_integration_guard();
    let (root, _root_guard) = private_test_root();
    let install = root.join("install");
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staging = install.join(format!(".astrid-update-stage.{transaction_id}"));
    astrid_core::platform_fs::ensure_private_directory(&install).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();

    let test_astrid = PathBuf::from(env!("CARGO_BIN_EXE_astrid"));
    std::fs::copy(&test_astrid, install.join("astrid.exe")).unwrap();
    astrid_core::platform_fs::restrict_private_file(&install.join("astrid.exe")).unwrap();
    for name in BINARIES {
        write_private(&staging.join(name), format!("pending {name}").as_bytes());
    }
    let helper = staging.join("helper.exe");
    std::fs::copy(&test_astrid, &helper).unwrap();
    astrid_core::platform_fs::restrict_private_file(&helper).unwrap();
    let parent = spawn_test_parent();
    let pending_path = staging.join("transaction.pending.json");
    write_private(
        &pending_path,
        &serde_json::to_vec(&Transaction {
            schema_version: 2,
            id: transaction_id,
            target_version: "pending-test".to_owned(),
            parent_pid: parent.0.id(),
            parent_creation_time: process_creation_time(parent.0.id()),
            install_dir: install.clone(),
            staging_dir: staging.clone(),
            helper,
            entries: BINARIES
                .iter()
                .map(|name| Entry {
                    name: (*name).to_owned(),
                    blake3: digest(&staging.join(name)),
                })
                .collect(),
        })
        .unwrap(),
    );

    assert!(
        !invoke_installed_cli(&install).success(),
        "ordinary invocation interpreted a provisional handoff as runnable state"
    );
    assert!(pending_path.exists(), "provisional handoff was discarded");
    assert!(
        !staging.join("transaction.json").exists(),
        "ordinary invocation promoted a transaction owned by the completion helper"
    );
    assert!(
        !staging.join("result.json").exists(),
        "ordinary invocation attempted recovery for a provisional handoff"
    );
}

#[test]
fn ordinary_invocation_cleans_an_abandoned_provisional_handoff() {
    let _serial = updater_integration_guard();
    let (root, _root_guard) = private_test_root();
    let install = root.join("install");
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staging = install.join(format!(".astrid-update-stage.{transaction_id}"));
    astrid_core::platform_fs::ensure_private_directory(&install).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();

    let test_astrid = PathBuf::from(env!("CARGO_BIN_EXE_astrid"));
    std::fs::copy(&test_astrid, install.join("astrid.exe")).unwrap();
    astrid_core::platform_fs::restrict_private_file(&install.join("astrid.exe")).unwrap();
    let live_cli_digest = digest(&install.join("astrid.exe"));
    for name in BINARIES {
        write_private(
            &staging.join(name),
            format!("abandoned pending {name}").as_bytes(),
        );
    }
    let helper = staging.join("helper.exe");
    std::fs::copy(&test_astrid, &helper).unwrap();
    astrid_core::platform_fs::restrict_private_file(&helper).unwrap();
    let mut parent = spawn_test_parent();
    let parent_pid = parent.0.id();
    let parent_creation_time = process_creation_time(parent_pid);
    let pending_path = staging.join("transaction.pending.json");
    write_private(
        &pending_path,
        &serde_json::to_vec(&Transaction {
            schema_version: 2,
            id: transaction_id,
            target_version: "abandoned-pending-test".to_owned(),
            parent_pid,
            parent_creation_time,
            install_dir: install.clone(),
            staging_dir: staging.clone(),
            helper,
            entries: BINARIES
                .iter()
                .map(|name| Entry {
                    name: (*name).to_owned(),
                    blake3: digest(&staging.join(name)),
                })
                .collect(),
        })
        .unwrap(),
    );
    terminate_child_bounded_sync(&mut parent.0).unwrap();

    assert!(
        invoke_installed_cli(&install).success(),
        "ordinary invocation remained blocked by an abandoned provisional handoff"
    );
    assert_eq!(
        digest(&install.join("astrid.exe")),
        live_cli_digest,
        "abandoned pre-mutation cleanup changed the live CLI"
    );
    assert!(
        !staging.exists(),
        "abandoned provisional update stage was not cleaned"
    );
}

#[test]
fn ordinary_invocation_recovers_an_interrupted_update_before_dispatch() {
    let _serial = updater_integration_guard();
    let (root, _root_guard) = private_test_root();
    let install = root.join("install");
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staging = install.join(format!(".astrid-update-stage.{transaction_id}"));
    astrid_core::platform_fs::ensure_private_directory(&install).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&staging).unwrap();

    let test_astrid = PathBuf::from(env!("CARGO_BIN_EXE_astrid"));
    for name in BINARIES {
        let live = install.join(name);
        std::fs::copy(&test_astrid, &live).unwrap();
        astrid_core::platform_fs::restrict_private_file(&live).unwrap();
        write_private(
            &staging.join(name),
            format!("uncommitted {name}").as_bytes(),
        );
    }
    let helper = staging.join("helper.exe");
    std::fs::copy(&test_astrid, &helper).unwrap();
    astrid_core::platform_fs::restrict_private_file(&helper).unwrap();
    let mut original_parent = spawn_test_parent();
    let original_parent_pid = original_parent.0.id();
    let original_parent_creation_time = process_creation_time(original_parent_pid);
    terminate_child_bounded_sync(&mut original_parent.0).unwrap();

    let transaction = Transaction {
        schema_version: 2,
        id: transaction_id.clone(),
        target_version: "interrupted-test".to_owned(),
        parent_pid: original_parent_pid,
        parent_creation_time: original_parent_creation_time,
        install_dir: install.clone(),
        staging_dir: staging.clone(),
        helper,
        entries: BINARIES
            .iter()
            .map(|name| Entry {
                name: (*name).to_owned(),
                blake3: blake3::hash(format!("uncommitted {name}").as_bytes())
                    .to_hex()
                    .to_string(),
            })
            .collect(),
    };
    let transaction_path = staging.join("transaction.json");
    write_private(
        &transaction_path,
        &serde_json::to_vec(&transaction).unwrap(),
    );
    let receipt_path = staging.join("result.json");
    write_private(
        &receipt_path,
        &serde_json::to_vec(&Receipt {
            schema_version: 2,
            transaction_id,
            target_version: "interrupted-test".to_owned(),
            state: "applying",
            detail: None,
            reported: false,
        })
        .unwrap(),
    );

    let mut blocked = spawn_installed_cli(&install);
    let status = wait_for_child(&mut blocked.0, Duration::from_secs(15));
    assert!(!status.success(), "interrupted update was not fail-closed");

    wait_for_receipt_state(&receipt_path, "failed_recovered", Duration::from_secs(30));
    wait_for_recovered_stage_cleanup(&install, &staging, Duration::from_secs(15));
}
