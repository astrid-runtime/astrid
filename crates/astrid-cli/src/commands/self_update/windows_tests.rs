use super::*;
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};

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
