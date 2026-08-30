//! Exact-file Windows DACL regressions for trusted provider executables.

use super::*;
use windows_sys::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_WRITE_DATA, WRITE_DAC};

#[test]
fn trusted_file_validator_accepts_a_trusted_private_executable() {
    let _guard = serial_test_guard();
    let root = private_temp();
    let executable = root.path().join("trusted-provider.exe");
    std::fs::write(&executable, b"trusted provider").unwrap();
    apply_private_acl(&executable, false).unwrap();

    validate_trusted_file(&executable).expect("trusted executable DACL must be accepted");
}

#[test]
fn trusted_file_validator_rejects_a_writable_file_dacl() {
    let _guard = serial_test_guard();
    let root = private_temp();
    let executable = root.path().join("writable-provider.exe");
    std::fs::write(&executable, b"provider").unwrap();
    apply_private_acl(&executable, false).unwrap();
    set_world_entry(&executable, FILE_WRITE_DATA | FILE_APPEND_DATA, true);

    let error = validate_trusted_file(&executable)
        .expect_err("an untrusted writable file ACE must fail closed");
    assert!(error.to_string().contains("writable by an untrusted"));
}

#[test]
fn trusted_file_validator_rejects_a_write_dac_file_dacl() {
    let _guard = serial_test_guard();
    let root = private_temp();
    let executable = root.path().join("write-dac-provider.exe");
    std::fs::write(&executable, b"provider").unwrap();
    apply_private_acl(&executable, false).unwrap();
    set_world_entry(&executable, WRITE_DAC, true);

    let error = validate_trusted_file(&executable)
        .expect_err("an untrusted WRITE_DAC file ACE must fail closed");
    assert!(error.to_string().contains("writable by an untrusted"));
}
