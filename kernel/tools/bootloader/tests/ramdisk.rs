use std::path::Path;

use bootloader_test_runner::run_test_kernel_with_ramdisk;
use tempfile::NamedTempFile;

static RAMDISK_PATH: &str = "tests/ramdisk.txt";

#[test]
fn basic_boot() {
    run_test_kernel_with_ramdisk(
        env!("CARGO_BIN_FILE_TEST_KERNEL_RAMDISK_basic_boot"),
        Some(Path::new(RAMDISK_PATH)),
    );
}

#[test]
fn check_ramdisk() {
    run_test_kernel_with_ramdisk(
        env!("CARGO_BIN_FILE_TEST_KERNEL_RAMDISK_ramdisk"),
        Some(Path::new(RAMDISK_PATH)),
    );
}

#[test]
fn memory_map() {
    run_test_kernel_with_ramdisk(
        env!("CARGO_BIN_FILE_TEST_KERNEL_RAMDISK_memory_map"),
        Some(Path::new(RAMDISK_PATH)),
    );
}

#[test]
fn large_ramdisk() {
    // Create a large file to act as the RAM disk.
    let ramdisk = NamedTempFile::new().unwrap();
    ramdisk.as_file().set_len(1024 * 1024 * 16).unwrap();

    run_test_kernel_with_ramdisk(
        env!("CARGO_BIN_FILE_TEST_KERNEL_RAMDISK_large_ramdisk"),
        Some(ramdisk.as_ref()),
    );
}
