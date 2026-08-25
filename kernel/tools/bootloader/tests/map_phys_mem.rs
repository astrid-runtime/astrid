use bootloader_test_runner::run_test_kernel;

#[test]
fn check_boot_info() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_MAP_PHYS_MEM_check_boot_info"
    ));
}

#[test]
fn access_phys_mem() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_MAP_PHYS_MEM_access_phys_mem"
    ));
}
