use bootloader_test_runner::run_test_kernel;

#[test]
fn basic_boot() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_FIXED_KERNEL_ADDRESS_basic_boot"
    ));
}

#[test]
fn should_panic() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_FIXED_KERNEL_ADDRESS_should_panic"
    ));
}

#[test]
fn check_boot_info() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_FIXED_KERNEL_ADDRESS_check_boot_info"
    ));
}

#[test]
fn verify_kernel_address() {
    run_test_kernel(env!(
        "CARGO_BIN_FILE_TEST_KERNEL_FIXED_KERNEL_ADDRESS_verify_kernel_address"
    ));
}
