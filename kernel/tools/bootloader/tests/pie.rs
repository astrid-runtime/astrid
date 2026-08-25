use bootloader_test_runner::run_test_kernel;

#[test]
fn basic_boot() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_PIE_basic_boot"));
}

#[test]
fn should_panic() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_PIE_should_panic"));
}

#[test]
fn check_boot_info() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_PIE_check_boot_info"));
}

#[test]
fn global_variable() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_PIE_global_variable"));
}
