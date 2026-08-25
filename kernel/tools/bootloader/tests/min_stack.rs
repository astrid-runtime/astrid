use bootloader_test_runner::run_test_kernel;

#[test]
fn basic_boot() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_MIN_STACK_basic_boot"));
}
