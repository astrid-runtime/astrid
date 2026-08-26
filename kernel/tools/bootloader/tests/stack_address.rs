use bootloader_test_runner::run_test_kernel;

#[test]
fn basic_boot() {
    run_test_kernel(env!("CARGO_BIN_FILE_TEST_KERNEL_STACK_ADDRESS_basic_boot"));
}
