use std::{path::Path, process::Command};

use bootloader_test_runner::run_test_kernel;

#[test]
fn basic_boot() {
    // build test kernel manually to force-enable link-time optimization
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir("tests/test_kernels");
    cmd.arg("build");
    cmd.arg("-p").arg("test_kernel_lto");
    cmd.arg("--profile").arg("lto");
    let status = cmd.status().unwrap();
    assert!(status.success());

    let root = env!("CARGO_MANIFEST_DIR");
    let kernel_path = Path::new(root)
        .join("target")
        .join("x86_64-unknown-none")
        .join("lto")
        .join("basic_boot");
    assert!(kernel_path.exists());

    run_test_kernel(kernel_path.as_path().to_str().unwrap());
}
