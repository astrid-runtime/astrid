#[path = "../src/build_config.rs"]
mod build_config;

#[test]
fn nested_uefi_build_uses_serial_curve_backend() {
    assert_eq!(build_config::NESTED_UEFI_TARGET, "x86_64-unknown-uefi");
    assert_eq!(
        build_config::NESTED_UEFI_RUSTFLAGS,
        "--cfg curve25519_dalek_backend=\"serial\""
    );
}
