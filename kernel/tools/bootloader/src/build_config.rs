//! Build-time settings shared by the vendored UEFI build script and its
//! focused configuration regression.

/// The target built by `build.rs` for the UEFI bootloader fixture.
pub const NESTED_UEFI_TARGET: &str = "x86_64-unknown-uefi";

/// Keep the nested UEFI build on the serial curve25519 backend.
///
/// This is a compile configuration for the pinned nightly/toolchain and does
/// not change the Ed25519 scheme or its verification inputs.
pub const NESTED_UEFI_RUSTFLAGS: &str = "--cfg curve25519_dalek_backend=\"serial\"";
