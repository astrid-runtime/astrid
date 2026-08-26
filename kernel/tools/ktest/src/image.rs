//! kimage invocation.
//!
//! bootloader 0.11's build.rs runs `cargo install bootloader-x86_64-uefi`
//! and inherits `CARGO_TARGET_DIR`. If that directory is also the parent
//! kimage target dir, parent and nested cargo deadlock on `.cargo-build-lock`.
//! Parent uses `--target-dir` (not inherited). Nested install uses a distinct
//! `CARGO_TARGET_DIR`. Neither path is the shared `~/.cache/cargo-targets`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Dated rustup channel for kimage and the nested UEFI bootloader build.
/// Floating `nightly` is not CI evidence: bootloader 0.11.16 failed to
/// link `wcslen` on GitHub rolling nightly.
pub const KIMAGE_NIGHTLY: &str = "nightly-2026-07-21";

/// Nightly host artifacts for the `kimage` binary and the `bootloader` crate.
pub const HOST_TARGET_REL: &str = "target/kimage-host";
/// Target dir inherited by nested `cargo install -Zbuild-std`.
pub const NESTED_TARGET_REL: &str = "target/bootloader-nested";
pub const ROOT_KEY_REL: &str = "tools/kimage/fixtures/root.key.hex";
pub const KERNEL_KEY_REL: &str = "tools/kimage/fixtures/kernel.key.hex";
pub const SYSGEN_KEY_REL: &str = "tools/kimage/fixtures/sysgen.key.hex";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KimageInvocation {
    pub toolchain: String,
    pub host_target_dir: PathBuf,
    pub nested_target_dir: PathBuf,
}

impl KimageInvocation {
    pub fn new(root: &Path, toolchain: impl Into<String>) -> Self {
        Self {
            toolchain: toolchain.into(),
            host_target_dir: root.join(HOST_TARGET_REL),
            nested_target_dir: root.join(NESTED_TARGET_REL),
        }
    }

    /// Parent `--target-dir` and nested `CARGO_TARGET_DIR` must not be equal.
    pub fn isolates_nested_install(&self) -> bool {
        self.host_target_dir != self.nested_target_dir
    }

    pub fn command(&self, root: &Path, kernel: &Path, output: &Path) -> Command {
        let mut cmd = Command::new("rustup");
        cmd.current_dir(root);
        cmd.env("CARGO_TARGET_DIR", &self.nested_target_dir);
        cmd.env_remove("CARGO_BUILD_TARGET_DIR");
        cmd.args([
            "run",
            self.toolchain.as_str(),
            "cargo",
            "run",
            "-q",
            "-p",
            "kimage",
            "--locked",
            "--release",
            "--target-dir",
        ]);
        cmd.arg(&self.host_target_dir);
        cmd.arg("--");
        cmd.arg(kernel);
        cmd.arg(output);
        cmd.args([
            "--root-key",
            ROOT_KEY_REL,
            "--kernel-key",
            KERNEL_KEY_REL,
            "--sysgen-key",
            SYSGEN_KEY_REL,
        ]);
        cmd
    }

    pub fn command_with_tampered_handoff(
        &self,
        root: &Path,
        kernel: &Path,
        output: &Path,
    ) -> Command {
        let mut cmd = self.command(root, kernel, output);
        cmd.arg("--tamper-handoff");
        cmd
    }

    pub fn command_with_tampered_sysgen(
        &self,
        root: &Path,
        kernel: &Path,
        output: &Path,
    ) -> Command {
        let mut cmd = self.command(root, kernel, output);
        cmd.arg("--tamper-sysgen");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kimage_nightly_is_dated_not_floating() {
        assert_eq!(KIMAGE_NIGHTLY, "nightly-2026-07-21");
        assert_ne!(KIMAGE_NIGHTLY, "nightly");
        assert!(KIMAGE_NIGHTLY.starts_with("nightly-20"));
    }

    #[test]
    fn nested_target_is_not_the_parent_host_target() {
        let inv = KimageInvocation::new(Path::new("/ws"), "nightly");
        assert!(inv.isolates_nested_install());
        assert!(inv.host_target_dir.ends_with("target/kimage-host"));
        assert!(inv.nested_target_dir.ends_with("target/bootloader-nested"));
    }

    #[test]
    fn command_uses_flag_for_host_and_env_for_nested() {
        let inv = KimageInvocation::new(Path::new("/ws"), "nightly");
        let cmd = inv.command(Path::new("/ws"), Path::new("/k.elf"), Path::new("/o.img"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(cmd.get_program().to_string_lossy(), "rustup");
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--target-dir" && w[1].ends_with("target/kimage-host")),
            "missing parent --target-dir: {args:?}"
        );
        assert!(args.contains(&"--locked".to_string()));
        assert!(args.windows(2).any(|w| w == ["--root-key", ROOT_KEY_REL]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--kernel-key", KERNEL_KEY_REL])
        );
        assert!(
            args.windows(2)
                .any(|w| w == ["--sysgen-key", SYSGEN_KEY_REL])
        );
        let mut saw_nested = false;
        let mut cleared_build_target = false;
        for (key, val) in cmd.get_envs() {
            let key = key.to_string_lossy();
            if key == "CARGO_TARGET_DIR" {
                let val = val.expect("CARGO_TARGET_DIR must be set");
                assert!(
                    val.to_string_lossy().ends_with("target/bootloader-nested"),
                    "{}",
                    val.to_string_lossy()
                );
                saw_nested = true;
            }
            if key == "CARGO_BUILD_TARGET_DIR" {
                assert!(val.is_none(), "CARGO_BUILD_TARGET_DIR must be cleared");
                cleared_build_target = true;
            }
        }
        assert!(saw_nested, "nested CARGO_TARGET_DIR missing");
        assert!(cleared_build_target, "CARGO_BUILD_TARGET_DIR not cleared");
        assert!(!args.contains(&"--tamper-handoff".to_string()));

        let tampered = inv.command_with_tampered_handoff(
            Path::new("/ws"),
            Path::new("/k.elf"),
            Path::new("/o.img"),
        );
        let tampered_args: Vec<String> = tampered
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(tampered_args.ends_with(&["--tamper-handoff".to_string()]));

        let tampered = inv.command_with_tampered_sysgen(
            Path::new("/ws"),
            Path::new("/k.elf"),
            Path::new("/o.img"),
        );
        let tampered_args: Vec<String> = tampered
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(tampered_args.ends_with(&["--tamper-sysgen".to_string()]));
    }
}
