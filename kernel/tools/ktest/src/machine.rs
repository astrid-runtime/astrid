//! Experimental emulator machine contract for M1 evidence.
//!
//! Named architecture contract (quote, do not rename): x86-64 QEMU/KVM with
//! UEFI, fixed memory, one CPU, serial diagnostics, APIC timer, and an explicit
//! virtio/IOMMU topology.
//!
//! This child uses TCG as the first evidence class under that named contract.
//! It does not enable KVM, virtio, or IOMMU, and does not rename the contract.

use std::path::Path;

/// QEMU system emulator binary name.
pub const QEMU_BIN: &str = "qemu-system-x86_64";
/// Q35 chipset. Must stay aligned with firmware/UEFI bring-up.
pub const MACHINE: &str = "q35";
/// Explicit accelerator. TCG is the M1 evidence class; KVM is not selected.
pub const ACCEL: &str = "tcg";
pub const CPU: &str = "max";
/// Must match ring-0 `PHYS_SPAN` (256 MiB).
pub const MEMORY_MIB: u32 = 256;
pub const SMP: u32 = 1;
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);
/// isa-debug-exit success value 0x10 -> QEMU process exit code (0x10<<1)|1.
pub const EXPECT_EXIT_CODE: i32 = 33;

/// Build the frozen M1 QEMU argv. Firmware paths are injected by discovery.
pub fn qemu_args(code: &Path, vars: &Path, image: &Path) -> Vec<String> {
    vec![
        "-machine".into(),
        MACHINE.into(),
        "-accel".into(),
        ACCEL.into(),
        "-cpu".into(),
        CPU.into(),
        "-m".into(),
        MEMORY_MIB.to_string(),
        "-smp".into(),
        SMP.to_string(),
        "-drive".into(),
        format!("if=pflash,format=raw,readonly=on,file={}", code.display()),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars.display()),
        "-drive".into(),
        format!("format=raw,file={}", image.display()),
        "-serial".into(),
        "stdio".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
        "-device".into(),
        "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
    ]
}

pub fn contains_explicit_tcg(args: &[String]) -> bool {
    args.windows(2).any(|w| w[0] == "-accel" && w[1] == ACCEL)
        || args.iter().any(|a| a.contains("accel=tcg"))
}

pub fn claims_kvm(args: &[String]) -> bool {
    args.iter().any(|a| a == "-enable-kvm" || a.contains("kvm"))
}

pub fn joined_forbids_virtio_iommu(args: &[String]) -> bool {
    let joined = args.join(" ");
    !joined.contains("virtio") && !joined.contains("iommu")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<String> {
        qemu_args(
            Path::new("/fw/code.fd"),
            Path::new("/fw/vars.fd"),
            Path::new("/img/disk.img"),
        )
    }

    #[test]
    fn argv_is_q35_tcg_256m_smp1_no_kvm() {
        let args = sample();
        assert!(args.windows(2).any(|w| w == ["-machine", "q35"]));
        assert!(contains_explicit_tcg(&args));
        assert!(args.windows(2).any(|w| w == ["-m", "256"]));
        assert!(args.windows(2).any(|w| w == ["-smp", "1"]));
        assert!(!claims_kvm(&args));
        assert!(joined_forbids_virtio_iommu(&args));
    }

    #[test]
    fn firmware_and_serial_are_present() {
        let args = sample();
        let joined = args.join(" ");
        assert!(joined.contains("if=pflash"));
        assert!(joined.contains("/fw/code.fd"));
        assert!(joined.contains("/fw/vars.fd"));
        assert!(args.windows(2).any(|w| w == ["-serial", "stdio"]));
        assert!(args.iter().any(|a| a.starts_with("isa-debug-exit")));
    }

    #[test]
    fn timeout_is_two_minutes() {
        assert_eq!(TIMEOUT, std::time::Duration::from_mins(2));
        assert_eq!(EXPECT_EXIT_CODE, 33);
    }
}
