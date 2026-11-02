//! Sampler unit checks that do not open a volume or the engine.

#[path = "../benches/storage_io/resource.rs"]
mod resource;

#[path = "../benches/storage_io/resource/linux.rs"]
mod linux;

use std::io::ErrorKind;

#[test]
fn linux_vm_rss_parses_kibibytes_into_bytes() {
    let bytes = linux::parse_linux_vm_rss_bytes("VmPeak:\t999 kB\nVmRSS:\t  12 kB\n")
        .expect("VmRSS is present");
    assert_eq!(bytes, 12_288);
}

#[test]
fn linux_vm_rss_accepts_a_zero_resident_set() {
    let bytes = linux::parse_linux_vm_rss_bytes("VmRSS: 0 kB\n").expect("zero is valid");
    assert_eq!(bytes, 0);
}

#[test]
fn linux_vm_rss_rejects_malformed_status() {
    for status in [
        "VmPeak:\t12 kB\n",
        "VmRSS:\n",
        "VmRSS: 12\n",
        "VmRSS: 12 KB\n",
        "VmRSS: 12 KiB\n",
        "VmRSS: 12 mB\n",
        "VmRSS: 12 kB extra\n",
        "VmRSS: 12 kB kB\n",
        "VmRSS: not-a-number kB\n",
        "VmRSS: 12kB\n",
    ] {
        let error = linux::parse_linux_vm_rss_bytes(status).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData, "{status:?}");
    }
}

#[test]
fn linux_vm_rss_rejects_kibibyte_overflow() {
    let error = linux::parse_linux_vm_rss_bytes("VmRSS: 18446744073709551615 kB\n")
        .expect_err("u64::MAX kibibytes overflow a byte count");
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(error.to_string().contains("overflows"), "{error}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn process_resident_bytes_is_nonzero_on_macos_and_linux() {
    let bytes = resource::process_resident_bytes()
        .expect("current RSS is readable")
        .expect("macOS and Linux expose current RSS");
    assert_ne!(bytes, 0);
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn process_resident_bytes_is_omitted_where_unsupported() {
    let sample =
        resource::process_resident_bytes().expect("unsupported RSS is omitted, not an error");
    assert_eq!(sample, None);
}
