//! Linux /proc status RSS units and checked byte conversion.

use std::io::{self, ErrorKind};

pub(crate) fn parse_linux_vm_rss_bytes(status: &str) -> io::Result<u64> {
    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "VmRSS" {
            continue;
        }
        let mut tokens = value.split_whitespace();
        let count = tokens.next().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "VmRSS is missing a kibibyte count")
        })?;
        let unit = tokens.next().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "VmRSS is missing the kB unit")
        })?;
        if unit != "kB" {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "VmRSS unit must be kB",
            ));
        }
        if tokens.next().is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "VmRSS has trailing tokens after the kB unit",
            ));
        }
        let kib = count.parse::<u64>().map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "VmRSS is not an integer kibibyte count",
            )
        })?;
        return kib
            .checked_mul(1024)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "VmRSS overflows a byte count"));
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        "VmRSS is missing from /proc/self/status",
    ))
}
