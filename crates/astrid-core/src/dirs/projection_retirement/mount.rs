//! Reject device transitions and, on Linux, same-device bind mounts.

use nix::sys::stat::fstat;
use std::fs::File;
use std::io;

pub(super) struct MountBoundary {
    device: nix::libc::dev_t,
    #[cfg(target_os = "linux")]
    mount: MountId,
}

impl MountBoundary {
    pub(super) fn new(root: &File) -> io::Result<Self> {
        Ok(Self {
            device: fstat(root).map_err(super::nix_error)?.st_dev,
            #[cfg(target_os = "linux")]
            mount: MountId::read(root)?,
        })
    }

    pub(super) fn validate(&self, child: &File) -> io::Result<()> {
        self.validate_device(fstat(child).map_err(super::nix_error)?.st_dev)?;
        #[cfg(target_os = "linux")]
        if MountId::read(child)? != self.mount {
            return Err(super::invalid("projection crosses a mount boundary"));
        }
        Ok(())
    }

    pub(super) fn validate_device(&self, device: nix::libc::dev_t) -> io::Result<()> {
        if device != self.device {
            return Err(super::invalid("projection crosses a device boundary"));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Eq, PartialEq)]
struct MountId(std::num::NonZeroU64);

#[cfg(any(target_os = "linux", test))]
impl MountId {
    #[cfg(target_os = "linux")]
    fn read(file: &File) -> io::Result<Self> {
        use std::os::fd::AsRawFd as _;

        // fdinfo describes the already-open descriptor. This path supplies
        // mount metadata only and never grants authority to remove anything.
        // Missing procfs/mnt_id is an error; st_dev alone cannot detect binds.
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        Self::parse(&info)
    }

    fn parse(info: &str) -> io::Result<Self> {
        let mut mount = None;
        for line in info.lines() {
            if let Some(value) = line.strip_prefix("mnt_id:") {
                let value = value.trim_ascii();
                if mount.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(super::invalid("malformed fdinfo mount identity"));
                }
                let number = value
                    .parse::<u64>()
                    .ok()
                    .and_then(std::num::NonZeroU64::new)
                    .ok_or_else(|| super::invalid("invalid fdinfo mount identity"))?;
                mount = Some(Self(number));
            }
        }
        mount.ok_or_else(|| super::invalid("fdinfo lacks mount identity"))
    }
}

#[cfg(test)]
mod tests {
    use super::MountId;

    #[test]
    fn mount_id_parser_accepts_kernel_decimal_field() {
        assert_eq!(
            MountId::parse("pos:\t0\nflags:\t0100000\nmnt_id:\t37\nino:\t9\n")
                .unwrap()
                .0
                .get(),
            37
        );
    }

    #[test]
    fn mount_id_parser_rejects_missing_duplicate_and_malformed_fields() {
        for info in [
            "",
            "mnt_id:\t0",
            "mnt_id:\t+1",
            "mnt_id:\t-1",
            "mnt_id:\t1 2",
            "mnt_id:\t",
            "mnt_id:\t18446744073709551616",
            "mnt_id: 1\nmnt_id: 1",
        ] {
            assert!(MountId::parse(info).is_err(), "accepted {info:?}");
        }
    }
}
