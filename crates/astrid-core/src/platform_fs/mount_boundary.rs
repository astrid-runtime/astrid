//! Reject device transitions and, on Linux, same-device bind mounts.

#[cfg(unix)]
use nix::sys::stat::fstat;
#[cfg(unix)]
use std::fs::File;
use std::io;

#[cfg(unix)]
pub(crate) struct MountBoundary {
    device: nix::libc::dev_t,
    #[cfg(target_os = "linux")]
    mount: MountId,
}

#[cfg(unix)]
impl MountBoundary {
    pub(crate) fn new(root: &File) -> io::Result<Self> {
        Ok(Self {
            device: fstat(root).map_err(super::nix_io_error)?.st_dev,
            #[cfg(target_os = "linux")]
            mount: MountId::of(root)?,
        })
    }

    pub(crate) fn validate(&self, child: &File) -> io::Result<()> {
        self.validate_device(fstat(child).map_err(super::nix_io_error)?.st_dev)?;
        #[cfg(target_os = "linux")]
        if MountId::of(child)? != self.mount {
            return Err(invalid("projection crosses a mount boundary"));
        }
        Ok(())
    }

    pub(crate) fn validate_device(&self, device: nix::libc::dev_t) -> io::Result<()> {
        if device != self.device {
            return Err(invalid("projection crosses a device boundary"));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountId(std::num::NonZeroU64);

#[cfg(any(target_os = "linux", test))]
impl MountId {
    #[cfg(target_os = "linux")]
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        use std::os::fd::AsRawFd as _;

        // fdinfo describes the already-open descriptor. This path supplies
        // mount metadata only and never grants authority to remove anything.
        // Missing procfs/mnt_id is an error; st_dev alone cannot detect binds.
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        Self::parse(&info)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn require_same(self, file: &File, path: &std::path::Path) -> io::Result<()> {
        if Self::of(file)? != self {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime projection crosses a Linux mount boundary: {}",
                    path.display()
                ),
            ));
        }
        Ok(())
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
                    return Err(invalid("malformed fdinfo mount identity"));
                }
                let number = value
                    .parse::<u64>()
                    .ok()
                    .and_then(std::num::NonZeroU64::new)
                    .ok_or_else(|| invalid("invalid fdinfo mount identity"))?;
                mount = Some(Self(number));
            }
        }
        mount.ok_or_else(|| invalid("fdinfo lacks mount identity"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_descriptors_from_different_mounts_are_rejected() {
        let root = std::fs::File::open("/").unwrap();
        let proc = std::fs::File::open("/proc").unwrap();
        let root_id = MountId::of(&root).unwrap();
        assert_ne!(root_id, MountId::of(&proc).unwrap());
        assert!(
            root_id
                .require_same(&proc, std::path::Path::new("/proc"))
                .is_err()
        );
        root_id
            .require_same(&root, std::path::Path::new("/"))
            .unwrap();
    }
}

#[cfg(all(any(test, feature = "test-support"), target_os = "linux"))]
pub mod fixtures;
