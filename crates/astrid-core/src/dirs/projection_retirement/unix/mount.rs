//! Linux mount identities bound to our own opened descriptors.
//!
//! Bind mounts can share device and inode numbers with their source. Reading
//! each opened handle's mount ID avoids resolving an ambient pathname or
//! caching a mount-table snapshot that misses mounts added during retirement.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MountId(u64);

impl MountId {
    pub(super) fn of(file: &File) -> io::Result<Self> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        Self::parse(&info)
    }

    pub(super) fn require_same(self, file: &File, path: &Path) -> io::Result<()> {
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
        let mut ids = info.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
        let id = ids.next().and_then(|value| value.trim().parse().ok());
        match (id, ids.next()) {
            (Some(id), None) => Ok(Self(id)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened projection handle has no unambiguous Linux mount identity",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MountId;

    #[test]
    fn mount_identity_is_required_and_unambiguous() {
        assert_eq!(
            MountId::parse("pos: 0\nmnt_id:\t123\n").unwrap(),
            MountId(123)
        );
        for malformed in ["", "mnt_id:", "mnt_id: nope", "mnt_id: 1\nmnt_id: 2"] {
            assert!(MountId::parse(malformed).is_err(), "{malformed:?}");
        }
    }

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
