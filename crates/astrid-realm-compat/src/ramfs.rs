//! Ephemeral in-memory namespace. Not a host directory and not a volume.

/// Empty ramfs owned by the reference interpreter.
///
/// There is no host path, `home://` URI, cwd fallback, or volume region.
/// Guest paths are never Astrid authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EphemeralRamfs;

impl EphemeralRamfs {
    /// Construct an empty ephemeral namespace.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Host path probe. Always `None`: this namespace is not ambient host FS.
    #[must_use]
    pub const fn as_host_path(&self) -> Option<&'static str> {
        let _ = self;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::EphemeralRamfs;

    #[test]
    fn ramfs_has_no_host_path_or_home_uri() {
        let ramfs = EphemeralRamfs::new();
        assert!(ramfs.as_host_path().is_none());
        assert_ne!(EphemeralRamfs::new().as_host_path(), Some("home://"));
        assert_ne!(EphemeralRamfs::new().as_host_path(), Some("/"));
    }
}
