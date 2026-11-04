//! One bounded, rooted session for restoring private projection files.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path};

use super::StagingScope;

mod compare;

#[cfg(unix)]
#[path = "private_projection/unix/mod.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "private_projection/portable.rs"]
mod platform;

/// Restore private files relative to one captured projection root.
///
/// Each Unix file retains its data and parent metadata fsyncs. Call [`Self::sync`]
/// after the batch, including after rollback or a failed operation, to complete
/// the root hardware durability fence and validate the absolute root binding.
/// Descriptors are bounded by the root and the current relative path depth;
/// no directory cache grows with the number of files.
pub struct PrivateFileProjection {
    platform: platform::Projection,
}

impl PrivateFileProjection {
    /// Open an existing projection root without following redirects.
    ///
    /// Opening can repair root privacy; snapshots can repair parent privacy.
    /// A caller requiring crash recovery must durably record its recovery
    /// intent before opening this session, and retain that intent until sync.
    ///
    /// # Errors
    /// Returns an error if the root is missing, redirected, or cannot be private.
    pub fn open(root: &Path) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Projection::open(root)?,
        })
    }

    /// Open a projection root bound to a durable restoration staging scope.
    ///
    /// Temporary basenames created by this session embed `scope`. Callers must
    /// record that same scope in the RETIRING receipt before opening. Standalone
    /// [`Self::open`] remains available for non-restoration callers.
    ///
    /// # Errors
    /// Returns an error if the root is missing, redirected, or cannot be private.
    pub fn open_with_staging(root: &Path, scope: StagingScope) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Projection::open_with_staging(root, scope)?,
        })
    }

    /// Snapshot an existing regular destination for rollback.
    ///
    /// Existing regular files may have ordinary modes, owners or other hard
    /// links; replacement creates a new private file without altering aliases.
    ///
    /// # Errors
    /// Returns an error for invalid names, redirects, special files or I/O failure.
    pub fn snapshot(&self, relative: &Path) -> io::Result<Option<Vec<u8>>> {
        self.platform.snapshot(&RelativePath::parse(relative)?)
    }

    /// Atomically publish a private regular file and fsync its data and parent.
    ///
    /// # Errors
    /// Returns an error on unsafe paths, changed identities or any write/fence failure.
    pub fn write(&self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        self.platform.write(&RelativePath::parse(relative)?, bytes)
    }

    /// Remove a regular projected file during rollback; absence is success.
    ///
    /// This path intentionally accepts ordinary prior host generations. Staging
    /// cleanup must use [`Self::remove_staging`] or
    /// [`Self::remove_authorized_private_leaf`] so private-file contracts bind
    /// the captured leaf through unlink.
    ///
    /// # Errors
    /// Returns an error for redirects, special entries, changed identities or I/O failure.
    pub fn remove(&self, relative: &Path) -> io::Result<()> {
        self.platform.remove(&RelativePath::parse(relative)?)
    }

    /// Remove a scoped staging temporary under the bound restoration session.
    ///
    /// Enforces private ownership (uid/mode/nlink/ACL) on the captured leaf and
    /// requires `relative`'s basename to embed `scope`.
    ///
    /// # Errors
    /// Returns an error for scope mismatch, non-private leaves, redirects, or I/O failure.
    pub fn remove_staging(&self, relative: &Path, scope: StagingScope) -> io::Result<()> {
        self.platform
            .remove_staging(&RelativePath::parse(relative)?, scope)
    }

    /// Remove a private single-link leaf after the caller established discard authority.
    ///
    /// Legacy etc sentinel cleanup uses this after receipt/etc classification.
    /// Prefer [`Self::remove_staging`] whenever a durable scope exists.
    ///
    /// # Errors
    /// Returns an error for non-private leaves, redirects, specials, or I/O failure.
    pub fn remove_authorized_private_leaf(&self, relative: &Path) -> io::Result<()> {
        self.platform
            .remove_authorized_private_leaf(&RelativePath::parse(relative)?)
    }

    /// Create a private directory marker, fsyncing changed directory metadata.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, directory substitutions or I/O failure.
    pub fn ensure_directory(&self, relative: &Path) -> io::Result<()> {
        self.platform
            .ensure_directory(&RelativePath::parse(relative)?)
    }

    /// Complete the batch's terminal durability fence and validate its root.
    ///
    /// # Errors
    /// Returns an error for a changed root binding or an unsuccessful fence.
    pub fn sync(&self) -> io::Result<()> {
        self.platform.sync()
    }
}

/// Read-only matching against one captured private projection root.
///
/// Unlike [`PrivateFileProjection`], opening never repairs privacy and directory
/// walks never create parents. Matching opens through the same root-bound
/// mount/device boundary used by the writer, so same-device Linux bind mounts
/// cannot satisfy an unchanged skip.
pub struct PrivateProjectionInspection {
    platform: platform::Inspection,
}

impl PrivateProjectionInspection {
    /// Open an already-private projection root without following redirects.
    ///
    /// # Errors
    /// Returns an error if the root is missing, redirected, or not private.
    pub fn try_open(root: &Path) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Inspection::try_open(root)?,
        })
    }

    /// Return whether `relative` is an existing private directory under the root.
    ///
    /// # Errors
    /// Returns an error for unexpected I/O outside ordinary non-match conditions.
    pub fn matches_private_directory(&self, relative: &Path) -> io::Result<bool> {
        self.platform
            .matches_private_directory(&RelativePath::parse(relative)?)
    }

    /// Return whether `relative` is a private single-link file with `expected` bytes.
    ///
    /// # Errors
    /// Returns an error for unexpected I/O outside ordinary non-match conditions.
    pub fn matches_private_file(&self, relative: &Path, expected: &[u8]) -> io::Result<bool> {
        self.platform
            .matches_private_file(&RelativePath::parse(relative)?, expected)
    }

    /// Revalidate the absolute root binding after an all-matching inspection pass.
    ///
    /// # Errors
    /// Returns an error when the absolute root binding or mount boundary changed.
    pub fn confirm_absolute_root(&self) -> io::Result<()> {
        self.platform.confirm_absolute_root()
    }
}

struct RelativePath(Vec<OsString>);

impl RelativePath {
    fn parse(path: &Path) -> io::Result<Self> {
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => names.push(name.to_os_string()),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "projection path is not strictly relative",
                    ));
                },
            }
        }
        // components() normalizes interior dots and repeated separators. Reject
        // those spellings too, while accepting either native Windows separator.
        let abnormal = path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/' || cfg!(windows) && *byte == b'\\')
            .any(|part| part.is_empty() || part == b"." || part == b"..");
        if names.is_empty() || abnormal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "projection path contains a non-normal component",
            ));
        }
        Ok(Self(names))
    }
}
