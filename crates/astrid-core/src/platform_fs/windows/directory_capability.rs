//! Public Windows staging flush/rename facade over existing NT primitives.
//!
//! Reuses paired [`NtfsDirectoryFlushGuard`] and the handle-relative exclusive
//! rename body. No ambient ancestor walks and no parallel flush protocol.

use super::ntfs_directory_flush::{
    NtfsDirectoryFlushGuard, open_flush_bound_to_authority, open_flush_relative_bound_to_authority,
};
use super::prelude::*;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};
use std::path::{Component, Path, PathBuf};

#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static DIRECTORY_FLUSH_FAILURES: Cell<usize> = const { Cell::new(0) };
}

/// Paired NTFS directory-structure flush capability for staging fences.
pub struct DirectoryFlushCapability {
    inner: NtfsDirectoryFlushGuard,
}

impl std::fmt::Debug for DirectoryFlushCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryFlushCapability")
            .field("identity", &self.inner.identity())
            .finish_non_exhaustive()
    }
}

impl DirectoryFlushCapability {
    pub fn flush(&self) -> io::Result<()> {
        #[cfg(any(test, feature = "test-support"))]
        test_maybe_fail_directory_flush()?;
        self.inner.flush()
    }

    #[must_use]
    pub fn file(&self) -> &File {
        self.inner.file()
    }

    #[must_use]
    pub fn identity(&self) -> crate::platform_fs::DirectoryIdentity {
        self.inner.identity()
    }
}

/// Exact single relative leaf for handle-relative Windows opens/renames.
///
/// Requires one [`Component::Normal`] whose `OsStr` equals `name` exactly (no
/// normalized suffix/prefix forms). Rejects UTF-16 NUL, `/`, `\\`, and `:`
/// (ADS / drive syntax). Non-ASCII opaque UTF-16 leaves are allowed.
pub fn validate_relative_component(name: &OsStr) -> io::Result<&OsStr> {
    if name.is_empty() {
        return Err(invalid_relative_component());
    }
    for unit in name.encode_wide() {
        if unit == 0
            || unit == u16::from(b'/')
            || unit == u16::from(b'\\')
            || unit == u16::from(b':')
        {
            return Err(invalid_relative_component());
        }
    }
    let mut components = Path::new(name).components();
    match components.next() {
        Some(Component::Normal(normal)) if normal == name && components.next().is_none() => {
            Ok(name)
        },
        _ => Err(invalid_relative_component()),
    }
}

fn invalid_relative_component() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Windows relative name must be exactly one normal path component",
    )
}

/// Open a paired flush capability bound to a live directory authority handle.
///
/// `path` is used only while an ambient open is known-good. The derived flusher
/// must match the authority `FileIdInfo` (128-bit) and an NTFS volume.
pub fn open_directory_flush(
    path: &Path,
    authority: BorrowedHandle<'_>,
) -> io::Result<DirectoryFlushCapability> {
    Ok(DirectoryFlushCapability {
        inner: open_flush_bound_to_authority(path, authority)?,
    })
}

/// Handle-relative paired flush: parent handle + single component + authority.
pub fn open_directory_flush_relative(
    parent: BorrowedHandle<'_>,
    name: &OsStr,
    authority: BorrowedHandle<'_>,
) -> io::Result<DirectoryFlushCapability> {
    let name = validate_relative_component(name)?;
    Ok(DirectoryFlushCapability {
        inner: open_flush_relative_bound_to_authority(
            parent.as_raw_handle().cast(),
            name,
            authority,
        )?,
    })
}

/// Create one regular file relative to a retained private directory.
///
/// Supplies the protected `ExactPrivate` ACL at `FILE_CREATE`, never overwrites,
/// rejects redirects and verifies both the live child and parent ACLs. Retains
/// ordinary read/write/delete sharing: the caller owns staging serialization.
/// No ambient path is opened and no existing entry's permissions are repaired.
///
/// # Errors
/// Returns an error for an invalid leaf, nonprivate parent, existing entry, or
/// failed birth/ACL checks. A failed parent postcheck deletes only the new handle.
pub fn create_private_file_relative(parent: BorrowedHandle<'_>, name: &OsStr) -> io::Result<File> {
    let name = validate_relative_component(name)?;
    let parent = parent.as_raw_handle().cast();
    super::acl::validate_private_acl_handle(parent, true, "private file parent")?;
    let file = super::io::create_private_relative_file(
        parent,
        name,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    if let Err(error) = super::acl::validate_private_acl_handle(parent, true, "private file parent")
    {
        let _ = super::path::mark_handle_for_deletion(file.as_raw_handle().cast());
        return Err(error);
    }
    Ok(file)
}

/// Create one private directory relative to a retained private parent.
///
/// Uses the same protected birth descriptor as ambient private-directory
/// creation. The caller retains responsibility for its directory durability fence.
/// Existing entries are never repaired or replaced.
///
/// # Errors
/// Rejects non-leaf names, nonprivate parents, existing entries, redirects and
/// failed ACL checks. Failed postchecks delete only the newly created handle.
pub fn create_private_directory_relative(
    parent: BorrowedHandle<'_>,
    name: &OsStr,
) -> io::Result<()> {
    let name = validate_relative_component(name)?;
    let parent = parent.as_raw_handle().cast();
    super::acl::validate_private_acl_handle(parent, true, "private directory parent")?;
    let child = super::path::create_private_directory_relative(parent, name)?;
    let checked = super::acl::validate_private_acl_handle(child.0, true, "private directory child")
        .and_then(|()| {
            super::acl::validate_private_acl_handle(parent, true, "private directory parent")
        });
    if let Err(error) = checked {
        let _ = super::path::mark_handle_for_deletion(child.0);
        return Err(error);
    }
    Ok(())
}

/// Exclusive rename of an already-opened source into `destination_parent/name`.
///
/// `destination_name` must be a single normal path component. Uses
/// `FileRenameInformation` with `ReplaceIfExists=false`.
pub fn rename_handle_no_replace(
    source: &impl AsRawHandle,
    destination_parent: &impl AsRawHandle,
    destination_name: &OsStr,
) -> io::Result<()> {
    let destination_name = validate_relative_component(destination_name)?;
    super::io::rename_by_parent_handle(
        source,
        destination_parent.as_raw_handle().cast(),
        destination_name,
        false,
    )
}

/// Open a regular-file child for exclusive rename (`DELETE | FILE_READ_ATTRIBUTES`).
pub fn open_file_child_for_exclusive_rename(
    parent: &impl AsHandle,
    name: &OsStr,
) -> io::Result<File> {
    let name = validate_relative_component(name)?;
    super::io::open_relative_file_for_exclusive_rename(
        parent.as_handle().as_raw_handle().cast(),
        name,
    )
}

/// Open a directory child for exclusive rename (`DELETE | FILE_READ_ATTRIBUTES`).
pub fn open_directory_child_for_exclusive_rename(
    parent: &impl AsHandle,
    name: &OsStr,
) -> io::Result<File> {
    let name = validate_relative_component(name)?;
    let (handle, _) = super::path::open_directory_identity_relative_with_access(
        parent.as_handle().as_raw_handle().cast(),
        name,
        false,
        DELETE | FILE_READ_ATTRIBUTES,
    )?;
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers once from OwnedHandle.
    Ok(unsafe { File::from_raw_handle(raw.cast()) })
}

#[cfg(any(test, feature = "test-support"))]
impl DirectoryFlushCapability {
    /// Arm the next `count` directory flush failures on this thread only.
    ///
    /// Available under `cfg(test)` and the `test-support` feature only.
    pub fn arm_flush_failures(count: usize) -> DirectoryFlushFaultReset {
        DIRECTORY_FLUSH_FAILURES.with(|slot| slot.set(count));
        DirectoryFlushFaultReset
    }
}

#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub struct DirectoryFlushFaultReset;

#[cfg(any(test, feature = "test-support"))]
impl Drop for DirectoryFlushFaultReset {
    fn drop(&mut self) {
        DIRECTORY_FLUSH_FAILURES.with(|slot| slot.set(0));
    }
}

#[cfg(any(test, feature = "test-support"))]
fn test_maybe_fail_directory_flush() -> io::Result<()> {
    DIRECTORY_FLUSH_FAILURES.with(|slot| {
        let remaining = slot.get();
        if remaining == 0 {
            return Ok(());
        }
        slot.set(remaining.strict_sub(1));
        Err(io::Error::other("injected directory flush failure"))
    })
}

/// Opaque retained `ExactPrivate` Windows runtime-root authority.
///
/// Holds a duplicated final-boundary [`File`] with the production no-delete
/// sharing mask, plus the admitted absolute root label. `std::fs::File` is
/// already `Send + Sync`; this type does not add unsafe auto-trait impls.
/// Dropping the last clone releases the namespace fence so ancestor rename can
/// succeed again.
pub struct RetainedPrivateRoot {
    /// Final-boundary authority; retained solely so Drop keeps the rename fence.
    _authority: File,
    path: PathBuf,
}

impl std::fmt::Debug for RetainedPrivateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedPrivateRoot")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl RetainedPrivateRoot {
    /// Create or capture `path` as `ExactPrivate` and retain its final authority.
    ///
    /// Missing roots use the existing `ensure_private_directory` birth path
    /// (create, child+parent NTFS flush, drop DELETE cleanup handles), then a
    /// normal locked capture. Existing roots must already be `ExactPrivate`;
    /// broad or redirected roots fail closed without repair. Admission begins
    /// once the post-ensure capture succeeds, before any store or volume I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when absolutization fails, the path is not a local
    /// absolute volume path, ensure/capture finds a redirect/non-directory/broad
    /// ACL, birth cannot create an `ExactPrivate` directory under a trusted
    /// parent, or host I/O fails. Non-`NotFound` capture failures propagate
    /// unchanged.
    pub fn admit(path: &Path) -> io::Result<std::sync::Arc<Self>> {
        use super::path::{BoundaryContract, TrustedPathGuard};

        let path = std::path::absolute(path)?;
        super::path::validate_local_absolute_path(&path)?;
        let guard = match TrustedPathGuard::capture(&path) {
            Ok(guard) => guard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                super::path::ensure_private_directory(&path)?;
                TrustedPathGuard::capture(&path)?
            },
            Err(error) => return Err(error),
        };
        guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let authority = guard.duplicate_authority_file()?;
        let path = guard.authority_boundary().to_path_buf();
        drop(guard);
        Ok(std::sync::Arc::new(Self {
            _authority: authority,
            path,
        }))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod relative_component_tests {
    use super::validate_relative_component;
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStringExt as _;

    #[test]
    fn rejects_escape_ads_and_separator_syntax_before_nt() {
        let rejected = ["", ".", "..", "\\", "C:", "x:y", "../x", "a\\b", "a/b"];
        for name in rejected {
            let error = validate_relative_component(OsStr::new(name)).expect_err(name);
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "{name}: {error}"
            );
        }
        let with_nul = OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]);
        let error = validate_relative_component(&with_nul).expect_err("embedded NUL");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    }

    #[test]
    fn accepts_exact_normal_ascii_and_non_ascii_leaves() {
        for name in ["writing.open", "café", "文件", "Αστρίδ"] {
            validate_relative_component(OsStr::new(name)).expect(name);
        }
    }
}
