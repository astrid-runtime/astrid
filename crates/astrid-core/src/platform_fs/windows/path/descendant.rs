//! Handle-relative private descendant capture for [`TrustedPathGuard`].
//!
//! Descendants are derived from duplicated root identity handles. Ambient
//! absolute re-capture is rejected so a mid-walk spelling swap cannot replace
//! the retained object identity.

use std::os::windows::io::BorrowedHandle;

use super::super::acl::validate_private_acl_handle;
use super::super::error::with_context;
use super::super::ntfs_directory_flush::{
    open_flush_bound_to_authority, open_flush_relative_bound_to_authority,
};
use super::super::prelude::*;
use super::{
    BoundaryContract, CreatedPrivateDirectories, FileIdentity, LockedPathComponent, OwnedHandle,
    TrustedPathGuard, create_private_directory_identity_relative, open_directory_identity_relative,
};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static DESCENDANT_NAMESPACE_FLUSH_FAILURES: Cell<usize> = const { Cell::new(0) };
    /// When set, the next parent-namespace flush fails after a successful child flush.
    static DESCENDANT_PARENT_NAMESPACE_FLUSH_FAIL: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
/// Arm the next `count` create-time directory namespace flush failures on this thread.
pub(in crate::platform_fs::windows) fn install_descendant_namespace_flush_failures(
    count: usize,
) -> DescendantNamespaceFlushFaultReset {
    DESCENDANT_NAMESPACE_FLUSH_FAILURES.with(|slot| slot.set(count));
    DescendantNamespaceFlushFaultReset
}

#[cfg(test)]
/// Fail only the parent fence after a successful child flush (discriminating regression).
pub(in crate::platform_fs::windows) fn install_descendant_parent_namespace_flush_failure()
-> DescendantNamespaceFlushFaultReset {
    DESCENDANT_PARENT_NAMESPACE_FLUSH_FAIL.with(|slot| slot.set(true));
    DescendantNamespaceFlushFaultReset
}

#[cfg(test)]
#[must_use]
pub(in crate::platform_fs::windows) struct DescendantNamespaceFlushFaultReset;

#[cfg(test)]
impl Drop for DescendantNamespaceFlushFaultReset {
    fn drop(&mut self) {
        DESCENDANT_NAMESPACE_FLUSH_FAILURES.with(|slot| slot.set(0));
        DESCENDANT_PARENT_NAMESPACE_FLUSH_FAIL.with(|slot| slot.set(false));
    }
}

#[cfg(test)]
fn test_maybe_fail_descendant_namespace_flush() -> io::Result<()> {
    DESCENDANT_NAMESPACE_FLUSH_FAILURES.with(|slot| {
        let remaining = slot.get();
        if remaining == 0 {
            return Ok(());
        }
        slot.set(remaining.strict_sub(1));
        Err(io::Error::other(
            "injected descendant namespace flush failure",
        ))
    })
}

#[cfg(test)]
fn test_maybe_fail_descendant_parent_namespace_flush() -> io::Result<()> {
    let should_fail = DESCENDANT_PARENT_NAMESPACE_FLUSH_FAIL.with(|slot| {
        let armed = slot.get();
        if armed {
            slot.set(false);
        }
        armed
    });
    if should_fail {
        Err(io::Error::other(
            "injected descendant parent namespace flush failure",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
/// After the first relative component is retained, rename `from` to `parked`
/// and move `replacement` onto `from` before the walk continues.
pub(in crate::platform_fs::windows) static TEST_MOVE_DESCENDANT_DURING_CAPTURE: std::sync::Mutex<
    Option<(PathBuf, PathBuf, PathBuf)>,
> = std::sync::Mutex::new(None);

impl TrustedPathGuard {
    /// Open or create a private descendant directory relative to this authority.
    ///
    /// When `create` is true, each component is opened if present (`ExactPrivate`)
    /// or created with a birth-time private ACL if absent. Partial creates are
    /// cleaned up on failure. The returned guard keeps the root identity chain
    /// by duplicating retained handles and appending root-relative opens—never
    /// ambient path capture.
    pub(in crate::platform_fs::windows) fn capture_descendant_directory(
        &self,
        relative: &[OsString],
        create: bool,
    ) -> io::Result<Self> {
        validate_relative_directory_components(relative)?;
        let target =
            relative
                .iter()
                .fold(self.authority_boundary().to_path_buf(), |mut path, part| {
                    path.push(part);
                    path
                });

        if create {
            self.verify_contract(BoundaryContract::TrustedForCreate)?;
            self.capture_or_create_relative_from_retained_handles(
                relative,
                target,
                BoundaryContract::ExactPrivateDirectory,
            )
        } else {
            self.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            let descendant = self.capture_relative_from_retained_handles(relative, target)?;
            descendant.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            self.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            Ok(descendant)
        }
    }

    /// Capture privately born descendants beneath a `TrustedForCreate` boundary.
    ///
    /// Unlike projection descent, the existing ancestor need not itself have
    /// the `ExactPrivate` ACL. Every returned descendant still must have it.
    pub(in crate::platform_fs::windows) fn capture_private_descendants_for_create(
        &self,
        relative: &[OsString],
    ) -> io::Result<Self> {
        validate_relative_directory_components(relative)?;
        self.verify_contract(BoundaryContract::TrustedForCreate)?;
        let target =
            relative
                .iter()
                .fold(self.authority_boundary().to_path_buf(), |mut path, part| {
                    path.push(part);
                    path
                });
        self.capture_or_create_relative_from_retained_handles(
            relative,
            target,
            BoundaryContract::TrustedForCreate,
        )
    }

    fn capture_or_create_relative_from_retained_handles(
        &self,
        relative: &[OsString],
        target: PathBuf,
        parent_contract: BoundaryContract,
    ) -> io::Result<Self> {
        let mut components = duplicate_locked_components(&self.components)?;
        let mut parent = components
            .last()
            .expect("captured Windows path has an authority component")
            .handle
            .0;
        let mut current = self.authority_boundary.clone();
        let mut created = CreatedPrivateDirectories::with_capacity(relative.len());

        let result = (|| {
            for (index, name) in relative.iter().enumerate() {
                let lock_leaf = Some(index) == relative.len().checked_sub(1);
                current.push(name);
                let (handle, identity, newly_created) =
                    open_or_create_private_directory_relative(parent, name, lock_leaf)?;
                let handle = if newly_created {
                    // Retain DELETE authority before the first fallible duplicate.
                    // Both handles refer to the object returned by FILE_CREATE.
                    created.push(current.clone(), handle);
                    duplicate_handle_same_access(
                        created
                            .last_handle()
                            .expect("created directory was just retained"),
                    )?
                } else {
                    handle
                };
                validate_private_acl_handle(handle.0, true, &current.display().to_string())?;
                if newly_created {
                    // Unix create parity: fsync(new dir) + fsync(parent).
                    // Parent path is `current` without the leaf just pushed — no clone.
                    let parent_path = current.parent().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "created projection directory has no parent path",
                        )
                    })?;
                    flush_created_child_directory(parent, name, handle.0)?;
                    flush_parent_directory_at(parent_path, parent)?;
                }
                parent = handle.0;
                components.push(LockedPathComponent {
                    path: current.clone(),
                    identity,
                    handle,
                });
                #[cfg(test)]
                after_descendant_component(index)?;
            }
            let descendant = Self {
                components: std::mem::take(&mut components),
                authority_boundary: target,
            };
            descendant.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            self.verify_contract(parent_contract)?;
            Ok(descendant)
        })();

        match result {
            Ok(descendant) => {
                created.disarm();
                Ok(descendant)
            },
            Err(error) => {
                // Release retained opens so cleanup can mark newly created dirs.
                drop(components);
                match created.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(with_context(
                        error,
                        format!(
                            "private Windows descendant creation failed and partial cleanup also failed: {cleanup_error}"
                        ),
                    )),
                }
            },
        }
    }

    fn capture_relative_from_retained_handles(
        &self,
        relative: &[OsString],
        target: PathBuf,
    ) -> io::Result<Self> {
        let mut components = duplicate_locked_components(&self.components)?;
        let mut parent = components
            .last()
            .expect("captured Windows path has an authority component")
            .handle
            .0;
        let mut current = self.authority_boundary.clone();
        for (index, name) in relative.iter().enumerate() {
            let lock_leaf = Some(index) == relative.len().checked_sub(1);
            let (handle, identity) = open_directory_identity_relative(parent, name, lock_leaf)?;
            current.push(name);
            validate_private_acl_handle(handle.0, true, &current.display().to_string())?;
            parent = handle.0;
            components.push(LockedPathComponent {
                path: current.clone(),
                identity,
                handle,
            });
            #[cfg(test)]
            after_descendant_component(index)?;
        }
        Ok(Self {
            components,
            authority_boundary: target,
        })
    }
}

/// Open an `ExactPrivate` directory component, or create it with birth-time ACL.
///
/// Existing components are never recreated. `AlreadyExists` on create races
/// falls back to open+`ExactPrivate` validation. Returns whether this call
/// created the component (for partial-failure cleanup).
fn open_or_create_private_directory_relative(
    parent: HANDLE,
    name: &OsStr,
    lock_against_rename: bool,
) -> io::Result<(OwnedHandle, FileIdentity, bool)> {
    match open_directory_identity_relative(parent, name, lock_against_rename) {
        Ok((handle, identity)) => Ok((handle, identity, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_private_directory_identity_relative(parent, name) {
                // Keep the birth handle and its identity continuously; reopening
                // by name would discard cleanup authority and admit a substitute.
                Ok((created, identity)) => Ok((created, identity, true)),
                Err(create_error) if create_error.kind() == io::ErrorKind::AlreadyExists => {
                    let (handle, identity) =
                        open_directory_identity_relative(parent, name, lock_against_rename)?;
                    Ok((handle, identity, false))
                },
                Err(create_error) => Err(create_error),
            }
        },
        Err(error) => Err(error),
    }
}

pub(super) fn flush_created_child_directory(
    parent: HANDLE,
    name: &OsStr,
    child: HANDLE,
) -> io::Result<()> {
    #[cfg(test)]
    test_maybe_fail_descendant_namespace_flush()?;
    // Child birth/cleanup handle is the no-SHARE_DELETE authority proof; derived
    // flusher opens with SHARE_DELETE to coexist (paired cap owns the duplicate).
    // SAFETY: `child` remains owned by CreatedPrivateDirectories / component.
    let authority = unsafe { BorrowedHandle::borrow_raw(child.cast()) };
    open_flush_relative_bound_to_authority(parent, name, authority)?.flush()
}

pub(super) fn flush_parent_directory_at(path: &Path, handle: HANDLE) -> io::Result<()> {
    #[cfg(test)]
    {
        test_maybe_fail_descendant_parent_namespace_flush()?;
        test_maybe_fail_descendant_namespace_flush()?;
    }
    // Retain the caller's live parent object (DuplicateHandle SAME_ACCESS + FileId
    // bind). Sharing mode follows that caller's boundary contract: the selected
    // authority leaf / birth cleanup handle omits FILE_SHARE_DELETE, but an
    // existing intermediate opened with lock_leaf=false may allow FILE_SHARE_DELETE.
    // Do not FileId-only reopen.
    // SAFETY: `handle` remains owned by the active parent component / guard dup.
    let authority = unsafe { BorrowedHandle::borrow_raw(handle.cast()) };
    open_flush_bound_to_authority(path, authority)?.flush()
}

fn validate_relative_directory_components(relative: &[OsString]) -> io::Result<()> {
    if relative.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descendant directory path is empty",
        ));
    }
    for part in relative {
        let bytes = part.as_encoded_bytes();
        if part.is_empty() || part == "." || part == ".." || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "descendant directory path contains a non-normal component",
            ));
        }
    }
    Ok(())
}

fn duplicate_locked_components(
    components: &[LockedPathComponent],
) -> io::Result<Vec<LockedPathComponent>> {
    let mut duplicated = Vec::with_capacity(components.len());
    for component in components {
        duplicated.push(LockedPathComponent {
            path: component.path.clone(),
            identity: component.identity,
            handle: duplicate_handle_same_access(component.handle.0)?,
        });
    }
    Ok(duplicated)
}

pub(super) fn duplicate_handle_same_access(source: HANDLE) -> io::Result<OwnedHandle> {
    let mut duplicate = null_mut();
    // SAFETY: source handle and the current process remain live; a successful
    // call creates one new owned handle with identical access rights.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "duplicate retained Windows path component handle",
        ));
    }
    Ok(OwnedHandle(duplicate))
}

#[cfg(test)]
fn after_descendant_component(index: usize) -> io::Result<()> {
    if index != 0 {
        return Ok(());
    }
    let swap = TEST_MOVE_DESCENDANT_DURING_CAPTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some((from, parked, replacement)) = swap else {
        return Ok(());
    };
    std::fs::rename(&from, &parked)?;
    std::fs::rename(&replacement, &from)?;
    Ok(())
}
