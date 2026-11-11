//! Handle-relative private descendant capture for [`TrustedPathGuard`].
//!
//! Descendants are derived from duplicated root identity handles. Ambient
//! absolute re-capture is rejected so a mid-walk spelling swap cannot replace
//! the retained object identity.

use super::super::acl::validate_private_acl_handle;
use super::super::error::with_context;
use super::super::prelude::*;
use super::{
    BoundaryContract, CreatedPrivateDirectories, FileIdentity, LockedPathComponent, OwnedHandle,
    TrustedPathGuard, create_private_directory_identity_relative, open_directory_identity_relative,
};

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
            self.capture_or_create_relative_from_retained_handles(relative, target)
        } else {
            self.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            let descendant = self.capture_relative_from_retained_handles(relative, target)?;
            descendant.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            self.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            Ok(descendant)
        }
    }

    fn capture_or_create_relative_from_retained_handles(
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
            self.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
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

fn duplicate_handle_same_access(source: HANDLE) -> io::Result<OwnedHandle> {
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
