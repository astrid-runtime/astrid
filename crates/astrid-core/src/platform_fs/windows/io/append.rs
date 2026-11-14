//! Guarded private append open: create-or-open without overwrite authority.

use super::super::acl::{apply_private_acl_to_handle, validate_private_acl_handle};
use super::super::path::{BoundaryContract, TrustedPathGuard};
use super::super::prelude::*;
use super::open_guarded_child_with_options;

#[cfg(test)]
thread_local! {
    pub(in crate::platform_fs::windows) static TEST_APPLY_PRIVATE_ACL_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn repair_existing_private_append_acl(handle: HANDLE) -> io::Result<()> {
    #[cfg(test)]
    TEST_APPLY_PRIVATE_ACL_COUNT.with(|count| count.set(count.get().strict_add(1)));
    apply_private_acl_to_handle(handle, false)
}

pub(in crate::platform_fs::windows) fn open_guarded_private_append(
    guard: &TrustedPathGuard,
    name: &OsStr,
) -> io::Result<File> {
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    let access = FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC;
    let sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let (handle, created) = match open_guarded_child_with_options(
        guard.authority_handle(),
        name,
        access,
        sharing,
        FILE_CREATE,
    ) {
        Ok(handle) => (handle, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            open_guarded_child_with_options(
                guard.authority_handle(),
                name,
                access,
                sharing,
                FILE_OPEN,
            )?,
            false,
        ),
        Err(error) => return Err(error),
    };
    // FILE_CREATE already installs the protected DACL. Existing leaves still
    // need repair. FILE_WRITE_DATA is never requested: ordinary writes append.
    // Rust 1.95 OpenOptions.append also withholds FILE_WRITE_DATA, and
    // File::sync_all is FlushFileBuffers on that same append handle.
    if !created {
        repair_existing_private_append_acl(handle.0)?;
    }
    validate_private_acl_handle(handle.0, false, &name.to_string_lossy())?;
    let file = File::from(handle);
    let observed = File::from(open_guarded_child_with_options(
        guard.authority_handle(),
        name,
        FILE_READ_ATTRIBUTES,
        sharing,
        FILE_OPEN,
    )?);
    if super::super::captured_directory::query_directory_identity(&observed)?
        != super::super::captured_directory::query_directory_identity(&file)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "append leaf binding changed",
        ));
    }
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    Ok(file)
}
