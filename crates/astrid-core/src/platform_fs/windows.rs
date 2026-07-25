#![allow(unsafe_code)]

#[path = "windows/acl.rs"]
mod acl;
#[path = "windows/error.rs"]
mod error;
#[path = "windows/executable.rs"]
mod executable;
#[path = "windows/io.rs"]
mod io;
#[path = "windows/path.rs"]
mod path;
#[path = "windows/prelude.rs"]
mod prelude;
#[path = "windows/private_file.rs"]
mod private_file;

pub(super) use executable::{recover_executable_transaction, replace_executable_set};
pub(super) use path::{
    default_astrid_home_root, ensure_private_directory, restrict_private_file,
    validate_private_file, verify_no_redirects,
};
pub(super) use private_file::{atomic_write_private_file, read_private_file_to_string};

pub(super) fn acquire_private_file_lock(
    path: &std::path::Path,
    owner_description: &str,
) -> std::io::Result<std::fs::File> {
    path::validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private lock file has no parent directory",
        )
    })?;
    let guard = path::TrustedPathGuard::capture(parent)?;
    guard.verify_contract(path::BoundaryContract::ExactPrivateDirectory)?;
    io::acquire_named_private_lock(&guard, path, owner_description)
}

pub(super) fn open_private_append_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    path::validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private append file has no parent directory",
        )
    })?;
    let guard = path::TrustedPathGuard::capture(parent)?;
    guard.verify_contract(path::BoundaryContract::ExactPrivateDirectory)?;
    io::open_guarded_private_append_file(&guard, path)
}

#[cfg(test)]
#[path = "windows/tests.rs"]
mod native_tests;
