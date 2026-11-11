#![allow(unsafe_code)]

#[path = "windows/acl.rs"]
mod acl;
#[path = "windows/captured_directory.rs"]
mod captured_directory;
#[path = "windows/directory_capability.rs"]
pub mod directory_capability;
#[cfg(test)]
#[path = "windows/directory_durability.rs"]
mod directory_durability;
#[path = "windows/error.rs"]
mod error;
#[path = "windows/executable.rs"]
mod executable;
#[path = "windows/io.rs"]
mod io;
#[path = "windows/ntfs_directory_flush.rs"]
pub(crate) mod ntfs_directory_flush;
#[path = "windows/path.rs"]
mod path;
#[path = "windows/prelude.rs"]
mod prelude;
#[path = "windows/private_file.rs"]
mod private_file;
#[path = "windows/projection_session/mod.rs"]
mod projection_session;
#[path = "windows/rename.rs"]
mod rename;
#[path = "windows/retirement_support.rs"]
pub(crate) mod retirement_support;

pub use captured_directory::CapturedDirectory;
pub use io::create_new_private_file;

/// Validate `ExactPrivate` ACL on an open file handle without reopening the path.
pub fn validate_private_file_handle(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    acl::validate_private_acl_handle(file.as_raw_handle().cast(), false, "private file handle")
}
pub(super) use executable::replace_executable_set;
pub(super) use path::{
    create_private_directory, default_astrid_home_root, ensure_private_directory,
    restrict_private_file, validate_private_directory, validate_private_file, verify_no_redirects,
};
pub(super) use private_file::{atomic_write_private_file, read_private_file_to_string};
pub(in crate::platform_fs) use projection_session::{
    ProjectionInspection, ProjectionRoot, create_private_scratch_file,
};
pub(super) use rename::rename_with_write_through;

#[cfg(test)]
#[path = "windows/tests.rs"]
mod native_tests;
