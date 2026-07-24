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

pub(super) use executable::replace_executable_set;
pub(super) use path::{
    default_astrid_home_root, ensure_private_directory, restrict_private_file,
    validate_private_file, verify_no_redirects,
};
pub(super) use private_file::{atomic_write_private_file, read_private_file_to_string};

#[cfg(test)]
#[path = "windows/tests.rs"]
mod native_tests;
