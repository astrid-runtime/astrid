//! Small Windows encoding and operating-system error helpers.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt as _;

pub(super) fn wide_nul(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub(super) fn last_error(context: &str) -> io::Error {
    let source = io::Error::last_os_error();
    io::Error::new(source.kind(), format!("{context}: {source}"))
}
