//! Handle-bound Windows namespace transitions used by private migrations.

use std::fs::OpenOptions;
use std::io;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileRenameInfo,
    SetFileInformationByHandle,
};

use super::{PrivateRenameIdentity, private_file_identity};

pub(in crate::principal_state) fn rename_windows_no_replace(
    source: &Path,
    destination: &Path,
    expected: PrivateRenameIdentity,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let source_file = options.open(source)?;
    let PrivateRenameIdentity::File(expected) = expected else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows handle-bound directory rename is unsupported",
        ));
    };
    if private_file_identity(&source_file).map_err(|error| io::Error::other(error.to_string()))?
        != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::StaleNetworkFileHandle,
            "private source changed before no-replace rename",
        ));
    }
    let destination_name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let name_words = destination_name.len();
    let buffer_words = usize::checked_add(4, name_words.div_ceil(2))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large"))?;
    let mut buffer = vec![0_u64; buffer_words];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: all writes remain inside the aligned zeroed allocation.
    #[allow(unsafe_code)]
    unsafe {
        std::ptr::addr_of_mut!((*information).Anonymous.ReplaceIfExists).write(false);
        std::ptr::addr_of_mut!((*information).RootDirectory).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*information).FileNameLength).write(
            u32::try_from(name_words).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename path is too long")
            })?,
        );
        let file_name = std::ptr::addr_of_mut!((*information).FileName).cast::<u16>();
        std::ptr::copy_nonoverlapping(destination_name.as_ptr(), file_name, name_words);
    }
    // SAFETY: the source handle and rename buffer remain live for the call.
    #[allow(unsafe_code)]
    if unsafe {
        SetFileInformationByHandle(
            source_file.as_raw_handle(),
            FileRenameInfo,
            information.cast(),
            u32::try_from(buffer.len().saturating_mul(size_of::<u64>())).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large")
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let destination_file = options.open(destination)?;
    if private_file_identity(&destination_file)
        .map_err(|error| io::Error::other(error.to_string()))?
        != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::StaleNetworkFileHandle,
            "private destination does not name the verified source",
        ));
    }
    Ok(())
}
