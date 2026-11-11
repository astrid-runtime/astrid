//! Read-only host-directory naming properties used before raw restoration.

use std::io;
use std::path::Path;

/// Query whether an existing directory compares names case-sensitively.
///
/// Opens the directory without following redirects and never creates probe
/// files or repairs permissions. An indeterminate filesystem response is an
/// error: callers must not assume case sensitivity and overwrite an alias.
///
/// Linux reports the inverse of `FS_CASEFOLD_FL` (`0x40000000`, uapi protocol
/// bit). That flag is a per-directory inode attribute inherited by children
/// (ext4 `EXT4_CASEFOLD_FL`); querying the nearest existing parent is the
/// authoritative check for names that do not yet exist.
///
/// # Errors
/// Returns an error when the directory cannot be opened as a real directory
/// without following a redirect, or when its naming contract cannot be
/// determined.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
pub fn directory_is_case_sensitive(path: &Path) -> io::Result<bool> {
    cfg_select! {
        target_os = "macos" => directory_is_case_sensitive_macos(path),
        target_os = "linux" => directory_is_case_sensitive_linux(path),
        windows => directory_is_case_sensitive_windows(path),
    }
}

/// Build a Windows NT UTF-16 upcase comparison key for one projection prefix.
///
/// Each UTF-16 code unit is passed through `RtlUpcaseUnicodeChar` independently.
/// There is no Unicode normalization and surrogate pairs are not recombined.
/// This matches the user-mode NT ordinal upcase table (ntdll), which is the
/// Win32 path-compare authority Astrid uses for caseless admission. On-disk
/// NTFS `$UpCase` tables can differ on older or custom volumes; those are not
/// claimed identical here.
#[cfg(windows)]
#[must_use]
pub fn windows_nt_utf16_upcase_key(value: &str) -> Vec<u16> {
    value
        .encode_utf16()
        .map(windows_nt_utf16_upcase_unit)
        .collect()
}

/// Upcase one UTF-16 code unit with the Windows NT ordinal table.
#[cfg(windows)]
#[must_use]
#[allow(
    unsafe_code,
    reason = "Pure Windows NT code-unit mapping; no pointer or ownership boundary."
)]
fn windows_nt_utf16_upcase_unit(unit: u16) -> u16 {
    // SAFETY: RtlUpcaseUnicodeChar is a pure ntdll character mapping with no
    // pointers or shared mutable state; it returns another UTF-16 code unit.
    unsafe { windows_sys::Wdk::System::SystemServices::RtlUpcaseUnicodeChar(unit) }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn directory_is_case_sensitive_macos(path: &Path) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;

    let file = open_unix_directory(path)?;
    nix::errno::Errno::clear();
    // SAFETY: the descriptor remains owned and live; this read-only pathconf
    // selector takes no pointers and is provided by Darwin for directory names.
    let result = unsafe { nix::libc::fpathconf(file.as_raw_fd(), nix::libc::_PC_CASE_SENSITIVE) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::UnknownErrno {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "filesystem case-sensitivity query is indeterminate",
                ))
            } else {
                Err(io::Error::from_raw_os_error(error as i32))
            }
        },
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn directory_is_case_sensitive_linux(path: &Path) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;

    // Linux uapi `FS_CASEFOLD_FL` / ext4 `EXT4_CASEFOLD_FL` protocol bit. Not a
    // knob: it is the on-disk/inode flag retrieved by `FS_IOC_GETFLAGS`.
    //
    // The ioctl request encodes `sizeof(long)`, but the kernel writes an `int`
    // (see ioctl_iflags(2) / FS_IOC_GETFLAGS). Using `c_long` on big-endian
    // 64-bit would leave the value in the wrong half of the word.
    const FS_CASEFOLD_FL: nix::libc::c_int = 0x4000_0000;

    let file = open_unix_directory(path)?;
    let mut flags: nix::libc::c_int = 0;
    nix::errno::Errno::clear();
    // SAFETY: `file` owns a live O_DIRECTORY|O_NOFOLLOW descriptor; `flags` is
    // a valid mutable int for the FS_IOC_GETFLAGS output ABI.
    let result = unsafe {
        nix::libc::ioctl(
            file.as_raw_fd(),
            nix::libc::FS_IOC_GETFLAGS,
            std::ptr::addr_of_mut!(flags),
        )
    };
    if result != 0 {
        let error = nix::errno::Errno::last();
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(flags & FS_CASEFOLD_FL == 0)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn directory_is_case_sensitive_windows(path: &Path) -> io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "case-sensitivity query requires a real directory without following redirects",
        ));
    }
    let mut info = FILE_CASE_SENSITIVE_INFO { Flags: 0 };
    // SAFETY: `file` owns a live directory handle; `info` is a valid output
    // buffer for FileCaseSensitiveInfo.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileCaseSensitiveInfo,
            std::ptr::addr_of_mut!(info).cast(),
            u32::try_from(std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>())
                .expect("FILE_CASE_SENSITIVE_INFO fits in u32"),
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_unix_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
}

#[cfg(all(test, windows))]
mod windows_upcase_tests {
    use super::{windows_nt_utf16_upcase_key, windows_nt_utf16_upcase_unit};

    #[test]
    fn ascii_letters_share_upcase_keys() {
        assert_eq!(
            windows_nt_utf16_upcase_key("File"),
            windows_nt_utf16_upcase_key("FILE")
        );
        assert_ne!(
            windows_nt_utf16_upcase_key("File"),
            windows_nt_utf16_upcase_key("Files")
        );
    }

    #[test]
    fn nt_upcase_keys_match_native_filename_aliases() {
        // Check the actual filesystem instead of assuming linguistic Unicode
        // uppercase mappings. In particular, NT's dotless-i mapping differs
        // from the mapping a Unicode text library would suggest.
        for (first, second) in [
            ("i", "I"),
            ("I", "\u{0131}"),
            ("\u{00df}", "SS"),
            ("caf\u{e9}", "cafe\u{301}"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let sensitive = super::directory_is_case_sensitive(root.path()).unwrap();
            let first_path = root.path().join(first);
            std::fs::write(&first_path, b"retained first file").unwrap();
            let aliases = match std::fs::File::create_new(root.path().join(second)) {
                Ok(file) => {
                    drop(file);
                    false
                },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => true,
                Err(error) => panic!("native alias probe {first:?}/{second:?}: {error}"),
            };
            let expected_alias = !sensitive
                && windows_nt_utf16_upcase_key(first) == windows_nt_utf16_upcase_key(second);
            assert_eq!(
                aliases, expected_alias,
                "native filename comparison disagrees with admission for {first:?}/{second:?}"
            );
            assert_eq!(
                std::fs::read(first_path).unwrap(),
                b"retained first file",
                "create-new alias probe must not replace the original"
            );
        }
    }

    #[test]
    fn sharp_s_does_not_expand_to_ss_under_nt_upcase() {
        // U+00DF LATIN SMALL LETTER SHARP S stays a single code unit under
        // RtlUpcaseUnicodeChar. Unicode full casefold maps it to "ss".
        let sharp = windows_nt_utf16_upcase_key("\u{00df}");
        let ss = windows_nt_utf16_upcase_key("SS");
        let ss_lower = windows_nt_utf16_upcase_key("ss");
        assert_eq!(sharp, vec![windows_nt_utf16_upcase_unit(0x00df)]);
        assert_ne!(sharp, ss);
        assert_ne!(sharp, ss_lower);
        assert_eq!(ss, ss_lower);
    }

    #[test]
    fn surrogate_units_are_upcased_independently_without_normalization() {
        // U+1F600 as a surrogate pair: no recombination, no NFC/NFD.
        let emoji = "\u{1F600}";
        let units: Vec<u16> = emoji.encode_utf16().collect();
        assert_eq!(units.len(), 2);
        assert_eq!(
            windows_nt_utf16_upcase_key(emoji),
            units
                .into_iter()
                .map(windows_nt_utf16_upcase_unit)
                .collect::<Vec<_>>()
        );
        assert_ne!(
            windows_nt_utf16_upcase_key("cafe\u{301}"),
            windows_nt_utf16_upcase_key("caf\u{e9}")
        );
    }
}
