//! Private Windows helpers for captured projection retirement.
//!
//! Directory listing fields and names are decoded only after bounds checks.
//! Captured `FileId` identities bind relative opens and deletion authority.
//! The shared NTFS directory helper owns flush-capable opens and durability.

use super::captured_directory::query_directory_identity;
use super::error::with_context;
use super::ntfs_directory_flush::{NtfsDirectoryFlushGuard, open_flush_bound_to_guard};
use super::path::{
    OwnedHandle, TrustedPathGuard, mark_handle_for_deletion,
    open_directory_identity_relative_with_access,
};
use super::prelude::*;
use crate::platform_fs::DirectoryIdentity;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ID_EXTD_DIR_INFORMATION, FileIdExtdDirectoryInformation, NtQueryDirectoryFile,
};
use windows_sys::Win32::Foundation::{STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DEVICE;

/// Initial `NtQueryDirectoryFile` buffer. Already larger than one maximum NTFS
/// directory record (`FileName` offset + 255 UTF-16 units, 8-byte aligned), so
/// a single-component listing never needs growth for record representability.
const INITIAL_LISTING_BUFFER: usize = 16 * 1024;

/// Fail-closed native listing protocol ceiling, not an operator runtime knob.
/// `NtQueryDirectoryFile` returns many sibling records per call; when the next
/// record does not fit, the query reports overflow and the historical parser
/// grows the buffer. Cap growth at one mebibyte so a hostile/pathological FS
/// cannot force unbounded allocation via repeated overflow — preserved from
/// `3df88012` `projection.rs`.
const MAX_LISTING_BUFFER: usize = 1 << 20;

#[cfg(test)]
const MAX_COMPONENT_UTF16: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedEntry {
    pub(crate) name: OsString,
    pub(crate) identity: DirectoryIdentity,
    pub(crate) is_directory: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum Query {
    Done,
    Grow,
    Entries(usize),
}

struct ListingBuffer {
    words: Vec<u64>,
}

impl ListingBuffer {
    fn new() -> Self {
        Self {
            words: vec![0; INITIAL_LISTING_BUFFER / 8],
        }
    }

    fn grow(&mut self) -> io::Result<()> {
        let bytes = self
            .words
            .len()
            .checked_mul(8)
            .and_then(|length| length.checked_mul(2))
            .filter(|length| *length <= MAX_LISTING_BUFFER)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory listing exceeded the retirement buffer",
                )
            })?;
        self.words.resize(bytes / 8, 0);
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        listing_bytes(&self.words)
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        listing_bytes_mut(&mut self.words)
    }
}

fn listing_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: initialized u64 storage is a valid 8-aligned byte buffer for
    // NtQueryDirectoryFile, which requires LONGLONG alignment.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), std::mem::size_of_val(words)) }
}

fn listing_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    // SAFETY: initialized u64 storage is a valid 8-aligned byte buffer for
    // NtQueryDirectoryFile, which requires LONGLONG alignment.
    unsafe {
        std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), std::mem::size_of_val(words))
    }
}

/// Rename-locked projection root opened for handle-relative listing, NTFS flush,
/// and retirement.
///
/// Wraps the paired [`NtfsDirectoryFlushGuard`]: the owned authority duplicate
/// retains the original no-`FILE_SHARE_DELETE` denial on the root file object
/// ([DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
/// [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)).
/// The derived flusher may share delete for coexistence only and is never sole
/// rename/delete authority. Ambient deletes against the root still fail with
/// sharing violations — callers must use handle-relative disposition.
pub(crate) struct RetirementRoot {
    cap: NtfsDirectoryFlushGuard,
}

impl RetirementRoot {
    /// Capture path authority, then open the paired FileId+NTFS flush capability.
    /// Caller-specific capture policy stays here; paired open/bind/NTFS/flush
    /// protocol lives in `ntfs_directory_flush`. The temporary `TrustedPathGuard`
    /// may be dropped: rename-lock continues via `cap`'s authority duplicate.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let guard = TrustedPathGuard::capture(path).map_err(|error| {
            with_context(
                error,
                format!("capture retirement root authority {}", path.display()),
            )
        })?;
        let cap = open_flush_bound_to_guard(&guard)?;
        drop(guard);
        Ok(Self { cap })
    }

    pub(crate) fn file(&self) -> &File {
        self.cap.file()
    }

    pub(crate) fn identity(&self) -> DirectoryIdentity {
        self.cap.identity()
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.cap.handle()
    }

    /// Synchronous NTFS directory-structure flush; both syscall and IOSB must be 0.
    pub(crate) fn flush_namespace(&self) -> io::Result<()> {
        self.cap.flush()
    }
}

fn volume_serial_number(file: &File) -> io::Result<u64> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: handle and FILE_ID_INFO out remain live for the call.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32"),
        )
    } == 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "GetFileInformationByHandleEx(FileIdInfo) for listing volume serial",
        ));
    }
    Ok(info.VolumeSerialNumber)
}

/// Child entries under `directory`, excluding `.` and `..`, sorted for stable plans.
///
/// Uses historical `NtQueryDirectoryFile(FileIdExtdDirectoryInformation)` with
/// checked buffer growth (`MAX_LISTING_BUFFER`) and bounds-checked record/name
/// parsing before any typed field use.
pub(crate) fn list_child_entries(directory: &File) -> io::Result<Vec<ListedEntry>> {
    let parent_volume = volume_serial_number(directory)?;
    let mut names = Vec::new();
    let mut restart = true;
    let mut buffer = ListingBuffer::new();
    loop {
        match query_directory(
            directory.as_raw_handle().cast(),
            buffer.bytes_mut(),
            restart,
        )? {
            Query::Done => break,
            Query::Grow => buffer.grow()?,
            Query::Entries(used) => {
                names.extend(parse_directory_buffer(
                    &buffer.bytes()[..used],
                    parent_volume,
                )?);
                restart = false;
            },
        }
    }
    names.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(names)
}

fn query_directory(parent: HANDLE, buffer: &mut [u8], restart: bool) -> io::Result<Query> {
    let mut status = IO_STATUS_BLOCK::default();
    let length =
        u32::try_from(buffer.len()).map_err(|_| io::Error::other("listing buffer too large"))?;
    // SAFETY: `parent` is a live directory handle; the status and listing
    // buffers remain valid for the call. FileName is always null so the handle
    // never captures a search expression.
    let result = unsafe {
        NtQueryDirectoryFile(
            parent,
            null_mut(),
            None,
            null(),
            &raw mut status,
            buffer.as_mut_ptr().cast(),
            length,
            FileIdExtdDirectoryInformation,
            false,
            null(),
            restart,
        )
    };
    if result == STATUS_NO_MORE_FILES {
        return Ok(Query::Done);
    }
    if result == STATUS_BUFFER_OVERFLOW {
        return Ok(Query::Grow);
    }
    if result < 0 {
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    // SAFETY: Information is populated by a successful NtQueryDirectoryFile.
    let used = status.Information;
    listing_information(used, buffer.len())
}

fn listing_information(used: usize, buffer_len: usize) -> io::Result<Query> {
    if used == 0 {
        return Ok(Query::Done);
    }
    if used > buffer_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing reported more bytes than the buffer",
        ));
    }
    Ok(Query::Entries(used))
}

fn parse_directory_buffer(buffer: &[u8], parent_volume: u64) -> io::Result<Vec<ListedEntry>> {
    let mut offset = 0;
    let mut entries = Vec::new();
    while offset < buffer.len() {
        let rest = &buffer[offset..];
        let (entry, next, name_end) = parse_directory_record(rest, parent_volume)?;
        if let Some(entry) = entry {
            entries.push(entry);
        }
        if next == 0 {
            break;
        }
        offset = advance_listing_offset(offset, next, name_end, rest.len())?;
    }
    Ok(entries)
}

fn parse_directory_record(
    rest: &[u8],
    parent_volume: u64,
) -> io::Result<(Option<ListedEntry>, u32, usize)> {
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    if rest.len() < name_offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing entry is truncated",
        ));
    }
    let name_bytes = usize::try_from(read_u32(
        rest,
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength),
    )?)
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing name is too long",
        )
    })?;
    if name_bytes % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing name is not UTF-16",
        ));
    }
    let name_end = name_offset.checked_add(name_bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing name is too long",
        )
    })?;
    let name_slice = rest.get(name_offset..name_end).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing name is truncated",
        )
    })?;
    let units = name_slice
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let name = OsString::from_wide(&units);
    let next = read_u32(
        rest,
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset),
    )?;
    if name == OsStr::new(".") || name == OsStr::new("..") {
        return Ok((None, next, name_end));
    }
    let attributes = read_u32(
        rest,
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes),
    )?;
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "projection contains a redirect or special entry",
        ));
    }
    let file_id = read_file_id(
        rest,
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId),
    )?;
    if file_id == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "projection entry has no file identifier",
        ));
    }
    Ok((
        Some(ListedEntry {
            name,
            identity: DirectoryIdentity::from_windows_file_id(parent_volume, file_id),
            is_directory: attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        }),
        next,
        name_end,
    ))
}

fn advance_listing_offset(
    offset: usize,
    next: u32,
    name_end: usize,
    rest_len: usize,
) -> io::Result<usize> {
    let step = usize::try_from(next).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing next offset is invalid",
        )
    })?;
    if step % 8 != 0 || step < name_end || step >= rest_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing next offset is invalid",
        ));
    }
    offset.checked_add(step).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory listing next offset is invalid",
        )
    })
}

fn read_u32(buffer: &[u8], offset: usize) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    let slice = buffer
        .get(offset..)
        .and_then(|rest| rest.get(..4))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory listing entry is truncated",
            )
        })?;
    bytes.copy_from_slice(slice);
    Ok(u32::from_le_bytes(bytes))
}

fn read_file_id(buffer: &[u8], offset: usize) -> io::Result<[u8; 16]> {
    let slice = buffer
        .get(offset..)
        .and_then(|rest| rest.get(..16))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory listing entry is truncated",
            )
        })?;
    let mut file_id = [0_u8; 16];
    file_id.copy_from_slice(slice);
    Ok(file_id)
}

pub(crate) fn open_child_directory(
    parent: HANDLE,
    name: &OsStr,
) -> io::Result<(File, DirectoryIdentity)> {
    let (handle, _legacy) = open_directory_identity_relative_with_access(
        parent,
        name,
        true,
        DELETE | FILE_LIST_DIRECTORY,
    )?;
    let file = File::from(handle);
    let identity = query_directory_identity(&file)?;
    Ok((file, identity))
}

/// Open a child directory for inventory capture (list + rename-lock; no DELETE).
pub(crate) fn open_child_directory_for_capture(
    parent: HANDLE,
    name: &OsStr,
) -> io::Result<(File, DirectoryIdentity)> {
    let (handle, _legacy) =
        open_directory_identity_relative_with_access(parent, name, true, FILE_LIST_DIRECTORY)?;
    let file = File::from(handle);
    let identity = query_directory_identity(&file)?;
    Ok((file, identity))
}

pub(crate) fn open_child_file_for_delete(
    parent: HANDLE,
    name: &OsStr,
) -> io::Result<(File, DirectoryIdentity)> {
    let handle = open_relative_file(parent, name, DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL)?;
    let file = File::from(handle);
    reject_directory_or_reparse(&file)?;
    let identity = query_directory_identity(&file)?;
    Ok((file, identity))
}

pub(crate) fn open_child_file_for_identity(
    parent: HANDLE,
    name: &OsStr,
) -> io::Result<(File, DirectoryIdentity)> {
    let handle = open_relative_file(parent, name, FILE_READ_ATTRIBUTES | READ_CONTROL)?;
    let file = File::from(handle);
    reject_directory_or_reparse(&file)?;
    let identity = query_directory_identity(&file)?;
    Ok((file, identity))
}

/// Open a captured-parent leaf for content verification without changing ACLs.
pub(crate) fn open_child_file_for_read(
    parent: HANDLE,
    name: &OsStr,
) -> io::Result<(File, DirectoryIdentity)> {
    let handle = open_relative_file(
        parent,
        name,
        GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
    )?;
    let file = File::from(handle);
    reject_directory_or_reparse(&file)?;
    let identity = query_directory_identity(&file)?;
    Ok((file, identity))
}

pub(crate) fn file_id_identity(file: &File) -> io::Result<DirectoryIdentity> {
    query_directory_identity(file)
}

pub(crate) fn delete_captured_file(file: File) -> io::Result<()> {
    mark_handle_for_deletion(file.as_raw_handle().cast())?;
    drop(file);
    Ok(())
}

pub(crate) fn delete_empty_captured_directory(file: File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: captured directory holds DELETE; classic disposition refuses nonempty.
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle().cast(),
            &raw mut status,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFORMATION>())
                .expect("FILE_DISPOSITION_INFORMATION fits in u32"),
            FileDispositionInformation,
        )
    };
    if result < 0 {
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    drop(file);
    Ok(())
}

pub(crate) fn require_identity(
    expected: DirectoryIdentity,
    actual: DirectoryIdentity,
    path: &Path,
) -> io::Result<()> {
    if expected != actual {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("projection identity changed: {}", path.display()),
        ));
    }
    Ok(())
}

fn open_relative_file(
    parent: HANDLE,
    name: &OsStr,
    desired_access: u32,
) -> io::Result<OwnedHandle> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid handle-relative Windows file name",
        ));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Windows file name is too long")
        })?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).expect("OBJECT_ATTRIBUTES fits u32"),
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: parent and name buffers remain live; OPEN_REPARSE_POINT avoids follow.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            desired_access | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile returned an invalid relative file handle",
        ));
    }
    Ok(OwnedHandle(handle))
}

fn reject_directory_or_reparse(file: &File) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle and info remain live.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a regular non-reparse file",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn max_listing_record_bytes() -> usize {
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    let unaligned = name_offset.strict_add(MAX_COMPONENT_UTF16.strict_mul(2));
    unaligned.div_ceil(8).strict_mul(8)
}

/// Pure parser/buffer regressions adapted from historical `3df88012`
/// `platform_fs/windows/projection_tests.rs` onto current `DirectoryIdentity`
/// + `parse_directory_record` / `advance_listing_offset` / checked grow.
#[cfg(test)]
mod parser_tests {
    use super::{
        FILE_ID_EXTD_DIR_INFORMATION, ListingBuffer, MAX_LISTING_BUFFER, Query,
        listing_information, max_listing_record_bytes, parse_directory_buffer,
    };
    use crate::platform_fs::DirectoryIdentity;
    use std::ffi::OsString;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    fn file_id(low: u64, high: u64) -> [u8; 16] {
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&low.to_le_bytes());
        id[8..].copy_from_slice(&high.to_le_bytes());
        id
    }

    fn listing_entry(name: &str, file_id: [u8; 16], next: u32, attributes: u32) -> Vec<u8> {
        listing_entry_units(
            &OsString::from(name).encode_wide().collect::<Vec<_>>(),
            file_id,
            next,
            attributes,
        )
    }

    fn listing_entry_units(
        units: &[u16],
        file_id: [u8; 16],
        next: u32,
        attributes: u32,
    ) -> Vec<u8> {
        let name_bytes = std::mem::size_of_val(units);
        let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        let mut buffer = vec![0_u8; name_offset];
        let next_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset);
        buffer[next_offset..][..4].copy_from_slice(&next.to_le_bytes());
        let attr_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes);
        buffer[attr_offset..][..4].copy_from_slice(&attributes.to_le_bytes());
        let len_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
        buffer[len_offset..][..4]
            .copy_from_slice(&u32::try_from(name_bytes).unwrap().to_le_bytes());
        let id_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId);
        buffer[id_offset..][..16].copy_from_slice(&file_id);
        for unit in units {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        buffer
    }

    fn packed_chain(first: &str, first_id: [u8; 16], second: &str, second_id: [u8; 16]) -> Vec<u8> {
        let mut first = listing_entry(first, first_id, 0, 0);
        while !first.len().is_multiple_of(8) {
            first.push(0);
        }
        let next = u32::try_from(first.len()).unwrap();
        first[0..4].copy_from_slice(&next.to_le_bytes());
        first.extend(listing_entry(second, second_id, 0, 0));
        first
    }

    #[test]
    fn listing_parser_captures_128_bit_file_id_and_volume() {
        let id = file_id(0x0000_0002_0000_0009, 0x1111_2222_3333_4444);
        let entries = parse_directory_buffer(&listing_entry("astrid.volume", id, 0, 0), 7).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, OsString::from("astrid.volume"));
        assert_eq!(
            entries[0].identity,
            DirectoryIdentity::from_windows_file_id(7, id)
        );
    }

    #[test]
    fn file_ids_differing_only_in_upper_64_bits_remain_distinct() {
        let low = file_id(1, 0);
        let high = file_id(1, 1);
        assert_ne!(
            DirectoryIdentity::from_windows_file_id(1, low),
            DirectoryIdentity::from_windows_file_id(1, high)
        );
        let entries = parse_directory_buffer(&packed_chain("a", low, "b", high), 3).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].identity,
            DirectoryIdentity::from_windows_file_id(3, low)
        );
        assert_eq!(
            entries[1].identity,
            DirectoryIdentity::from_windows_file_id(3, high)
        );
    }

    #[test]
    fn one_char_listing_name_parses_below_struct_size() {
        let buffer = listing_entry("a", file_id(1, 0), 0, 0);
        let packed = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName) + 2;
        assert!(packed < size_of::<FILE_ID_EXTD_DIR_INFORMATION>());
        assert_eq!(buffer.len(), packed);
        let entries = parse_directory_buffer(&buffer, 3).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, OsString::from("a"));
        assert_eq!(
            entries[0].identity,
            DirectoryIdentity::from_windows_file_id(3, file_id(1, 0))
        );
    }

    #[test]
    fn listing_parser_treats_wildcard_characters_as_literal_names() {
        let entries = parse_directory_buffer(&listing_entry("*", file_id(8, 0), 0, 0), 1).unwrap();
        assert_eq!(entries[0].name, OsString::from("*"));
    }

    #[test]
    fn listing_parser_skips_dot_entries_and_keeps_siblings() {
        let buffer = packed_chain(".", file_id(2, 0), "keep", file_id(3, 0));
        let entries = parse_directory_buffer(&buffer, 1).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, OsString::from("keep"));
    }

    #[test]
    fn listing_parser_rejects_malformed_records() {
        let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        let mut truncated_header = listing_entry("a", file_id(1, 0), 0, 0);
        truncated_header.truncate(name_offset.strict_sub(1));

        let mut odd_utf16 = listing_entry("a", file_id(1, 0), 0, 0);
        let len_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
        odd_utf16[len_offset..][..4].copy_from_slice(&1_u32.to_le_bytes());

        let unaligned_next = listing_entry("a", file_id(1, 0), 1, 0);
        let overlapping_name = listing_entry("a", file_id(1, 0), 8, 0);

        let mut truncated_name = listing_entry("ab", file_id(1, 0), 0, 0);
        truncated_name.truncate(name_offset.strict_add(2));
        truncated_name[len_offset..][..4].copy_from_slice(&4_u32.to_le_bytes());

        let mut next_at_end = listing_entry("a", file_id(1, 0), 0, 0);
        while !next_at_end.len().is_multiple_of(8) {
            next_at_end.push(0);
        }
        let end = u32::try_from(next_at_end.len()).unwrap();
        next_at_end[0..4].copy_from_slice(&end.to_le_bytes());

        let cases = [
            truncated_header,
            odd_utf16,
            unaligned_next,
            overlapping_name,
            truncated_name,
            next_at_end,
        ];
        for buffer in cases {
            assert_eq!(
                parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn listing_information_rejects_bytes_past_buffer() {
        assert!(listing_information(5, 4).is_err());
        assert_eq!(listing_information(0, 4).unwrap(), Query::Done);
        assert_eq!(listing_information(4, 4).unwrap(), Query::Entries(4));
    }

    #[test]
    fn listing_parser_rejects_reparse_attributes() {
        let buffer = listing_entry("link", file_id(4, 0), 0, FILE_ATTRIBUTE_REPARSE_POINT);
        assert_eq!(
            parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn listing_parser_rejects_device_attributes() {
        let buffer = listing_entry("dev", file_id(5, 0), 0, FILE_ATTRIBUTE_DEVICE);
        assert_eq!(
            parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn zero_file_id_is_rejected() {
        let buffer = listing_entry("empty-id", [0; 16], 0, 0);
        assert_eq!(
            parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn listing_buffer_ceiling_covers_one_max_record() {
        assert!(MAX_LISTING_BUFFER >= max_listing_record_bytes());
    }

    #[test]
    fn listing_buffer_grow_fails_closed_at_historical_cap() {
        let mut buffer = ListingBuffer::new();
        // Grow until the checked protocol ceiling rejects further expansion.
        let mut grew = 0_usize;
        loop {
            match buffer.grow() {
                Ok(()) => grew += 1,
                Err(err) => {
                    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                    assert!(
                        grew >= 1,
                        "initial 16KiB must be able to grow at least once"
                    );
                    assert!(buffer.bytes().len() <= MAX_LISTING_BUFFER);
                    return;
                },
            }
            assert!(
                grew < 64,
                "grow must hit MAX_LISTING_BUFFER rather than loop forever"
            );
        }
    }
}
