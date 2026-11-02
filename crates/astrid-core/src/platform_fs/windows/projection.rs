//! Crate-private handle helpers for Windows runtime projection retirement.
//!
//! Directory authority is a held backup-semantics handle. Children are opened
//! relative to that handle with `FILE_OPEN_REPARSE_POINT` and never by
//! reconstructed paths.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ID_EXTD_DIR_INFORMATION, FileFsDeviceInformation, FileIdExtdDirectoryInformation,
    NtQueryDirectoryFile, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::{
    FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
};
use windows_sys::Win32::Foundation::{STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES, TRUE};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DEVICE, FILE_DEVICE_DISK, FILE_ID_INFO, FILE_LIST_DIRECTORY, FileIdInfo,
    GetFileInformationByHandleEx,
};

use super::path::{
    OwnedHandle, mark_handle_for_deletion, open_directory_identity_relative_with_access,
    validate_local_absolute_path, wide_path,
};
use super::prelude::*;

/// Fail-closed listing denial-of-service guard, not an operator knob. One native record is
/// `offset_of(FileName)` plus at most 255 UTF-16 units, rounded up to 8-byte
/// alignment. One mebibyte is above that ceiling and is intentionally not
/// configuration.
const MAX_LISTING_BUFFER: usize = 1 << 20;
const INITIAL_LISTING_BUFFER: usize = 16_384;
#[cfg(test)]
const MAX_COMPONENT_UTF16: usize = 255;
const CANONICAL_VOLUME: &str = "astrid.volume";

#[cfg(test)]
thread_local! {
    static REMOTE_VOLUME_AFTER_OPEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_DIRECTORY_FLUSH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LIST_CHILDREN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) volume: u64,
    pub(crate) file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListedEntry {
    pub(crate) name: OsString,
    pub(crate) identity: FileIdentity,
    pub(crate) kind: EntryKind,
}

pub(crate) struct OpenedDirectory {
    file: File,
}

pub(crate) struct OpenedFile {
    file: File,
}

#[derive(Clone, Copy)]
enum OpenMode {
    Inspect,
    Flush,
    Delete,
}

impl OpenedDirectory {
    pub(crate) fn open_existing(path: &Path) -> io::Result<Self> {
        open_existing_no_follow(path)
    }

    pub(crate) fn list(&self) -> io::Result<Vec<ListedEntry>> {
        list_children(self.handle(), self.identity()?.volume)
    }

    pub(crate) fn identity(&self) -> io::Result<FileIdentity> {
        file_identity_from_file(&self.file)
    }

    pub(crate) fn open_directory(&self, name: &OsStr, delete: bool) -> io::Result<Self> {
        open_child_directory(self.handle(), name, mode(delete))
    }

    pub(crate) fn open_file(&self, name: &OsStr, delete: bool) -> io::Result<OpenedFile> {
        open_child_file(self.handle(), name, mode(delete))
    }

    pub(crate) fn sync_all(&self) -> io::Result<()> {
        #[cfg(test)]
        if FAIL_DIRECTORY_FLUSH.get() {
            return Err(io::Error::other("test: directory flush failed"));
        }
        self.file.sync_all()
    }

    pub(crate) fn delete(self) -> io::Result<()> {
        delete_file(self.file)
    }

    fn handle(&self) -> HANDLE {
        self.file.as_raw_handle().cast()
    }
}

impl OpenedFile {
    pub(crate) fn identity(&self) -> io::Result<FileIdentity> {
        file_identity_from_file(&self.file)
    }

    pub(crate) fn delete(self) -> io::Result<()> {
        delete_file(self.file)
    }
}

#[cfg(test)]
pub(crate) fn fail_directory_flush(fail: bool) {
    FAIL_DIRECTORY_FLUSH.set(fail);
}

#[cfg(test)]
pub(crate) fn reset_directory_list_count() {
    LIST_CHILDREN_COUNT.set(0);
}

#[cfg(test)]
pub(crate) fn directory_list_count() -> usize {
    LIST_CHILDREN_COUNT.get()
}

pub(crate) fn windows_names_equal(left: &OsStr, right: &OsStr) -> io::Result<bool> {
    let left_wide = left.encode_wide().collect::<Vec<_>>();
    let right_wide = right.encode_wide().collect::<Vec<_>>();
    let left_len = i32::try_from(left_wide.len())
        .map_err(|_| invalid_input("Windows file name is too long"))?;
    let right_len = i32::try_from(right_wide.len())
        .map_err(|_| invalid_input("Windows file name is too long"))?;
    // SAFETY: both buffers live for the call; lengths are UTF-16 units, so a
    // terminating NUL is not required.
    let result = unsafe {
        CompareStringOrdinal(
            left_wide.as_ptr(),
            left_len,
            right_wide.as_ptr(),
            right_len,
            TRUE,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == CSTR_EQUAL)
}

pub(crate) fn is_canonical_volume_name(name: &OsStr) -> io::Result<bool> {
    windows_names_equal(name, OsStr::new(CANONICAL_VOLUME))
}

fn mode(delete: bool) -> OpenMode {
    if delete {
        OpenMode::Delete
    } else {
        OpenMode::Inspect
    }
}

fn open_existing_no_follow(path: &Path) -> io::Result<OpenedDirectory> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    validate_local_absolute_path(&absolute)?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid_input("projection root is not a local volume path"));
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid_input("projection root is not a local volume path"));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::CurDir => {},
            Component::ParentDir => {
                return Err(invalid_input("projection root contains traversal"));
            },
            _ => return Err(invalid_input("projection root is not a local volume path")),
        }
    }
    let Some((last, ancestors)) = names.split_last() else {
        return Err(invalid_input("projection root is a volume root"));
    };
    let mut volume = PathBuf::from(prefix.as_os_str());
    volume.push("\\");
    let mut directory = open_volume_root(&volume)?;
    for name in ancestors {
        directory = open_child_directory(directory.handle(), name, OpenMode::Inspect)?;
    }
    open_child_directory(directory.handle(), last, OpenMode::Flush)
}

fn verify_local_volume(handle: HANDLE) -> io::Result<()> {
    let mut info = FILE_FS_DEVICE_INFORMATION::default();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the retained synchronous handle and both fixed-size output
    // buffers remain live. This queries the opened volume, not a remappable
    // drive-letter name, before any child is opened or inventoried.
    let result = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &raw mut status,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
                .expect("FILE_FS_DEVICE_INFORMATION fits in u32"),
            FileFsDeviceInformation,
        )
    };
    if result != 0 {
        return Err(nt_error(result));
    }
    #[cfg(test)]
    if REMOTE_VOLUME_AFTER_OPEN.get() {
        info.Characteristics |= FILE_REMOTE_DEVICE;
    }
    validate_local_volume_info(info, status.Information)
}

fn validate_local_volume_info(info: FILE_FS_DEVICE_INFORMATION, used: usize) -> io::Result<()> {
    if used != size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(invalid("volume device information has an invalid length"));
    }
    // MS-FSCC 2.5.10 identifies disk-backed volumes by FILE_DEVICE_DISK.
    // Reject unsupported/remote devices rather than falling back to a name.
    if info.DeviceType != FILE_DEVICE_DISK
        || info.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB) != 0
    {
        return Err(invalid_input(
            "projection root is not a local writable disk volume",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn remote_volume_after_open(remote: bool) {
    REMOTE_VOLUME_AFTER_OPEN.set(remote);
}

fn volume_root_access() -> u32 {
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
}

fn open_volume_root(path: &Path) -> io::Result<OpenedDirectory> {
    let wide = wide_path(path)?;
    let access = volume_root_access();
    // SAFETY: `wide` is NUL-terminated; null security/template pointers are
    // permitted. OPEN_REPARSE_POINT keeps a volume-root reparse from being
    // followed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(handle);
    verify_local_volume(handle.0)?;
    from_directory_handle(handle)
}

fn open_child_directory(
    parent: HANDLE,
    name: &OsStr,
    mode: OpenMode,
) -> io::Result<OpenedDirectory> {
    let extra = directory_access(mode);
    // Delete authority itself denies delete sharing. This prevents an external
    // rename between the final parent-relative identity check and disposition.
    // Inspection reopens keep sharing delete so they cannot conflict with our
    // own retained delete handle.
    let (handle, _) = open_directory_identity_relative_with_access(
        parent,
        name,
        matches!(mode, OpenMode::Delete),
        extra,
    )?;
    from_directory_handle(handle)
}

fn directory_access(mode: OpenMode) -> u32 {
    let inspect = FILE_LIST_DIRECTORY | FILE_TRAVERSE;
    match mode {
        OpenMode::Inspect => inspect,
        OpenMode::Flush => inspect | GENERIC_WRITE,
        OpenMode::Delete => inspect | DELETE | GENERIC_WRITE,
    }
}

fn from_directory_handle(handle: OwnedHandle) -> io::Result<OpenedDirectory> {
    let info = handle_information(handle.0)?;
    reject_special(info.dwFileAttributes)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid("projection contains a redirect or special entry"));
    }
    Ok(OpenedDirectory {
        file: handle.into_file(),
    })
}

fn open_child_file(parent: HANDLE, name: &OsStr, mode: OpenMode) -> io::Result<OpenedFile> {
    let handle = open_relative_file(
        parent,
        name,
        file_access(mode),
        matches!(mode, OpenMode::Delete),
    )?;
    let info = handle_information(handle.0)?;
    reject_special(info.dwFileAttributes)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(invalid("projection contains a redirect or special entry"));
    }
    Ok(OpenedFile {
        file: handle.into_file(),
    })
}

fn file_access(mode: OpenMode) -> u32 {
    let inspect = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    match mode {
        OpenMode::Inspect | OpenMode::Flush => inspect,
        OpenMode::Delete => inspect | DELETE,
    }
}

fn open_relative_file(
    parent: HANDLE,
    name: &OsStr,
    access: u32,
    lock_against_rename: bool,
) -> io::Result<OwnedHandle> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(invalid_input("invalid handle-relative Windows file name"));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| invalid_input("Windows file name is too long"))?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES fits in u32"),
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: 0x40,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: name, object attributes, and output buffers remain live; the
    // child is resolved only through the retained parent handle.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            access,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            FILE_SHARE_READ
                | FILE_SHARE_WRITE
                | if lock_against_rename {
                    0
                } else {
                    FILE_SHARE_DELETE
                },
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(nt_error(result));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile returned an invalid relative file handle",
        ));
    }
    Ok(OwnedHandle(handle))
}

fn list_children(parent: HANDLE, parent_volume: u64) -> io::Result<Vec<ListedEntry>> {
    #[cfg(test)]
    LIST_CHILDREN_COUNT.set(LIST_CHILDREN_COUNT.get().strict_add(1));
    let mut names = Vec::new();
    let mut restart = true;
    let mut buffer = ListingBuffer::new();
    loop {
        match query_directory(parent, buffer.bytes_mut(), restart)? {
            Query::Done => break,
            Query::Grow => {
                buffer.grow()?;
            },
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
            .ok_or_else(|| invalid("directory listing exceeded the retirement buffer"))?;
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

fn query_directory(parent: HANDLE, buffer: &mut [u8], restart: bool) -> io::Result<Query> {
    let mut status = IO_STATUS_BLOCK::default();
    let length =
        u32::try_from(buffer.len()).map_err(|_| invalid_input("listing buffer too large"))?;
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
        return Err(nt_error(result));
    }
    listing_information(status.Information, buffer.len())
}

fn listing_information(used: usize, buffer_len: usize) -> io::Result<Query> {
    if used == 0 {
        return Ok(Query::Done);
    }
    if used > buffer_len {
        return Err(invalid(
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
        return Err(invalid("directory listing entry is truncated"));
    }
    let name_bytes = usize::try_from(read_u32(
        rest,
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength),
    )?)
    .map_err(|_| invalid("directory listing name is too long"))?;
    if name_bytes % 2 != 0 {
        return Err(invalid("directory listing name is not UTF-16"));
    }
    let name_end = name_offset
        .checked_add(name_bytes)
        .ok_or_else(|| invalid("directory listing name is too long"))?;
    let name_slice = rest
        .get(name_offset..name_end)
        .ok_or_else(|| invalid("directory listing name is truncated"))?;
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
    Ok((
        Some(ListedEntry {
            name,
            identity: identity_from_file_id(
                parent_volume,
                read_file_id(
                    rest,
                    std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId),
                )?,
            )?,
            kind: entry_kind(read_u32(
                rest,
                std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes),
            )?)?,
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
    let step =
        usize::try_from(next).map_err(|_| invalid("directory listing next offset is invalid"))?;
    if step % 8 != 0 || step < name_end || step >= rest_len {
        return Err(invalid("directory listing next offset is invalid"));
    }
    offset
        .checked_add(step)
        .ok_or_else(|| invalid("directory listing next offset is invalid"))
}

fn read_u32(buffer: &[u8], offset: usize) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    let slice = buffer
        .get(offset..)
        .and_then(|rest| rest.get(..4))
        .ok_or_else(|| invalid("directory listing entry is truncated"))?;
    bytes.copy_from_slice(slice);
    Ok(u32::from_le_bytes(bytes))
}

fn read_file_id(buffer: &[u8], offset: usize) -> io::Result<[u8; 16]> {
    let slice = buffer
        .get(offset..)
        .and_then(|rest| rest.get(..16))
        .ok_or_else(|| invalid("directory listing entry is truncated"))?;
    let mut file_id = [0_u8; 16];
    file_id.copy_from_slice(slice);
    Ok(file_id)
}

fn identity_from_file_id(volume: u64, file_id: [u8; 16]) -> io::Result<FileIdentity> {
    if file_id == [0; 16] {
        return Err(invalid("projection entry has no file identifier"));
    }
    Ok(FileIdentity { volume, file_id })
}

#[cfg(test)]
fn max_listing_record_bytes() -> usize {
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    let unaligned = name_offset.strict_add(MAX_COMPONENT_UTF16.strict_mul(2));
    unaligned.div_ceil(8).strict_mul(8)
}

fn entry_kind(attributes: u32) -> io::Result<EntryKind> {
    reject_special(attributes)?;
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Ok(EntryKind::Directory)
    } else {
        Ok(EntryKind::File)
    }
}

fn reject_special(attributes: u32) -> io::Result<()> {
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err(invalid("projection contains a redirect or special entry"));
    }
    Ok(())
}

fn handle_information(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `info` is a valid output buffer.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn file_identity_from_file(file: &File) -> io::Result<FileIdentity> {
    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32");
    // SAFETY: `file` owns a live handle and `info` is a writable FILE_ID_INFO.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut info).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    identity_from_file_id(info.VolumeSerialNumber, info.FileId.Identifier)
}

fn delete_file(file: File) -> io::Result<()> {
    mark_handle_for_deletion(file.as_raw_handle().cast())?;
    drop(file);
    Ok(())
}

fn nt_error(result: i32) -> io::Error {
    // SAFETY: conversion is defined for the NTSTATUS returned by the native call.
    let code = unsafe { RtlNtStatusToDosError(result) };
    io::Error::from_raw_os_error(code.cast_signed())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
