use std::sync::{Arc, Mutex};

use anyhow::Result;
use astrid_core::local_transport;
use astrid_core::storage_filesystem::{
    StorageFilesystemEntryKindV1, StorageFilesystemOperationV1, StorageFilesystemSuccessV1,
    StorageMountLeaseV1,
};
use astrid_core::storage_provider::StorageProviderAccessV1;
use widestring::{U16CString, U16String};
use windows_sys::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DEVICE_NOT_READY, STATUS_DIRECTORY_NOT_EMPTY,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INTERNAL_ERROR, STATUS_IO_DEVICE_ERROR,
    STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use winfsp_wrs::{
    CleanupFlags, CreateOptions, DirInfo, FileAttributes, FileInfo, FileSystemInterface, NTSTATUS,
    PSecurityDescriptor, SecurityDescriptor, VolumeInfo, WriteMode,
};

use crate::PROVIDER_NAME;
use crate::callback::{AdapterFailure, CallbackClient, maximum_io_bytes, normalize_path};

#[derive(Debug)]
pub(super) struct OpenEntry {
    path: String,
    kind: StorageFilesystemEntryKindV1,
    logical_bytes: u64,
}

pub(super) struct CallbackFs {
    client: CallbackClient,
    read_only: bool,
    // `PSecurityDescriptor` is a borrowed pointer. Keep its backing bytes for
    // the complete filesystem lifetime so WinFsp can copy them after the trait
    // method returns.
    security_descriptor: SecurityDescriptor,
}

impl CallbackFs {
    pub(super) fn new(
        lease: StorageMountLeaseV1,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Result<Self, AdapterFailure> {
        let read_only = lease.access == StorageProviderAccessV1::ReadOnly;
        let user = local_transport::current_user_security_identifier().map_err(|error| {
            AdapterFailure::Transport(format!("resolve Windows user SID: {error}"))
        })?;
        let access = if read_only { "FRFX" } else { "FA" };
        let sddl = format!("O:{user}G:{user}D:P(A;;{access};;;SY)(A;;{access};;;{user})");
        let encoded = U16CString::from_str(&sddl)
            .map_err(|error| AdapterFailure::Transport(format!("encode Windows ACL: {error}")))?;
        let security_descriptor = SecurityDescriptor::from_wstr(&encoded)
            .map_err(|error| AdapterFailure::Transport(format!("build Windows ACL: {error}")))?;
        Ok(Self {
            client: CallbackClient::new(lease.callback_path, lease.lease_token, runtime),
            read_only,
            security_descriptor,
        })
    }

    fn invoke(
        &self,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, NTSTATUS> {
        self.client.invoke(operation).map_err(map_failure)
    }

    fn security_descriptor(&self) -> PSecurityDescriptor {
        self.security_descriptor.as_ptr()
    }
}

fn context_path(context: &Arc<Mutex<OpenEntry>>) -> Result<String, NTSTATUS> {
    Ok(context
        .lock()
        .map_err(|_| STATUS_INTERNAL_ERROR)?
        .path
        .clone())
}

fn context_snapshot(
    context: &Arc<Mutex<OpenEntry>>,
) -> Result<(StorageFilesystemEntryKindV1, u64), NTSTATUS> {
    let entry = context.lock().map_err(|_| STATUS_INTERNAL_ERROR)?;
    Ok((entry.kind, entry.logical_bytes))
}

fn update_context_length(
    context: &Arc<Mutex<OpenEntry>>,
    logical_bytes: u64,
) -> Result<(), NTSTATUS> {
    context
        .lock()
        .map_err(|_| STATUS_INTERNAL_ERROR)?
        .logical_bytes = logical_bytes;
    Ok(())
}

impl FileSystemInterface for CallbackFs {
    type FileContext = Arc<Mutex<OpenEntry>>;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    const CREATE_DEFINED: bool = true;
    const OPEN_DEFINED: bool = true;
    const OVERWRITE_DEFINED: bool = true;
    const CLEANUP_DEFINED: bool = true;
    const CLOSE_DEFINED: bool = true;
    const READ_DEFINED: bool = true;
    const WRITE_DEFINED: bool = true;
    const FLUSH_DEFINED: bool = true;
    const GET_FILE_INFO_DEFINED: bool = true;
    const SET_BASIC_INFO_DEFINED: bool = true;
    const SET_FILE_SIZE_DEFINED: bool = true;
    const CAN_DELETE_DEFINED: bool = true;
    const RENAME_DEFINED: bool = true;
    const GET_SECURITY_DEFINED: bool = true;
    const READ_DIRECTORY_DEFINED: bool = true;

    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        let label = U16String::from_str("Astrid");
        VolumeInfo::new(1 << 40, 1 << 40, &label).map_err(|_| STATUS_INTERNAL_ERROR)
    }

    fn get_security_by_name(
        &self,
        file_name: &widestring::U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let path = native_path(&file_name.to_string_lossy())?;
        let entry = self.stat(&path)?;
        Ok((
            attributes(entry.kind, self.read_only),
            self.security_descriptor(),
            false,
        ))
    }

    fn create(
        &self,
        file_name: &widestring::U16CStr,
        create_file_info: winfsp_wrs::CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = native_path(&file_name.to_string_lossy())?;
        let kind = if create_file_info
            .create_options
            .is(CreateOptions::FILE_DIRECTORY_FILE)
        {
            StorageFilesystemEntryKindV1::Directory
        } else {
            StorageFilesystemEntryKindV1::File
        };
        self.invoke(StorageFilesystemOperationV1::Create { path, kind })?;
        let context = Arc::new(Mutex::new(OpenEntry {
            path: native_path(&file_name.to_string_lossy())?,
            kind,
            logical_bytes: 0,
        }));
        Ok((context, file_info(kind, 0, self.read_only)))
    }

    fn open(
        &self,
        file_name: &widestring::U16CStr,
        create_options: CreateOptions,
        _granted_access: winfsp_wrs::FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = native_path(&file_name.to_string_lossy())?;
        let entry = self.stat(&path)?;
        if create_options.is(CreateOptions::FILE_DIRECTORY_FILE)
            && entry.kind != StorageFilesystemEntryKindV1::Directory
        {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if create_options.is(CreateOptions::FILE_NON_DIRECTORY_FILE)
            && entry.kind == StorageFilesystemEntryKindV1::Directory
        {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let context = Arc::new(Mutex::new(OpenEntry {
            path,
            kind: entry.kind,
            logical_bytes: entry.logical_bytes,
        }));
        Ok((
            context,
            file_info(entry.kind, entry.logical_bytes, self.read_only),
        ))
    }

    fn overwrite(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        let path = context_path(&file_context)?;
        self.invoke(StorageFilesystemOperationV1::SetLength { path, length: 0 })?;
        update_context_length(&file_context, 0)?;
        let (kind, _) = context_snapshot(&file_context)?;
        Ok(file_info(kind, 0, self.read_only))
    }

    fn cleanup(
        &self,
        file_context: Self::FileContext,
        _file_name: Option<&widestring::U16CStr>,
        flags: CleanupFlags,
    ) {
        if !flags.is(CleanupFlags::DELETE) {
            return;
        }
        let Ok(path) = context_path(&file_context) else {
            return;
        };
        let _ = self.invoke(StorageFilesystemOperationV1::Remove { path });
    }

    fn close(&self, _file_context: Self::FileContext) {}

    fn read(
        &self,
        file_context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, NTSTATUS> {
        let path = context_path(&file_context)?;
        let mut transferred = 0_usize;
        while transferred < buffer.len() {
            let remaining = buffer
                .len()
                .checked_sub(transferred)
                .ok_or(STATUS_INTERNAL_ERROR)?;
            let wanted = remaining
                .min(usize::try_from(maximum_io_bytes()).map_err(|_| STATUS_INTERNAL_ERROR)?);
            let current_offset = offset
                .checked_add(u64::try_from(transferred).map_err(|_| STATUS_INTERNAL_ERROR)?)
                .ok_or(STATUS_OBJECT_NAME_INVALID)?;
            let success = self.invoke(StorageFilesystemOperationV1::Read {
                path: path.clone(),
                offset: current_offset,
                length: wanted as u64,
            })?;
            let StorageFilesystemSuccessV1::Data(data) = success else {
                return Err(STATUS_INTERNAL_ERROR);
            };
            if data.len() > wanted {
                return Err(STATUS_INTERNAL_ERROR);
            }
            let end = transferred
                .checked_add(data.len())
                .ok_or(STATUS_INTERNAL_ERROR)?;
            buffer[transferred..end].copy_from_slice(&data);
            transferred = end;
            if data.len() < wanted {
                break;
            }
        }
        Ok(transferred)
    }

    fn write(
        &self,
        file_context: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), NTSTATUS> {
        let path = context_path(&file_context)?;
        let offset = match mode {
            WriteMode::Normal { offset } | WriteMode::ConstrainedIO { offset } => offset,
            WriteMode::WriteToEOF => self.stat(&path)?.logical_bytes,
        };
        let mut writable = buffer;
        if matches!(mode, WriteMode::ConstrainedIO { .. }) {
            let current = self.stat(&path)?.logical_bytes;
            let available = current.saturating_sub(offset);
            let writable_length =
                available.min(u64::try_from(buffer.len()).map_err(|_| STATUS_INTERNAL_ERROR)?);
            writable = buffer
                .get(..usize::try_from(writable_length).map_err(|_| STATUS_INTERNAL_ERROR)?)
                .ok_or(STATUS_INTERNAL_ERROR)?;
        }

        let mut transferred = 0_usize;
        let mut logical_bytes = self.stat(&path)?.logical_bytes;
        while transferred < writable.len() {
            let remaining = writable
                .len()
                .checked_sub(transferred)
                .ok_or(STATUS_INTERNAL_ERROR)?;
            let wanted = remaining
                .min(usize::try_from(maximum_io_bytes()).map_err(|_| STATUS_INTERNAL_ERROR)?);
            let current_offset = offset
                .checked_add(u64::try_from(transferred).map_err(|_| STATUS_INTERNAL_ERROR)?)
                .ok_or(STATUS_OBJECT_NAME_INVALID)?;
            let end = transferred
                .checked_add(wanted)
                .ok_or(STATUS_INTERNAL_ERROR)?;
            let chunk = &writable[transferred..end];
            let success = self.invoke(StorageFilesystemOperationV1::Write {
                path: path.clone(),
                offset: current_offset,
                data: chunk.to_vec(),
            })?;
            let StorageFilesystemSuccessV1::Written(length) = success else {
                return Err(STATUS_INTERNAL_ERROR);
            };
            logical_bytes = logical_bytes.max(offset.saturating_add(length));
            transferred = end;
        }
        update_context_length(&file_context, logical_bytes)?;
        let (kind, _) = context_snapshot(&file_context)?;
        Ok((transferred, file_info(kind, logical_bytes, self.read_only)))
    }

    fn flush(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        self.invoke(StorageFilesystemOperationV1::Sync)?;
        self.get_file_info(file_context)
    }

    fn get_file_info(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        let (kind, logical_bytes) = context_snapshot(&file_context)?;
        Ok(file_info(kind, logical_bytes, self.read_only))
    }

    fn set_basic_info(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _change_time: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        self.get_file_info(file_context)
    }

    fn set_file_size(
        &self,
        file_context: Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<FileInfo, NTSTATUS> {
        let path = context_path(&file_context)?;
        let current = self.stat(&path)?.logical_bytes;
        if set_allocation_size && new_size >= current {
            let (kind, _) = context_snapshot(&file_context)?;
            return Ok(file_info(kind, current, self.read_only));
        }
        self.invoke(StorageFilesystemOperationV1::SetLength {
            path,
            length: new_size,
        })?;
        update_context_length(&file_context, new_size)?;
        let (kind, _) = context_snapshot(&file_context)?;
        Ok(file_info(kind, new_size, self.read_only))
    }

    fn can_delete(
        &self,
        file_context: Self::FileContext,
        _file_name: &widestring::U16CStr,
    ) -> Result<(), NTSTATUS> {
        let path = context_path(&file_context)?;
        let entry = self.stat(&path)?;
        if entry.kind != StorageFilesystemEntryKindV1::Directory {
            return Ok(());
        }
        let success = self.invoke(StorageFilesystemOperationV1::ReadDirectory { path })?;
        let StorageFilesystemSuccessV1::Entries(entries) = success else {
            return Err(STATUS_INTERNAL_ERROR);
        };
        if entries.is_empty() {
            Ok(())
        } else {
            Err(STATUS_DIRECTORY_NOT_EMPTY)
        }
    }

    fn rename(
        &self,
        file_context: Self::FileContext,
        file_name: &widestring::U16CStr,
        new_file_name: &widestring::U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        let _ = file_name;
        let from = context_path(&file_context)?;
        let to = native_path(&new_file_name.to_string_lossy())?;
        self.invoke(StorageFilesystemOperationV1::Rename {
            from,
            to: to.clone(),
            replace: replace_if_exists,
        })?;
        file_context.lock().map_err(|_| STATUS_INTERNAL_ERROR)?.path = to;
        Ok(())
    }

    fn get_security(
        &self,
        file_context: Self::FileContext,
    ) -> Result<PSecurityDescriptor, NTSTATUS> {
        let _ = file_context;
        Ok(self.security_descriptor())
    }

    fn read_directory(
        &self,
        file_context: Self::FileContext,
        marker: Option<&widestring::U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        let path = context_path(&file_context)?;
        let success = self.invoke(StorageFilesystemOperationV1::ReadDirectory { path })?;
        let StorageFilesystemSuccessV1::Entries(entries) = success else {
            return Err(STATUS_NOT_A_DIRECTORY);
        };
        for entry in entries {
            if let Some(marker) = marker
                && entry.name.as_str() <= marker.to_string_lossy().as_str()
            {
                continue;
            }
            let name = U16CString::from_str(&entry.name).map_err(|_| STATUS_INTERNAL_ERROR)?;
            let info = file_info(entry.kind, entry.logical_bytes, self.read_only);
            if !add_dir_info(DirInfo::new(info, &name)) {
                break;
            }
        }
        Ok(())
    }
}

trait StatEntry {
    fn stat(
        &self,
        path: &str,
    ) -> Result<astrid_core::storage_filesystem::StorageFilesystemEntryV1, NTSTATUS>;
}

impl StatEntry for CallbackFs {
    fn stat(
        &self,
        path: &str,
    ) -> Result<astrid_core::storage_filesystem::StorageFilesystemEntryV1, NTSTATUS> {
        match self.invoke(StorageFilesystemOperationV1::Stat {
            path: path.to_owned(),
        })? {
            StorageFilesystemSuccessV1::Entry(entry) => Ok(entry),
            _ => Err(STATUS_INTERNAL_ERROR),
        }
    }
}

fn file_info(kind: StorageFilesystemEntryKindV1, logical_bytes: u64, read_only: bool) -> FileInfo {
    let mut info = FileInfo::default();
    info.set_file_attributes(attributes(kind, read_only));
    info.set_allocation_size(logical_bytes);
    info.set_file_size(logical_bytes);
    info
}

fn attributes(kind: StorageFilesystemEntryKindV1, read_only: bool) -> FileAttributes {
    match (kind, read_only) {
        (StorageFilesystemEntryKindV1::Directory, _) => FileAttributes::DIRECTORY,
        (StorageFilesystemEntryKindV1::File, false) => FileAttributes::NORMAL,
        (StorageFilesystemEntryKindV1::File, true) => FileAttributes::READONLY,
    }
}

fn native_path(path: &str) -> Result<String, NTSTATUS> {
    normalize_path(path).map_err(map_failure)
}

fn map_failure(failure: AdapterFailure) -> NTSTATUS {
    match failure {
        AdapterFailure::Transport(message) => {
            eprintln!("{PROVIDER_NAME}: callback transport failure: {message}");
            STATUS_IO_DEVICE_ERROR
        },
        AdapterFailure::Filesystem { code, message } => {
            eprintln!("{PROVIDER_NAME}: callback failure [{code}]: {message}");
            match code.as_str() {
                "invalid-path" => STATUS_OBJECT_NAME_INVALID,
                "not-found" | "stale-lease" => STATUS_OBJECT_NAME_NOT_FOUND,
                "is-directory" => STATUS_FILE_IS_A_DIRECTORY,
                "not-directory" => STATUS_NOT_A_DIRECTORY,
                "already-exists" | "namespace-conflict" => STATUS_OBJECT_NAME_COLLISION,
                "directory-not-empty" => STATUS_DIRECTORY_NOT_EMPTY,
                "read-only" | "unauthorized" => STATUS_ACCESS_DENIED,
                "unavailable" => STATUS_DEVICE_NOT_READY,
                _ => STATUS_IO_DEVICE_ERROR,
            }
        },
    }
}
