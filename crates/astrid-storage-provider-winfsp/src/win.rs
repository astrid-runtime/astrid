#![allow(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use astrid_core::local_transport;
use astrid_core::storage_filesystem::{
    StorageFilesystemEntryKindV1, StorageFilesystemOperationV1, StorageFilesystemSuccessV1,
    StorageMountLeaseV1,
};
use astrid_core::storage_provider::StorageProviderAccessV1;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use widestring::{U16CString, U16String};
use windows_sys::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DEVICE_NOT_READY, STATUS_DIRECTORY_NOT_EMPTY,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INTERNAL_ERROR, STATUS_IO_DEVICE_ERROR,
    STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
use winfsp_wrs::{
    CleanupFlags, CreateOptions, DirInfo, FileAttributes, FileInfo, FileSystem,
    FileSystemInterface, NTSTATUS, OperationGuardStrategy, PSecurityDescriptor, Params,
    SecurityDescriptor, VolumeInfo, VolumeParams, WriteMode,
};

use crate::callback::{
    AdapterFailure, CallbackClient, endpoint_is_present, maximum_io_bytes, normalize_path,
};
use crate::{DAEMON_ARGUMENT, PROVIDER_NAME, provider_control_path};

const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(30);
const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LEASE_BYTES: u64 = 64 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct DaemonStart {
    lease: StorageMountLeaseV1,
    mountpoint: PathBuf,
}

pub(crate) fn daemon_main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_LEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read WinFsp daemon lease")?;
    if bytes.len() as u64 > MAX_LEASE_BYTES {
        bail!("WinFsp daemon lease exceeds limit");
    }
    let start: DaemonStart =
        serde_json::from_slice(&bytes).context("decode WinFsp daemon lease")?;
    let lease = start.lease;
    if !start.mountpoint.is_absolute() || !lease.callback_path.is_absolute() {
        bail!("WinFsp daemon lease contains a relative endpoint");
    }

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("start WinFsp callback runtime")?,
    );
    let callback = CallbackFs::new(lease.clone(), Arc::clone(&runtime));
    let control_path = provider_control_path(&lease.mount_id)?;
    let control_listener = local_transport::bind(&control_path)
        .with_context(|| format!("bind WinFsp control endpoint {}", control_path.display()))?;
    initialize_winfsp()?;
    let mountpoint = U16CString::from_os_str(start.mountpoint.as_os_str())
        .map_err(|_| anyhow::anyhow!("mountpoint is not valid UTF-16"))?;
    let filesystem = FileSystem::start(volume_params(lease.access), Some(&mountpoint), callback)
        .map_err(|status| {
            anyhow::anyhow!("WinFsp failed to start mount with status {status:#x}")
        })?;

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "READY {0}", lease.mount_id).context("report WinFsp readiness")?;
    stdout.flush().context("flush WinFsp readiness")?;

    let result = runtime.block_on(daemon_loop(filesystem, control_listener));
    if let Err(error) = result {
        eprintln!("{PROVIDER_NAME}: daemon stopped after failure: {error:#}");
        return Err(error);
    }
    Ok(())
}

async fn daemon_loop(
    filesystem: FileSystem,
    listener: local_transport::LocalListener,
) -> Result<()> {
    let mut filesystem = Some(filesystem);
    loop {
        let mut stream = local_transport::accept(&listener)
            .await
            .context("accept WinFsp control client")?;
        let mut command = [0_u8; 4];
        let read = stream
            .read(&mut command)
            .await
            .context("read stop command")?;
        if read == 0 {
            continue;
        }
        if read != command.len() || &command != b"STOP" {
            continue;
        }
        if let Some(filesystem) = filesystem.take() {
            filesystem.stop();
        }
        stream
            .write_all(b"S")
            .await
            .context("acknowledge WinFsp stop")?;
        stream
            .flush()
            .await
            .context("flush WinFsp stop acknowledgement")?;
        return Ok(());
    }
}

pub(crate) async fn spawn_daemon(lease: &StorageMountLeaseV1, mountpoint: &Path) -> Result<()> {
    let executable = std::env::current_exe().context("resolve WinFsp provider executable")?;
    let mut command = tokio::process::Command::new(&executable);
    command
        .arg(DAEMON_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    let mut child = command
        .spawn()
        .with_context(|| format!("start detached {}", executable.display()))?;

    let success = async {
        let mut stdin = child
            .stdin
            .take()
            .context("WinFsp daemon stdin is unavailable")?;
        let start = DaemonStart {
            lease: lease.clone(),
            mountpoint: mountpoint.to_path_buf(),
        };
        let bytes = serde_json::to_vec(&start).context("encode WinFsp daemon lease")?;
        stdin.write_all(&bytes).await.context("send daemon lease")?;
        stdin
            .write_all(b"\n")
            .await
            .context("terminate daemon lease")?;
        drop(stdin);

        let stdout = child
            .stdout
            .take()
            .context("WinFsp daemon stdout is unavailable")?;
        let mut stdout = tokio::io::BufReader::new(stdout);
        let mut ready = String::new();
        stdout
            .read_line(&mut ready)
            .await
            .context("read WinFsp daemon readiness")?;
        let expected = format!("READY {}\n", lease.mount_id);
        if ready != expected {
            bail!("WinFsp daemon returned invalid readiness: {ready:?}");
        }
        if child.try_wait().context("inspect WinFsp daemon")?.is_some() {
            bail!("WinFsp daemon exited immediately after readiness");
        }
        Result::<()>::Ok(())
    };

    match tokio::time::timeout(DAEMON_READY_TIMEOUT, success).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error.context("start WinFsp native filesystem"))
        },
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("WinFsp daemon did not report readiness within 30 seconds");
        },
    }
}

pub(crate) async fn stop_daemon(control_path: &Path) -> Result<()> {
    let stop = async {
        let mut stream = match local_transport::connect(control_path).await {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).context(format!(
                    "connect WinFsp control endpoint {}",
                    control_path.display()
                ));
            },
        };
        stream
            .write_all(b"STOP")
            .await
            .context("send WinFsp stop")?;
        stream.flush().await.context("flush WinFsp stop")?;
        let mut acknowledgement = [0_u8; 1];
        stream
            .read_exact(&mut acknowledgement)
            .await
            .context("read WinFsp stop acknowledgement")?;
        if acknowledgement[0] != b'S' {
            bail!("WinFsp daemon returned an invalid stop acknowledgement");
        }
        Result::<()>::Ok(())
    };
    tokio::time::timeout(DAEMON_STOP_TIMEOUT, stop)
        .await
        .map_err(|_| anyhow::anyhow!("WinFsp stop timed out"))??;

    let deadline = tokio::time::Instant::now()
        .checked_add(DAEMON_STOP_TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("WinFsp stop deadline overflow"))?;
    while endpoint_is_present(control_path) {
        if tokio::time::Instant::now() >= deadline {
            bail!("WinFsp control endpoint remained live after stop");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

fn initialize_winfsp() -> Result<()> {
    load_adjacent_winfsp().context("load co-installed WinFsp runtime")?;
    winfsp_wrs::init().context("initialize installed WinFsp runtime")
}

fn load_adjacent_winfsp() -> Result<()> {
    let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return Ok(());
    };
    let architecture = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "a64"
    } else {
        return Ok(());
    };
    let library = directory.join(format!("winfsp-{architecture}.dll"));
    if !library.is_file() {
        return Ok(());
    }
    let encoded: Vec<u16> = library
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { LoadLibraryW(encoded.as_ptr()) }.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("load co-installed WinFsp runtime {}", library.display()));
    }
    Ok(())
}

fn volume_params(access: StorageProviderAccessV1) -> Params {
    let mut volume = VolumeParams::default();
    volume
        .set_case_sensitive_search(false)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(false)
        .set_read_only_volume(access == StorageProviderAccessV1::ReadOnly)
        .set_sector_size(4096)
        .set_max_component_length(255)
        .set_sectors_per_allocation_unit(1)
        .set_file_info_timeout(1000)
        .set_volume_info_timeout(1000)
        .set_dir_info_timeout(1000)
        .set_security_timeout(1000);
    Params {
        volume_params: volume,
        guard_strategy: OperationGuardStrategy::Fine,
    }
}

#[derive(Debug)]
struct OpenEntry {
    path: String,
    kind: StorageFilesystemEntryKindV1,
    logical_bytes: u64,
}

struct CallbackFs {
    client: CallbackClient,
    read_only: bool,
}

impl CallbackFs {
    fn new(lease: StorageMountLeaseV1, runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            client: CallbackClient::new(lease.callback_path, lease.lease_token, runtime),
            read_only: lease.access == StorageProviderAccessV1::ReadOnly,
        }
    }

    fn invoke(
        &self,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, NTSTATUS> {
        self.client.invoke(operation).map_err(map_failure)
    }

    fn security_descriptor(&self) -> Result<SecurityDescriptor, NTSTATUS> {
        let user = local_transport::current_user_security_identifier()
            .map_err(|_| STATUS_INTERNAL_ERROR)?;
        let access = if self.read_only { "GR" } else { "GA" };
        let sddl = format!("O:{user}D:P(A;;{access};;;SY)(A;;{access};;;{user})");
        let encoded = U16CString::from_str(&sddl).map_err(|_| STATUS_INTERNAL_ERROR)?;
        SecurityDescriptor::from_wstr(&encoded).map_err(|_| STATUS_INTERNAL_ERROR)
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
        let descriptor = self.security_descriptor()?;
        Ok((
            attributes(entry.kind, self.read_only),
            descriptor.as_ptr(),
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
        let descriptor = self.security_descriptor()?;
        Ok(descriptor.as_ptr())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use astrid_core::storage_filesystem::{
        StorageFilesystemEntryV1, StorageFilesystemFailureV1, StorageFilesystemOutcomeV1,
        StorageFilesystemRequestV1, StorageFilesystemResponseV1,
    };
    use astrid_core::storage_provider::{StorageMountId, StorageProviderViewV1};

    use super::*;

    type FakeState = Arc<Mutex<BTreeMap<String, (StorageFilesystemEntryKindV1, Vec<u8>)>>>;

    #[tokio::test]
    async fn native_winfsp_translates_filesystem_operations() {
        if std::env::var_os("ASTRID_WINFSP_NATIVE_TEST").is_none() {
            eprintln!("skipping native WinFsp runtime test; set ASTRID_WINFSP_NATIVE_TEST=1");
            return;
        }

        let temporary = tempfile::tempdir().expect("temporary WinFsp directory");
        let callback_path = temporary.path().join("callback.endpoint");
        let mountpoint = temporary.path().join("mount");
        std::fs::create_dir(&mountpoint).expect("empty mountpoint");
        let listener = Arc::new(local_transport::bind(&callback_path).expect("fake callback"));
        let state: FakeState = Arc::new(Mutex::new(BTreeMap::new()));
        let server = tokio::spawn(fake_callback_server(
            Arc::clone(&listener),
            Arc::clone(&state),
        ));
        let runtime = Arc::new(tokio::runtime::Runtime::new().expect("callback runtime"));
        let lease = StorageMountLeaseV1 {
            mount_id: StorageMountId::new(),
            view: StorageProviderViewV1::Admin,
            access: StorageProviderAccessV1::ReadWrite,
            resource_path: temporary.path().join("resource"),
            callback_path: callback_path.clone(),
            lease_token: "native-test-token".to_owned(),
            expires_at_epoch_secs: u64::MAX,
        };
        let callback = CallbackFs::new(lease, runtime);
        let native_mountpoint =
            U16CString::from_os_str(mountpoint.as_os_str()).expect("mountpoint UTF-16");
        let filesystem = FileSystem::start(
            volume_params(StorageProviderAccessV1::ReadWrite),
            Some(&native_mountpoint),
            callback,
        )
        .expect("start native WinFsp filesystem");

        std::fs::write(mountpoint.join("hello.txt"), b"astrid").expect("write through WinFsp");
        assert_eq!(
            std::fs::read(mountpoint.join("hello.txt")).expect("read through WinFsp"),
            b"astrid"
        );
        std::fs::create_dir(mountpoint.join("notes")).expect("create directory");
        std::fs::rename(
            mountpoint.join("hello.txt"),
            mountpoint.join("notes").join("greeting.txt"),
        )
        .expect("rename through WinFsp");
        assert!(mountpoint.join("hello.txt").symlink_metadata().is_err());
        assert_eq!(
            std::fs::read(mountpoint.join("notes").join("greeting.txt"))
                .expect("read renamed file"),
            b"astrid"
        );

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(mountpoint.join("notes").join("greeting.txt"))
            .expect("open for append");
        file.write_all(b" filesystem").expect("append");
        file.set_len(20).expect("truncate through WinFsp");
        file.sync_all().expect("sync through WinFsp");
        drop(file);
        assert_eq!(
            std::fs::metadata(mountpoint.join("notes").join("greeting.txt"))
                .expect("renamed metadata")
                .len(),
            20
        );

        let root_names = std::fs::read_dir(&mountpoint)
            .expect("enumerate root")
            .map(|entry| {
                entry
                    .expect("root entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(root_names, vec!["notes".to_owned()]);
        std::fs::remove_file(mountpoint.join("notes").join("greeting.txt"))
            .expect("remove through WinFsp");
        assert!(
            mountpoint
                .join("notes")
                .join("greeting.txt")
                .symlink_metadata()
                .is_err()
        );

        filesystem.stop();
        server.abort();
    }

    async fn fake_callback_server(listener: Arc<local_transport::LocalListener>, state: FakeState) {
        loop {
            let Ok(mut stream) = local_transport::accept(&listener).await else {
                break;
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut length = [0_u8; 4];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let request_length =
                    usize::try_from(u32::from_be_bytes(length)).expect("bounded request length");
                let mut request = vec![0_u8; request_length];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let Ok(request) = serde_json::from_slice::<StorageFilesystemRequestV1>(&request)
                else {
                    return;
                };
                let outcome = if request.lease_token.as_str() == "native-test-token" {
                    match fake_apply(&state, request.operation) {
                        Ok(success) => StorageFilesystemOutcomeV1::Success(success),
                        Err((code, message)) => fake_failure(&code, &message),
                    }
                } else {
                    fake_failure("unauthorized", "invalid test token")
                };
                let response = StorageFilesystemResponseV1 {
                    protocol_version: 1,
                    request_id: request.request_id,
                    outcome,
                };
                let Ok(bytes) = serde_json::to_vec(&response) else {
                    return;
                };
                let Ok(length) = u32::try_from(bytes.len()) else {
                    return;
                };
                if stream.write_all(&length.to_be_bytes()).await.is_err() {
                    return;
                }
                if stream.write_all(&bytes).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
            });
        }
    }

    fn fake_failure(code: &str, message: &str) -> StorageFilesystemOutcomeV1 {
        StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 {
            code: code.to_owned(),
            message: message.to_owned(),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn fake_apply(
        state: &FakeState,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, (String, String)> {
        let mut entries = state
            .lock()
            .map_err(|_| ("internal".to_owned(), "test state poisoned".to_owned()))?;
        match operation {
            StorageFilesystemOperationV1::Stat { path } => {
                if path.is_empty() {
                    return Ok(StorageFilesystemSuccessV1::Entry(fake_entry(
                        "",
                        StorageFilesystemEntryKindV1::Directory,
                        0,
                    )));
                }
                let (_, bytes) = entries
                    .get(&path)
                    .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
                Ok(StorageFilesystemSuccessV1::Entry(fake_entry(
                    path.rsplit('/').next().unwrap_or(&path),
                    entries[&path].0,
                    u64::try_from(bytes.len()).expect("bounded test file length"),
                )))
            },
            StorageFilesystemOperationV1::Create { path, kind } => {
                if entries.contains_key(&path) {
                    return Err(("already-exists".to_owned(), path));
                }
                entries.insert(path, (kind, Vec::new()));
                Ok(StorageFilesystemSuccessV1::Done)
            },
            StorageFilesystemOperationV1::Read {
                path,
                offset,
                length,
            } => {
                let bytes = entries
                    .get(&path)
                    .ok_or_else(|| ("not-found".to_owned(), path.clone()))?
                    .1
                    .clone();
                let byte_length = u64::try_from(bytes.len()).expect("bounded test file length");
                let start = usize::try_from(offset.min(byte_length)).expect("bounded offset");
                let end = usize::try_from(offset.saturating_add(length).min(byte_length))
                    .expect("bounded read end");
                Ok(StorageFilesystemSuccessV1::Data(bytes[start..end].to_vec()))
            },
            StorageFilesystemOperationV1::Write { path, offset, data } => {
                let (_, bytes) = entries
                    .get_mut(&path)
                    .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
                let data_length = u64::try_from(data.len()).expect("bounded test write length");
                let end = usize::try_from(
                    offset
                        .checked_add(data_length)
                        .expect("bounded test write end"),
                )
                .expect("bounded test write end");
                if end > bytes.len() {
                    bytes.resize(end, 0);
                }
                let start = usize::try_from(offset).expect("bounded test offset");
                bytes[start..end].copy_from_slice(&data);
                Ok(StorageFilesystemSuccessV1::Written(
                    u64::try_from(bytes.len()).expect("bounded test file length"),
                ))
            },
            StorageFilesystemOperationV1::SetLength { path, length } => {
                let (_, bytes) = entries
                    .get_mut(&path)
                    .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
                bytes.resize(usize::try_from(length).expect("bounded test length"), 0);
                Ok(StorageFilesystemSuccessV1::Done)
            },
            StorageFilesystemOperationV1::Remove { path } => {
                entries
                    .remove(&path)
                    .ok_or_else(|| ("not-found".to_owned(), path.clone()))?;
                Ok(StorageFilesystemSuccessV1::Done)
            },
            StorageFilesystemOperationV1::Rename {
                from,
                to,
                replace: _,
            } => {
                let value = entries
                    .remove(&from)
                    .ok_or_else(|| ("not-found".to_owned(), from.clone()))?;
                entries.insert(to, value);
                Ok(StorageFilesystemSuccessV1::Done)
            },
            StorageFilesystemOperationV1::Sync => Ok(StorageFilesystemSuccessV1::Done),
            StorageFilesystemOperationV1::ReadDirectory { path } => {
                let prefix = if path.is_empty() {
                    String::new()
                } else {
                    format!("{path}/")
                };
                let children = entries
                    .iter()
                    .filter(|(name, _)| {
                        name.starts_with(&prefix)
                            && name[prefix.len()..]
                                .split('/')
                                .next()
                                .is_some_and(|segment| !segment.is_empty())
                            && !name[prefix.len()..].contains('/')
                    })
                    .map(|(name, (kind, bytes))| {
                        fake_entry(
                            name.rsplit('/').next().unwrap_or(name),
                            *kind,
                            bytes.len() as u64,
                        )
                    })
                    .collect::<Vec<_>>();
                Ok(StorageFilesystemSuccessV1::Entries(children))
            },
        }
    }

    fn fake_entry(
        name: &str,
        kind: StorageFilesystemEntryKindV1,
        logical_bytes: u64,
    ) -> StorageFilesystemEntryV1 {
        StorageFilesystemEntryV1 {
            name: name.to_owned(),
            kind,
            logical_bytes,
        }
    }
}
