#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{self, Read as _, Seek as _, Write as _};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, ERROR_UNABLE_TO_MOVE_REPLACEMENT,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, ERROR_UNABLE_TO_REMOVE_REPLACED, GENERIC_ALL, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation, INHERIT_ONLY_ACE,
    INHERITED_ACE, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, GetFileInformationByHandle, GetVolumePathNameW, MoveFileExW, OPEN_EXISTING,
    READ_CONTROL, ReplaceFileW, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{AclAccess, AclInheritance, AclPrincipal, AclRule, acl_rules_are_private};

const DANGEROUS_PARENT_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
const DANGEROUS_EXISTING_PARENT_ACCESS: u32 =
    FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
const DANGEROUS_FILE_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `OwnedHandle` is constructed only from successful Win32
            // handle-returning calls and closes that handle exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: both security-descriptor and ACL allocations held here
            // are documented `LocalFree` allocations returned by Win32.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct CurrentUserSid {
    _token: OwnedHandle,
    token_info: Vec<usize>,
}

impl CurrentUserSid {
    fn get() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: the out-pointer is valid and the returned handle is
        // immediately transferred into `OwnedHandle`.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);

        let mut length = 0;
        // SAFETY: the null buffer/zero length call is the documented size
        // query. `length` is a valid writable out-parameter.
        let first =
            unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut length) };
        if first != 0 || length == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }

        let byte_length = usize::try_from(length).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Windows token length overflow")
        })?;
        let word_length = byte_length.div_ceil(size_of::<usize>());
        let mut token_info = vec![0_usize; word_length];
        // SAFETY: `token_info` is pointer-aligned and has at least `length`
        // writable bytes; the token handle stays live for the call.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                token_info.as_mut_ptr().cast::<c_void>(),
                length,
                &raw mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let result = Self {
            _token: token,
            token_info,
        };
        // SAFETY: `as_ptr` points into the initialized TOKEN_USER buffer owned
        // by `result`.
        if unsafe { IsValidSid(result.as_ptr()) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid current-user SID",
            ));
        }
        Ok(result)
    }

    fn as_ptr(&self) -> PSID {
        let token_user = self.token_info.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: `token_info` was filled by `GetTokenInformation(TokenUser)`,
        // is aligned as `usize`, and lives for the returned SID pointer.
        unsafe { (*token_user).User.Sid }
    }
}

#[repr(align(4))]
struct SidBytes([u8; SECURITY_MAX_SID_SIZE as usize]);

struct WellKnownSid {
    bytes: SidBytes,
}

impl WellKnownSid {
    fn get(kind: i32) -> io::Result<Self> {
        let mut result = Self {
            bytes: SidBytes([0; SECURITY_MAX_SID_SIZE as usize]),
        };
        let mut length = SECURITY_MAX_SID_SIZE;
        // SAFETY: the aligned fixed buffer is the documented maximum SID size
        // and `length` describes its writable capacity.
        if unsafe {
            CreateWellKnownSid(
                kind,
                null_mut(),
                result.bytes.0.as_mut_ptr().cast(),
                &raw mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    fn as_ptr(&self) -> PSID {
        self.bytes.0.as_ptr().cast_mut().cast()
    }
}

struct RequiredSids {
    current_user: CurrentUserSid,
    local_system: WellKnownSid,
    administrators: WellKnownSid,
    trusted_installer: LocalAllocation,
}

impl RequiredSids {
    fn get() -> io::Result<Self> {
        let mut trusted_installer = null_mut();
        let trusted_installer_text =
            wide_text("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        // SAFETY: the SID string is NUL terminated and the returned allocation
        // is transferred to `LocalAllocation`.
        if unsafe {
            ConvertStringSidToSidW(trusted_installer_text.as_ptr(), &raw mut trusted_installer)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            current_user: CurrentUserSid::get()?,
            local_system: WellKnownSid::get(WinLocalSystemSid)?,
            administrators: WellKnownSid::get(WinBuiltinAdministratorsSid)?,
            trusted_installer: LocalAllocation(trusted_installer.cast()),
        })
    }

    fn classify(&self, sid: PSID) -> AclPrincipal {
        // SAFETY: callers provide SIDs from a Win32 security descriptor or
        // owned SID buffer; null is checked before the API call.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return AclPrincipal::Other;
        }
        // SAFETY: all compared SID pointers are valid for the duration of this
        // method and have passed `IsValidSid`.
        if unsafe { EqualSid(sid, self.current_user.as_ptr()) } != 0 {
            AclPrincipal::CurrentUser
        } else if unsafe { EqualSid(sid, self.local_system.as_ptr()) } != 0 {
            AclPrincipal::LocalSystem
        } else if unsafe { EqualSid(sid, self.administrators.as_ptr()) } != 0 {
            AclPrincipal::Administrators
        } else {
            AclPrincipal::Other
        }
    }

    fn is_trusted(&self, sid: PSID) -> bool {
        self.classify(sid) != AclPrincipal::Other
            // SAFETY: the descriptor SID was validated by `classify`; the
            // TrustedInstaller SID is a live converted SID allocation.
            || (!sid.is_null()
                && unsafe { IsValidSid(sid) } != 0
                && unsafe { EqualSid(sid, self.trusted_installer.0.cast()) } != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index_high: u32,
    index_low: u32,
}

struct LockedPathComponent {
    path: PathBuf,
    identity: FileIdentity,
    _handle: OwnedHandle,
}

/// Keeps every existing directory component open without delete sharing.
///
/// Windows path APIs are otherwise susceptible to check/use swaps. Holding
/// these handles prevents rename/delete of checked components for the lifetime
/// of the operation. Identity comparison before each mutation is defense in
/// depth and makes a same-user test hook observable; same-user races are
/// authority-equivalent, while the ACL check rejects write/delete authority
/// for other principals.
struct TrustedPathGuard {
    components: Vec<LockedPathComponent>,
}

impl TrustedPathGuard {
    fn capture(path: &Path) -> io::Result<Self> {
        validate_local_absolute_path(path)?;
        let mut components = Vec::new();
        let mut current = PathBuf::new();
        let mut rooted = false;
        for component in path.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::RootDir) {
                rooted = true;
            }
            if !rooted {
                continue;
            }
            let metadata = match std::fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path contains a redirect or non-directory component: {}",
                        current.display()
                    ),
                ));
            }
            validate_trusted_parent_acl(&current)?;
            let (handle, identity) = open_locked_directory(&current)?;
            components.push(LockedPathComponent {
                path: current.clone(),
                identity,
                _handle: handle,
            });
        }
        Ok(Self { components })
    }

    fn verify(&self) -> io::Result<()> {
        for component in &self.components {
            let (_, identity) = open_directory_identity(&component.path, true)?;
            if identity != component.identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path changed during a security-sensitive operation: {}",
                        component.path.display()
                    ),
                ));
            }
            validate_trusted_parent_acl(&component.path)?;
        }
        Ok(())
    }
}

fn open_locked_directory(path: &Path) -> io::Result<(OwnedHandle, FileIdentity)> {
    open_directory_identity(path, false)
}

fn open_directory_identity(
    path: &Path,
    allow_delete_sharing: bool,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    let wide = wide_path(path)?;
    let share = FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | if allow_delete_sharing {
            FILE_SHARE_DELETE
        } else {
            0
        };
    // SAFETY: the path is NUL terminated; null security/template pointers are
    // permitted. OPEN_REPARSE_POINT prevents following a late redirect.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            share,
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
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `info` is a valid output buffer.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trusted Windows path is a reparse point: {}",
                path.display()
            ),
        ));
    }
    Ok((
        handle,
        FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    ))
}

struct LockedRegularFile {
    file: File,
    identity: FileIdentity,
}

fn open_locked_regular_file(path: &Path) -> io::Result<LockedRegularFile> {
    verify_no_redirects(path)?;
    let wide = wide_path(path)?;
    // SAFETY: the path is NUL terminated. Read sharing permits concurrent
    // readers, while withholding write/delete sharing binds bytes and identity
    // for the lifetime of the returned File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        // SAFETY: ownership has not yet been transferred to File.
        unsafe {
            CloseHandle(handle);
        }
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        // SAFETY: ownership has not yet been transferred to File.
        unsafe {
            CloseHandle(handle);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted Windows file is redirected or not regular: {}",
                path.display()
            ),
        ));
    }
    // SAFETY: `handle` is a unique owned file handle and ownership transfers
    // exactly once into `File`.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_trusted_file_acl(path)?;
    Ok(LockedRegularFile {
        file,
        identity: FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    })
}

fn hash_locked_regular_file(path: &Path) -> io::Result<String> {
    let mut locked = open_locked_regular_file(path)?;
    hash_open_file(&mut locked.file)
}

fn verify_trusted_regular_file(path: &Path) -> io::Result<()> {
    let _locked = open_locked_regular_file(path)?;
    Ok(())
}

pub(super) fn default_astrid_home_root() -> io::Result<PathBuf> {
    let local_data = BaseDirs::new()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Windows LocalAppData known folder is unavailable",
            )
        })?
        .data_local_dir()
        .to_path_buf();
    validate_local_absolute_path(&local_data)?;
    TrustedPathGuard::capture(&local_data)?.verify()?;
    Ok(local_data.join("Astrid").join("Runtime"))
}

pub(super) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    if path.exists() {
        let guard = TrustedPathGuard::capture(path)?;
        if !std::fs::metadata(path)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("private path is not a directory: {}", path.display()),
            ));
        }
        validate_private_acl(path, true)?;
        return guard.verify();
    }

    let existing_parent = nearest_existing_ancestor(path)?;
    let guard = TrustedPathGuard::capture(&existing_parent)?;
    validate_trusted_parent_acl_for_create(&existing_parent)?;
    std::fs::create_dir_all(path)?;
    guard.verify()?;
    verify_no_redirects(path)?;
    if !std::fs::metadata(path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private path is not a directory: {}", path.display()),
        ));
    }
    apply_private_acl(path, true)?;
    validate_private_acl(path, true)?;
    TrustedPathGuard::capture(path)?.verify()
}

pub(super) fn restrict_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    verify_regular_file(path)?;
    apply_private_acl(path, false)?;
    validate_private_acl(path, false)?;
    guard.verify()
}

pub(super) fn validate_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    verify_regular_file(path)?;
    validate_private_acl(path, false)?;
    guard.verify()
}

pub(super) fn read_private_file_to_string(path: &Path) -> io::Result<String> {
    validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows file has no parent directory",
        )
    })?;
    let guard = TrustedPathGuard::capture(parent)?;
    validate_private_acl(parent, true)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent)?;
    recover_private_file_transaction_locked(parent)?;
    guard.verify()?;

    let mut locked = open_locked_regular_file(path)?;
    validate_private_acl(path, false)?;
    if file_identity(&locked.file)? != locked.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file identity changed before reading",
        ));
    }
    let mut contents = String::new();
    locked.file.read_to_string(&mut contents)?;
    if file_identity(&locked.file)? != locked.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file identity changed while reading",
        ));
    }
    guard.verify()?;
    Ok(contents)
}

pub(super) fn atomic_write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows file has no parent directory",
        )
    })?;
    let target_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file has no final path component",
        )
    })?;
    let target_name_lower = target_name.to_string_lossy().to_ascii_lowercase();
    if target_name_lower.starts_with(".astrid-private.")
        || target_name_lower == PRIVATE_FILE_TRANSACTION_JOURNAL
        || target_name_lower == PRIVATE_FILE_TRANSACTION_LOCK
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file name conflicts with Astrid recovery metadata",
        ));
    }
    let guard = TrustedPathGuard::capture(parent)?;
    validate_private_acl(parent, true)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent)?;
    recover_private_file_transaction_locked(parent)?;
    guard.verify()?;
    if path.exists() {
        validate_private_file(path)?;
    }

    let journal = prepare_private_file_transaction(path, bytes)?;
    if let Err(error) = write_private_file_transaction_journal(parent, &journal) {
        let recovery = recover_private_file_transaction_locked(parent);
        if recovery.is_ok() {
            cleanup_private_file_transaction_files(parent, &journal);
        }
        return Err(recovery_error(&error, recovery));
    }
    if let Err(error) = finish_private_file_transaction(parent, &journal, &guard) {
        let recovery = recover_private_file_transaction_locked(parent);
        return Err(recovery_error(&error, recovery));
    }
    cleanup_private_file_transaction_files(parent, &journal);
    Ok(())
}

const PRIVATE_FILE_TRANSACTION_JOURNAL: &str = ".astrid-private-write.transaction.json";
const PRIVATE_FILE_TRANSACTION_LOCK: &str = ".astrid-private-write.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateFileTransaction {
    version: u32,
    transaction_id: String,
    target: Vec<u16>,
    staged: String,
    rollback: Option<String>,
    displaced: String,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

fn prepare_private_file_transaction(
    path: &Path,
    bytes: &[u8],
) -> io::Result<PrivateFileTransaction> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let target = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file has no final path component",
        )
    })?;
    let target = target.encode_wide().collect::<Vec<_>>();
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staged = format!(".astrid-private.{transaction_id}.new");
    let staged_path = stage_unique_bytes(parent, bytes, "astrid-private-write")?;
    let new_hash = match hash_locked_regular_file(&staged_path) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = std::fs::remove_file(&staged_path);
            return Err(error);
        },
    };
    let deterministic_staged = parent.join(&staged);
    if let Err(error) = move_file(&staged_path, &deterministic_staged) {
        let _ = std::fs::remove_file(&staged_path);
        return Err(error);
    }

    let had_live = path.exists();
    let (rollback, old_hash) = if had_live {
        let rollback_name = format!(".astrid-private.{transaction_id}.rollback");
        let (rollback_path, old_hash) =
            match stage_transaction_copy_authenticated(parent, path, &rollback_name) {
                Ok(result) => result,
                Err(error) => {
                    let _ = std::fs::remove_file(&deterministic_staged);
                    return Err(error);
                },
            };
        if let Err(error) = restrict_private_file(&rollback_path) {
            let _ = std::fs::remove_file(&rollback_path);
            let _ = std::fs::remove_file(&deterministic_staged);
            return Err(error);
        }
        (Some(rollback_name), Some(old_hash))
    } else {
        (None, None)
    };
    Ok(PrivateFileTransaction {
        version: 1,
        transaction_id: transaction_id.clone(),
        target,
        staged,
        rollback,
        displaced: format!(".astrid-private.{transaction_id}.displaced"),
        had_live,
        old_hash,
        new_hash,
    })
}

fn write_private_file_transaction_journal(
    parent: &Path,
    journal: &PrivateFileTransaction,
) -> io::Result<()> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if journal_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a private-file write transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(parent, &bytes, "astrid-private-write-journal")?;
    if let Err(error) = move_file(&staged, &journal_path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    flush_file(&journal_path)
}

fn read_private_file_transaction_journal(
    parent: &Path,
) -> io::Result<Option<PrivateFileTransaction>> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if !journal_path.exists() {
        return Ok(None);
    }
    validate_private_file(&journal_path)?;
    let bytes = std::fs::read(&journal_path)?;
    let journal: PrivateFileTransaction = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_private_file_transaction(&journal)?;
    Ok(Some(journal))
}

fn validate_private_file_transaction(journal: &PrivateFileTransaction) -> io::Result<()> {
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    let target = OsString::from_wide(&journal.target);
    if journal.version != 1
        || journal.transaction_id.len() != 32
        || !journal
            .transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || journal.target.is_empty()
        || journal.target.contains(&0)
        || !is_single_path_component(&target)
        || !is_single_path_component(OsStr::new(&journal.staged))
        || !is_single_path_component(OsStr::new(&journal.displaced))
        || journal
            .rollback
            .as_deref()
            .is_some_and(|name| !is_single_path_component(OsStr::new(name)))
        || !journal.staged.contains(&journal.transaction_id)
        || !journal.displaced.contains(&journal.transaction_id)
        || journal
            .rollback
            .as_deref()
            .is_some_and(|name| !name.contains(&journal.transaction_id))
        || journal.had_live != journal.rollback.is_some()
        || journal.had_live != journal.old_hash.is_some()
        || !valid_digest(&journal.new_hash)
        || journal
            .old_hash
            .as_deref()
            .is_some_and(|hash| !valid_digest(hash))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid private-file write journal",
        ));
    }
    Ok(())
}

fn is_single_path_component(value: &OsStr) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn finish_private_file_transaction(
    parent: &Path,
    journal: &PrivateFileTransaction,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    guard.verify()?;
    let live = parent.join(OsString::from_wide(&journal.target));
    let staged = parent.join(&journal.staged);
    let displaced = parent.join(&journal.displaced);
    if journal.had_live {
        replace_file_checked(&live, &staged, Some(&displaced))?;
    } else {
        move_file(&staged, &live)?;
    }
    validate_private_file(&live)?;
    if hash_locked_regular_file(&live)? != journal.new_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed private file digest changed",
        ));
    }
    guard.verify()?;
    remove_file_if_exists(&staged)?;
    remove_file_if_exists(&displaced)?;
    remove_private_file_transaction_journal(parent)
}

fn recover_private_file_transaction_locked(parent: &Path) -> io::Result<()> {
    let Some(journal) = read_private_file_transaction_journal(parent)? else {
        return Ok(());
    };
    let guard = TrustedPathGuard::capture(parent)?;
    guard.verify()?;
    let live = parent.join(OsString::from_wide(&journal.target));
    if journal.had_live {
        restore_private_file_transaction(parent, &journal, &live)?;
    } else if live.exists() {
        verify_regular_file(&live)?;
        std::fs::remove_file(&live)?;
    }
    guard.verify()?;
    remove_private_file_transaction_journal(parent)?;
    cleanup_private_file_transaction_files(parent, &journal);
    Ok(())
}

fn restore_private_file_transaction(
    parent: &Path,
    journal: &PrivateFileTransaction,
    live: &Path,
) -> io::Result<()> {
    let old_hash = journal.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing private rollback digest",
        )
    })?;
    if live.exists()
        && validate_private_file(live).is_ok()
        && hash_locked_regular_file(live)? == old_hash
    {
        return Ok(());
    }
    if live.exists() {
        verify_regular_file(live)?;
    }
    let rollback = parent.join(
        journal
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    validate_private_file(&rollback)?;
    if hash_locked_regular_file(&rollback)? != old_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private rollback does not match its journaled digest",
        ));
    }
    let restore_name = format!(
        ".astrid-private.{}.{}.restore",
        journal.transaction_id,
        uuid::Uuid::new_v4().simple()
    );
    let restore = stage_transaction_copy(parent, &rollback, &restore_name)?;
    if let Err(error) = restrict_private_file(&restore) {
        let _ = std::fs::remove_file(&restore);
        return Err(error);
    }
    if live.exists() {
        let displaced = parent.join(&journal.displaced);
        remove_file_if_exists(&displaced)?;
        replace_file_checked(live, &restore, Some(&displaced))?;
    } else if let Err(error) = move_file(&restore, live) {
        let _ = std::fs::remove_file(&restore);
        copy_file_synced(&rollback, live).map_err(|copy_error| {
            io::Error::new(
                copy_error.kind(),
                format!(
                    "could not restore an absent private file ({error}); copy fallback failed: {copy_error}"
                ),
            )
        })?;
        restrict_private_file(live)?;
    }
    validate_private_file(live)?;
    if hash_locked_regular_file(live)? != old_hash {
        return Err(io::Error::other(
            "rollback did not restore the journaled private file",
        ));
    }
    Ok(())
}

fn remove_private_file_transaction_journal(parent: &Path) -> io::Result<()> {
    remove_file_if_exists(&parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL))
}

fn cleanup_private_file_transaction_files(parent: &Path, journal: &PrivateFileTransaction) {
    let _ = std::fs::remove_file(parent.join(&journal.staged));
    let _ = std::fs::remove_file(parent.join(&journal.displaced));
    if let Some(rollback) = &journal.rollback {
        let _ = std::fs::remove_file(parent.join(rollback));
    }
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn nearest_existing_ancestor(path: &Path) -> io::Result<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => return Ok(current),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path ancestor is not a directory: {}", current.display()),
                ));
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
        if !current.pop() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Windows path has no existing directory ancestor",
            ));
        }
    }
}

pub(super) fn verify_no_redirects(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "security-sensitive Windows path must be absolute without traversal: {}",
                path.display()
            ),
        ));
    }

    let mut current = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir) {
            rooted = true;
        }
        if !rooted {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "security-sensitive Windows path contains a reparse point: {}",
                    current.display()
                ),
            ));
        }
    }
    let guard_path = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => path.to_path_buf(),
        Ok(_) => path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
            .to_path_buf(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => nearest_existing_ancestor(path)?,
        Err(error) => return Err(error),
    };
    TrustedPathGuard::capture(&guard_path)?.verify()
}

fn validate_local_absolute_path(path: &Path) -> io::Result<()> {
    let mut components = path.components();
    let local_disk = matches!(
        components.next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    ) && matches!(components.next(), Some(Component::RootDir));
    if !local_disk {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "security-sensitive Windows path must use a local absolute volume: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn verify_regular_file(path: &Path) -> io::Result<()> {
    verify_no_redirects(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private Windows path is redirected or not a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn apply_private_acl(path: &Path, is_directory: bool) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let inheritance = if is_directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let mut entries = [
        explicit_access(required.current_user.as_ptr(), TRUSTEE_IS_USER, inheritance),
        explicit_access(
            required.local_system.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
        explicit_access(
            required.administrators.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
    ];
    let mut acl: *mut ACL = null_mut();
    // SAFETY: all three explicit entries point at live SID buffers and the ACL
    // out-pointer is valid. A successful allocation is owned by `allocation`.
    let status = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).expect("three ACL entries fit in u32"),
            entries.as_mut_ptr(),
            null(),
            &raw mut acl,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let allocation = LocalAllocation(acl.cast());
    let wide = wide_path(path)?;
    // SAFETY: the NUL-terminated path and ACL allocation remain live for the
    // call; owner/group/SACL are intentionally unchanged.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    drop(allocation);
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    Ok(())
}

fn explicit_access(sid: PSID, trustee_type: i32, inheritance: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            ptstrName: sid.cast(),
        },
    }
}

fn validate_private_acl(path: &Path, is_directory: bool) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let wide = wide_path(path)?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all out-pointers are valid and `wide` is NUL terminated. The
    // returned descriptor is released by `LocalAllocation`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let allocation = LocalAllocation(descriptor);
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private Windows path has a null DACL: {}", path.display()),
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is the live descriptor returned above and both
    // output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let dacl_is_protected = control & SE_DACL_PROTECTED != 0;
    let owner_is_allowed = required.classify(owner) != AclPrincipal::Other;

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is non-null and owned by the live descriptor; `info` has
    // the exact documented output size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL_SIZE_INFORMATION fits in u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut rules = Vec::with_capacity(usize::try_from(info.AceCount).unwrap_or_default());
    for index in 0..info.AceCount {
        let mut raw_ace: *mut c_void = null_mut();
        // SAFETY: `index` is bounded by the ACE count returned for this live
        // ACL, and `raw_ace` is a valid out-pointer.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        rules.push(private_acl_rule(&required, raw_ace, is_directory));
    }
    drop(allocation);

    if !acl_rules_are_private(is_directory, dacl_is_protected, owner_is_allowed, &rules) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private Windows path ACL is not restricted to the current user and required system principals: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn private_acl_rule(required: &RequiredSids, raw_ace: *mut c_void, is_directory: bool) -> AclRule {
    let invalid = || AclRule {
        principal: AclPrincipal::Other,
        access: AclAccess::Other,
        inheritance: AclInheritance::InheritedOrOther,
    };
    // SAFETY: caller obtained a non-null ACE pointer from GetAce.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return invalid();
    }
    // SAFETY: this is a plain ACCESS_ALLOWED_ACE.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = (&raw const ace.SidStart).cast_mut().cast();
    let ace_flags = u32::from(ace.Header.AceFlags);
    let expected_flags = if is_directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let inheritance = match ace_flags {
        flags if flags != expected_flags => AclInheritance::InheritedOrOther,
        0 => AclInheritance::None,
        flags if flags == OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE => AclInheritance::Children,
        _ => AclInheritance::InheritedOrOther,
    };
    AclRule {
        principal: required.classify(sid),
        access: if ace.Mask == FILE_ALL_ACCESS {
            AclAccess::AllowFullControl
        } else {
            AclAccess::Other
        },
        inheritance,
    }
}

fn validate_trusted_parent_acl(path: &Path) -> io::Result<()> {
    validate_trusted_parent_acl_with_mask(path, DANGEROUS_EXISTING_PARENT_ACCESS)
}

fn validate_trusted_parent_acl_for_create(path: &Path) -> io::Result<()> {
    validate_trusted_parent_acl_with_mask(path, DANGEROUS_PARENT_ACCESS)
}

fn validate_trusted_parent_acl_with_mask(path: &Path, dangerous_access: u32) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let wide = wide_path(path)?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all out-pointers are valid and `wide` is NUL terminated.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(descriptor);
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trusted Windows parent has a null DACL: {}", path.display()),
        ));
    }
    if !required.is_trusted(owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trusted Windows parent has an untrusted owner: {}",
                path.display()
            ),
        ));
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the live descriptor and `info` is exact size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL_SIZE_INFORMATION fits in u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    for index in 0..info.AceCount {
        let mut raw_ace: *mut c_void = null_mut();
        // SAFETY: `index` is bounded by the returned ACE count.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE starts with ACE_HEADER.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows parent has an unsupported ACE type: {}",
                    path.display()
                ),
            ));
        }
        // SAFETY: this is a plain ACCESS_ALLOWED_ACE.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let flags = u32::from(ace.Header.AceFlags);
        let sid = (&raw const ace.SidStart).cast_mut().cast();
        let applies_to_parent = flags & INHERIT_ONLY_ACE == 0;
        let applies_to_file_child = flags & OBJECT_INHERIT_ACE != 0;
        let applies_to_directory_child = flags & CONTAINER_INHERIT_ACE != 0;
        let unsafe_for_untrusted = (applies_to_parent && ace.Mask & dangerous_access != 0)
            || (applies_to_file_child && ace.Mask & DANGEROUS_FILE_ACCESS != 0)
            || (applies_to_directory_child && ace.Mask & DANGEROUS_PARENT_ACCESS != 0);
        if !required.is_trusted(sid) && unsafe_for_untrusted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows parent grants write or delete authority to an untrusted principal: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_trusted_file_acl(path: &Path) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let wide = wide_path(path)?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all output pointers are valid and `wide` is NUL terminated.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(descriptor);
    if dacl.is_null() || !required.is_trusted(owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trusted Windows file has an unsafe owner or null DACL: {}",
                path.display()
            ),
        ));
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: descriptor and DACL remain live and the output buffer is exact.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL_SIZE_INFORMATION fits in u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    for index in 0..info.AceCount {
        let mut raw_ace: *mut c_void = null_mut();
        // SAFETY: index is bounded by the returned ACE count.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE starts with ACE_HEADER.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        let flags = u32::from(header.AceFlags);
        if flags & !(INHERITED_ACE) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows file has unexpected ACE flags: {}",
                    path.display()
                ),
            ));
        }
        if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows file has an unsupported ACE type: {}",
                    path.display()
                ),
            ));
        }
        // SAFETY: this is a plain ACCESS_ALLOWED_ACE.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const ace.SidStart).cast_mut().cast();
        if !required.is_trusted(sid) && ace.Mask & DANGEROUS_FILE_ACCESS != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows file is writable by an untrusted principal: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn replace_executable_set(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> io::Result<()> {
    validate_local_absolute_path(install_dir)?;
    validate_local_absolute_path(extract_dir)?;
    let install_guard = TrustedPathGuard::capture(install_dir)?;
    let extract_guard = TrustedPathGuard::capture(extract_dir)?;
    validate_trusted_parent_acl_for_create(install_dir)?;
    let _transaction_lock = acquire_transaction_lock(install_dir)?;
    recover_executable_transaction_locked(install_dir)?;
    install_guard.verify()?;
    extract_guard.verify()?;

    let journal = prepare_executable_transaction(
        install_dir,
        extract_dir,
        names,
        &install_guard,
        &extract_guard,
    )?;
    let transaction_id = &journal.transaction_id;
    if let Err(error) = write_transaction_journal(install_dir, &journal) {
        let recovery = recover_executable_transaction_locked(install_dir);
        return Err(recovery_error(&error, recovery));
    }
    let result =
        finish_executable_transaction(install_dir, &journal, transaction_id, &install_guard);
    if let Err(error) = result {
        let recovery = recover_executable_transaction_locked(install_dir);
        return Err(recovery_error(&error, recovery));
    }
    cleanup_rollback_files(install_dir, &journal);
    Ok(())
}

const TRANSACTION_JOURNAL: &str = ".astrid-update.transaction.json";
const TRANSACTION_LOCK: &str = ".astrid-update.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableTransaction {
    version: u32,
    transaction_id: String,
    entries: Vec<ExecutableTransactionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableTransactionEntry {
    name: String,
    staged: String,
    rollback: Option<String>,
    displaced: String,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

fn acquire_transaction_lock(install_dir: &Path) -> io::Result<File> {
    acquire_named_private_lock(
        &install_dir.join(TRANSACTION_LOCK),
        "another Astrid executable replacement",
    )
}

fn acquire_private_file_transaction_lock(parent: &Path) -> io::Result<File> {
    acquire_named_private_lock(
        &parent.join(PRIVATE_FILE_TRANSACTION_LOCK),
        "another Astrid private-file write",
    )
}

fn acquire_named_private_lock(path: &Path, owner_description: &str) -> io::Result<File> {
    let (file, created) = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?,
            false,
        ),
        Err(error) => return Err(error),
    };
    if created {
        restrict_private_file(path)?;
    } else {
        validate_private_file(path)?;
    }
    file.try_lock().map_err(|error| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("{owner_description} owns {}: {error}", path.display()),
        )
    })?;
    Ok(file)
}

fn finish_executable_transaction(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    transaction_id: &str,
    install_guard: &TrustedPathGuard,
) -> io::Result<()> {
    for (index, entry) in journal.entries.iter().enumerate() {
        install_guard.verify()?;
        let live = install_dir.join(&entry.name);
        let staged = install_dir.join(&entry.staged);
        let displaced = install_dir.join(&entry.displaced);
        if entry.had_live {
            replace_file_checked(&live, &staged, Some(&displaced))?;
        } else {
            move_file(&staged, &live)?;
        }
        if hash_locked_regular_file(&live)? != entry.new_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed executable digest changed",
            ));
        }
        test_maybe_interrupt_after_replace(index);
    }

    // Preserve the prior authenticated executables as conventional backups.
    // Rollback copies stay independent and live until the journal commit point.
    for entry in &journal.entries {
        if let Some(rollback_name) = &entry.rollback {
            install_guard.verify()?;
            let rollback = install_dir.join(rollback_name);
            let backup = install_dir.join(format!("{}.bak", entry.name));
            let staged_backup = stage_transaction_copy(
                install_dir,
                &rollback,
                &format!(".{}.{}.backup", entry.name, transaction_id),
            )?;
            if backup.exists() {
                verify_trusted_regular_file(&backup)?;
                let displaced =
                    install_dir.join(format!(".{}.{}.old-backup", entry.name, transaction_id));
                replace_file_checked(&backup, &staged_backup, Some(&displaced))?;
                std::fs::remove_file(displaced)?;
            } else {
                move_file(&staged_backup, &backup)?;
            }
        }
    }
    install_guard.verify()?;
    cleanup_precommit_files(install_dir, journal)?;
    test_maybe_interrupt_before_commit();
    remove_transaction_journal(install_dir)
}

fn prepare_executable_transaction(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
    install_guard: &TrustedPathGuard,
    extract_guard: &TrustedPathGuard,
) -> io::Result<ExecutableTransaction> {
    let install_volume = volume_root(install_dir)?;
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let mut journal = ExecutableTransaction {
        version: 1,
        transaction_id: transaction_id.clone(),
        entries: Vec::with_capacity(names.len()),
    };
    for name in names {
        let source = extract_dir.join(name);
        verify_regular_file(&source)?;
        extract_guard.verify()?;
        install_guard.verify()?;
        let staged_name = format!(".{name}.{transaction_id}.new");
        let (temporary, new_hash) =
            stage_transaction_copy_authenticated(install_dir, &source, &staged_name)?;
        if volume_root(&temporary)? != install_volume {
            let _ = std::fs::remove_file(&temporary);
            cleanup_transaction_files(install_dir, &journal);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "staged executable is not on the live executable volume",
            ));
        }
        let live = install_dir.join(name);
        let had_live = live.exists();
        let (rollback, old_hash) = if had_live {
            verify_regular_file(&live)?;
            let rollback_name = format!(".{name}.{transaction_id}.rollback");
            let (_, old_hash) =
                stage_transaction_copy_authenticated(install_dir, &live, &rollback_name)?;
            (Some(rollback_name), Some(old_hash))
        } else {
            (None, None)
        };
        journal.entries.push(ExecutableTransactionEntry {
            name: (*name).to_owned(),
            staged: staged_name,
            rollback,
            displaced: format!(".{name}.{transaction_id}.displaced"),
            had_live,
            old_hash,
            new_hash,
        });
    }
    Ok(journal)
}

fn write_transaction_journal(
    install_dir: &Path,
    journal: &ExecutableTransaction,
) -> io::Result<()> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if journal_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an executable replacement transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(install_dir, &bytes, "astrid-update-journal")?;
    move_file(&staged, &journal_path)?;
    flush_file(&journal_path)
}

fn read_transaction_journal(install_dir: &Path) -> io::Result<Option<ExecutableTransaction>> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if !journal_path.exists() {
        return Ok(None);
    }
    validate_private_file(&journal_path)?;
    let bytes = std::fs::read(&journal_path)?;
    let journal: ExecutableTransaction = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if journal.version != 1 || journal.entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or empty executable replacement journal",
        ));
    }
    for entry in &journal.entries {
        validate_transaction_entry(&journal.transaction_id, entry)?;
    }
    Ok(Some(journal))
}

fn validate_transaction_entry(
    transaction_id: &str,
    entry: &ExecutableTransactionEntry,
) -> io::Result<()> {
    let valid_component = |value: &str| {
        let mut components = Path::new(value).components();
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
    };
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if transaction_id.len() != 32
        || !transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !valid_component(&entry.name)
        || !valid_component(&entry.staged)
        || !valid_component(&entry.displaced)
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !valid_component(name))
        || !entry.staged.contains(transaction_id)
        || !entry.displaced.contains(transaction_id)
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !name.contains(transaction_id))
        || entry.had_live != entry.rollback.is_some()
        || entry.had_live != entry.old_hash.is_some()
        || !valid_digest(&entry.new_hash)
        || entry
            .old_hash
            .as_deref()
            .is_some_and(|hash| !valid_digest(hash))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid executable replacement journal entry",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn recover_executable_transaction(install_dir: &Path) -> io::Result<()> {
    let _transaction_lock = acquire_transaction_lock(install_dir)?;
    recover_executable_transaction_locked(install_dir)
}

fn recover_executable_transaction_locked(install_dir: &Path) -> io::Result<()> {
    let Some(journal) = read_transaction_journal(install_dir)? else {
        return Ok(());
    };
    let guard = TrustedPathGuard::capture(install_dir)?;
    let mut failures = Vec::new();
    for entry in journal.entries.iter().rev() {
        guard.verify()?;
        let live = install_dir.join(&entry.name);
        let result = if entry.had_live {
            restore_transaction_entry(install_dir, entry)
        } else if live.exists() {
            std::fs::remove_file(&live)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            failures.push(format!("{}: {error}", live.display()));
        }
    }
    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "executable replacement recovery is still pending ({}); retry after releasing open executable handles",
            failures.join("; ")
        )));
    }
    remove_transaction_journal(install_dir)?;
    cleanup_transaction_files(install_dir, &journal);
    Ok(())
}

fn restore_transaction_entry(
    install_dir: &Path,
    entry: &ExecutableTransactionEntry,
) -> io::Result<()> {
    let old_hash = entry.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing rollback content hash")
    })?;
    let live = install_dir.join(&entry.name);
    if live.exists() && hash_locked_regular_file(&live)? == old_hash {
        return Ok(());
    }
    let rollback = install_dir.join(
        entry
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    verify_regular_file(&rollback)?;
    if hash_locked_regular_file(&rollback)? != old_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rollback executable does not match its journaled digest",
        ));
    }
    let restore = stage_transaction_copy(
        install_dir,
        &rollback,
        &format!(".{}.{}.restore", entry.name, uuid::Uuid::new_v4().simple()),
    )?;
    if live.exists() {
        let displaced = install_dir.join(&entry.displaced);
        let _ = std::fs::remove_file(&displaced);
        replace_file_checked(&live, &restore, Some(&displaced))?;
    } else if let Err(error) = move_file(&restore, &live) {
        // A ReplaceFileW partial-mutation error can leave the live name absent.
        // A direct copy is a final supported fallback; the rollback source is
        // deliberately retained until the journal commit point.
        let _ = std::fs::remove_file(&restore);
        copy_file_synced(&rollback, &live).map_err(|copy_error| {
            io::Error::new(
                copy_error.kind(),
                format!(
                    "could not restore an absent live executable ({error}); copy fallback failed: {copy_error}"
                ),
            )
        })?;
    }
    if !live.exists() || hash_locked_regular_file(&live)? != old_hash {
        return Err(io::Error::other(
            "rollback did not restore the journaled live executable",
        ));
    }
    Ok(())
}

fn remove_transaction_journal(install_dir: &Path) -> io::Result<()> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    match std::fs::remove_file(journal_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn cleanup_transaction_files(install_dir: &Path, journal: &ExecutableTransaction) {
    for entry in &journal.entries {
        let _ = std::fs::remove_file(install_dir.join(&entry.staged));
        let _ = std::fs::remove_file(install_dir.join(&entry.displaced));
        if let Some(rollback) = &entry.rollback {
            let _ = std::fs::remove_file(install_dir.join(rollback));
        }
    }
}

fn cleanup_precommit_files(install_dir: &Path, journal: &ExecutableTransaction) -> io::Result<()> {
    for entry in &journal.entries {
        for path in [
            install_dir.join(&entry.staged),
            install_dir.join(&entry.displaced),
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn cleanup_rollback_files(install_dir: &Path, journal: &ExecutableTransaction) {
    for entry in &journal.entries {
        if let Some(rollback) = &entry.rollback {
            let _ = std::fs::remove_file(install_dir.join(rollback));
        }
    }
}

fn recovery_error(install_error: &io::Error, recovery: io::Result<()>) -> io::Error {
    match recovery {
        Ok(()) => io::Error::new(
            install_error.kind(),
            format!(
                "executable replacement failed and the prior set was restored: {install_error}"
            ),
        ),
        Err(recovery_error) => io::Error::new(
            install_error.kind(),
            format!(
                "executable replacement failed: {install_error}; recovery remains journaled: {recovery_error}"
            ),
        ),
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestReplaceFault {
    NoMutation(u32),
    OldMovedToBackup(u32),
}

#[cfg(test)]
static TEST_REPLACE_FAULT: std::sync::Mutex<Option<TestReplaceFault>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn test_replace_fault(
    live: &Path,
    _replacement: &Path,
    backup: Option<&Path>,
) -> Option<io::Result<()>> {
    let fault = TEST_REPLACE_FAULT.lock().expect("fault lock").take()?;
    match fault {
        TestReplaceFault::NoMutation(code) => {
            Some(Err(io::Error::from_raw_os_error(code.cast_signed())))
        },
        TestReplaceFault::OldMovedToBackup(code) => {
            let result = backup
                .ok_or_else(|| io::Error::other("fault requires a backup path"))
                .and_then(|backup| move_file(live, backup))
                .and_then(|()| Err(io::Error::from_raw_os_error(code.cast_signed())));
            Some(result)
        },
    }
}

#[cfg(not(test))]
fn test_maybe_interrupt_after_replace(_: usize) {}

#[cfg(test)]
static TEST_CRASH_AFTER_REPLACE: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_ABORT_AFTER_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_ABORT_INSIDE_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_PAUSE_INSIDE_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn test_maybe_pause_inside_replace() {
    if TEST_PAUSE_INSIDE_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
        println!("astrid-private-replace-ready");
        std::io::stdout().flush().expect("flush pause marker");
        let mut release = String::new();
        std::io::stdin()
            .read_line(&mut release)
            .expect("read pause release");
    }
}

#[cfg(test)]
fn test_maybe_interrupt_after_replace(index: usize) {
    if index == 0 && TEST_ABORT_AFTER_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::abort();
    }
    let should_interrupt = *TEST_CRASH_AFTER_REPLACE.lock().expect("crash lock") == Some(index);
    assert!(
        !should_interrupt,
        "simulated process interruption after executable replacement"
    );
}

#[cfg(not(test))]
fn test_maybe_interrupt_before_commit() {}

#[cfg(test)]
static TEST_CRASH_BEFORE_COMMIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

#[cfg(test)]
fn test_maybe_interrupt_before_commit() {
    let should_interrupt = *TEST_CRASH_BEFORE_COMMIT.lock().expect("commit crash lock");
    assert!(
        !should_interrupt,
        "simulated process interruption before transaction commit"
    );
}

fn stage_transaction_copy(
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<PathBuf> {
    stage_transaction_copy_authenticated(install_dir, source, file_name).map(|(path, _hash)| path)
}

fn stage_transaction_copy_authenticated(
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<(PathBuf, String)> {
    let mut source = open_locked_regular_file(source)?;
    let source_identity = source.identity;
    let source_hash = hash_open_file(&mut source.file)?;
    source.file.seek(io::SeekFrom::Start(0))?;
    let destination = install_dir.join(file_name);
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)?;
    let result = (|| {
        io::copy(&mut source.file, &mut output)?;
        output.flush()?;
        output.sync_all()
    })();
    drop(output);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&destination);
        return Err(error);
    }
    if file_identity(&source.file)? != source_identity {
        let _ = std::fs::remove_file(&destination);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source executable identity changed while staging",
        ));
    }
    let staged_hash = match hash_locked_regular_file(&destination) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = std::fs::remove_file(&destination);
            return Err(error);
        },
    };
    if staged_hash != source_hash {
        let _ = std::fs::remove_file(&destination);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged executable does not match its locked source handle",
        ));
    }
    Ok((destination, source_hash))
}

fn copy_file_synced(source: &Path, destination: &Path) -> io::Result<()> {
    let mut input = open_locked_regular_file(source)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut input.file, &mut output)?;
    output.flush()?;
    output.sync_all()
}

fn flush_file(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    // `sync_all` maps to the supported `FlushFileBuffers` operation. We make
    // no claim that Windows durably commits subsequent namespace operations.
    file.sync_all()
}

fn hash_open_file(input: &mut File) -> io::Result<String> {
    input.seek(io::SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    io::copy(input, &mut hasher)?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the File owns a live Windows handle and `info` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume: info.dwVolumeSerialNumber,
        index_high: info.nFileIndexHigh,
        index_low: info.nFileIndexLow,
    })
}

fn stage_unique_bytes(parent: &Path, bytes: &[u8], label: &str) -> io::Result<PathBuf> {
    for _ in 0..16 {
        let temporary = parent.join(format!(".{label}.{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut output = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let write_result = (|| {
            output.write_all(bytes)?;
            output.flush()?;
            output.sync_all()
        })();
        drop(output);
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = restrict_private_file(&temporary) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        return Ok(temporary);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private staging path",
    ))
}

fn replace_file_checked(live: &Path, replacement: &Path, backup: Option<&Path>) -> io::Result<()> {
    let result = replace_file_raw(live, replacement, backup);
    let Err(error) = result else {
        return Ok(());
    };
    let code = error.raw_os_error().map(i32::cast_unsigned);
    let documented_partial_mutation = matches!(
        code,
        Some(
            ERROR_UNABLE_TO_REMOVE_REPLACED
                | ERROR_UNABLE_TO_MOVE_REPLACEMENT
                | ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
        )
    );

    // ReplaceFileW documents three failures that may happen after one or more
    // namespace mutations. Always inspect all names, and for those codes
    // immediately reconcile an absent live name before returning. The caller's
    // transaction rollback copy remains independent of these three paths.
    let live_exists = live.exists();
    let backup_exists = backup.is_some_and(Path::exists);
    let replacement_exists = replacement.exists();
    if !live_exists && (documented_partial_mutation || backup_exists || replacement_exists) {
        let candidate = backup
            .filter(|path| path.exists())
            .or_else(|| replacement.exists().then_some(replacement));
        if let Some(candidate) = candidate
            && let Err(move_error) = move_file(candidate, live)
            && !live.exists()
            && let Err(copy_error) = copy_file_synced(candidate, live)
        {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "ReplaceFileW failed after mutation ({error}); live executable was absent and reconciliation failed ({move_error}; {copy_error})"
                ),
            ));
        }
    }
    if !live.exists() {
        return Err(io::Error::new(
            error.kind(),
            format!(
                "ReplaceFileW failed ({error}); live executable is absent while recovery artifacts remain"
            ),
        ));
    }
    Err(error)
}

fn replace_file_raw(live: &Path, replacement: &Path, backup: Option<&Path>) -> io::Result<()> {
    #[cfg(test)]
    if let Some(result) = test_replace_fault(live, replacement, backup) {
        return result;
    }
    let live = wide_path(live)?;
    let replacement = wide_path(replacement)?;
    let backup = backup.map(wide_path).transpose()?;
    let backup_ptr = backup.as_ref().map_or(null(), Vec::as_ptr);
    // SAFETY: all optional and required path buffers are NUL terminated and
    // live for the call; reserved pointers are null as required by Win32.
    if unsafe {
        ReplaceFileW(
            live.as_ptr(),
            replacement.as_ptr(),
            backup_ptr,
            0,
            null(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    #[cfg(test)]
    {
        test_maybe_pause_inside_replace();
        if TEST_ABORT_INSIDE_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
            std::process::abort();
        }
    }
    Ok(())
}

fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both path buffers are NUL terminated and live for the call.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn volume_root(path: &Path) -> io::Result<Vec<u16>> {
    let wide = wide_path(path)?;
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: `wide` is NUL terminated and `buffer` is writable for the
    // capacity supplied to Win32.
    if unsafe {
        GetVolumePathNameW(
            wide.as_ptr(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).expect("Windows maximum path buffer fits in u32"),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = buffer.iter().position(|unit| *unit == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows volume path was not NUL terminated",
        )
    })?;
    buffer.truncate(length);
    for unit in &mut buffer {
        if (*unit >= u16::from(b'A')) && (*unit <= u16::from(b'Z')) {
            *unit = unit
                .checked_add(u16::from(b'a' - b'A'))
                .expect("ASCII uppercase plus case offset fits u16");
        }
    }
    Ok(buffer)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_text(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod native_tests {
    use std::io::BufRead as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::process::Stdio;

    use windows_sys::Win32::Foundation::{
        ERROR_SHARING_VIOLATION, ERROR_UNABLE_TO_MOVE_REPLACEMENT,
        ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, ERROR_UNABLE_TO_REMOVE_REPLACED,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, NO_PROPAGATE_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ};

    use super::*;
    use crate::groups::{BUILTIN_ADMIN, GroupConfig};
    use crate::profile::PrincipalProfile;
    use crate::session_token::SessionToken;

    static NATIVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn private_temp() -> tempfile::TempDir {
        let local = BaseDirs::new().unwrap().data_local_dir().to_path_buf();
        let root = tempfile::Builder::new()
            .prefix("astrid-platform-fs-")
            .tempdir_in(local)
            .unwrap();
        apply_private_acl(root.path(), true).unwrap();
        validate_private_acl(root.path(), true).unwrap();
        root
    }

    fn update_tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = private_temp();
        let install = root.path().join("install");
        let extract = root.path().join("extract");
        std::fs::create_dir(&install).unwrap();
        std::fs::create_dir(&extract).unwrap();
        apply_private_acl(&install, true).unwrap();
        apply_private_acl(&extract, true).unwrap();
        std::fs::write(install.join("astrid.exe"), b"old-cli").unwrap();
        std::fs::write(install.join("astrid-daemon.exe"), b"old-daemon").unwrap();
        std::fs::write(extract.join("astrid.exe"), b"new-cli").unwrap();
        std::fs::write(extract.join("astrid-daemon.exe"), b"new-daemon").unwrap();
        (root, install, extract)
    }

    fn assert_old_set(install: &Path) {
        assert_eq!(
            std::fs::read(install.join("astrid.exe")).unwrap(),
            b"old-cli"
        );
        assert_eq!(
            std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
            b"old-daemon"
        );
        assert!(!install.join(TRANSACTION_JOURNAL).exists());
    }

    fn abort_private_write(file: &Path) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("platform_fs::windows::native_tests::child_aborts_inside_private_file_replace")
            .arg("--ignored")
            .arg("--nocapture")
            .env("ASTRID_TEST_PRIVATE_FILE", file)
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(
            file.parent()
                .unwrap()
                .join(PRIVATE_FILE_TRANSACTION_JOURNAL)
                .exists()
        );
    }

    fn set_world_entry(path: &Path, mask: u32, protected: bool) {
        set_world_entry_with_flags(path, mask, protected, 0);
    }

    fn set_world_entry_with_flags(path: &Path, mask: u32, protected: bool, inheritance: u32) {
        let world = WellKnownSid::get(WinWorldSid).unwrap();
        let mut entries = [explicit_access(
            world.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        )];
        entries[0].grfAccessPermissions = mask;
        let mut acl: *mut ACL = null_mut();
        // SAFETY: the entry owns a live world SID and the out pointer is valid.
        let status = unsafe { SetEntriesInAclW(1, entries.as_mut_ptr(), null(), &raw mut acl) };
        assert_eq!(status, ERROR_SUCCESS);
        let allocation = LocalAllocation(acl.cast());
        let mut wide = wide_path(path).unwrap();
        let protection = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: path and ACL are live for the call.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        };
        drop(allocation);
        assert_eq!(status, ERROR_SUCCESS);
    }

    fn set_required_directory_acl_flags(path: &Path, extra_flags: u32) {
        let required = RequiredSids::get().unwrap();
        let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | extra_flags;
        let mut entries = [
            explicit_access(required.current_user.as_ptr(), TRUSTEE_IS_USER, inheritance),
            explicit_access(
                required.local_system.as_ptr(),
                TRUSTEE_IS_WELL_KNOWN_GROUP,
                inheritance,
            ),
            explicit_access(
                required.administrators.as_ptr(),
                TRUSTEE_IS_WELL_KNOWN_GROUP,
                inheritance,
            ),
        ];
        let mut acl: *mut ACL = null_mut();
        // SAFETY: all entries retain live SID storage and the out pointer is valid.
        let status = unsafe {
            SetEntriesInAclW(
                u32::try_from(entries.len()).unwrap(),
                entries.as_mut_ptr(),
                null(),
                &raw mut acl,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let allocation = LocalAllocation(acl.cast());
        let mut wide = wide_path(path).unwrap();
        // SAFETY: path and ACL remain live for the call.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        };
        drop(allocation);
        assert_eq!(status, ERROR_SUCCESS);
    }

    #[test]
    fn private_create_and_atomic_write_are_acl_validated() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();
        let directory = root.path().join("private");
        ensure_private_directory(&directory).unwrap();
        let file = directory.join("token");
        atomic_write_private_file(&file, b"secret").unwrap();
        validate_private_file(&file).unwrap();
        assert_eq!(std::fs::read(file).unwrap(), b"secret");
    }

    #[test]
    fn trusted_parent_rejects_permissive_extra_inherited_and_null_dacls() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        for (mask, protected) in [(FILE_ALL_ACCESS, true), (FILE_ALL_ACCESS, false)] {
            let root = private_temp();
            set_world_entry(root.path(), mask, protected);
            assert!(TrustedPathGuard::capture(root.path()).is_err());
        }

        let root = private_temp();
        let file = root.path().join("private");
        std::fs::write(&file, b"secret").unwrap();
        apply_private_acl(&file, false).unwrap();
        set_world_entry(&file, FILE_GENERIC_READ, true);
        assert!(validate_private_file(&file).is_err());

        let root = private_temp();
        let mut wide = wide_path(root.path()).unwrap();
        // SAFETY: a null DACL is intentionally installed for this adversarial
        // test; the temporary directory remains owned by the test process.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(TrustedPathGuard::capture(root.path()).is_err());

        for unexpected in [INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE] {
            let root = private_temp();
            set_required_directory_acl_flags(root.path(), unexpected);
            assert!(validate_private_acl(root.path(), true).is_err());
        }
    }

    #[test]
    fn trusted_parent_lock_blocks_path_swap() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();
        let guarded = root.path().join("guarded");
        std::fs::create_dir(&guarded).unwrap();
        apply_private_acl(&guarded, true).unwrap();
        let guard = TrustedPathGuard::capture(&guarded).unwrap();
        let moved = root.path().join("moved");
        assert!(std::fs::rename(&guarded, &moved).is_err());
        guard.verify().unwrap();
    }

    #[test]
    fn transaction_lock_excludes_a_second_process() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, install, _extract) = update_tree();
        drop(acquire_transaction_lock(&install).unwrap());
        let lock_path = install.join(TRANSACTION_LOCK);
        let script = concat!(
            "$f=[IO.File]::Open($env:ASTRID_LOCK_TEST_PATH,",
            "[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite);",
            "$f.Lock(0,[Int64]::MaxValue);",
            "[Console]::Out.WriteLine('ready');",
            "[Console]::Out.Flush();",
            "Start-Sleep -Seconds 30"
        );
        let mut child = std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(script)
            .env("ASTRID_LOCK_TEST_PATH", &lock_path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        let error = acquire_transaction_lock(&install).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        child.kill().unwrap();
        child.wait().unwrap();
        acquire_transaction_lock(&install).unwrap();
    }

    #[test]
    fn dangerous_inherit_only_ace_and_untrusted_source_are_rejected() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, install, extract) = update_tree();
        set_world_entry_with_flags(
            &install,
            FILE_ALL_ACCESS,
            true,
            OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
        );
        assert!(
            replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                .is_err()
        );

        let (_root, install, extract) = update_tree();
        let source = extract.join("astrid.exe");
        set_world_entry(&source, FILE_ALL_ACCESS, true);
        assert!(
            replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                .is_err()
        );
        assert_old_set(&install);
    }

    #[test]
    fn locked_source_handle_blocks_concurrent_mutation() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, _install, extract) = update_tree();
        let source = extract.join("astrid.exe");
        let locked = open_locked_regular_file(&source).unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&source)
                .is_err()
        );
        assert_eq!(file_identity(&locked.file).unwrap(), locked.identity);
    }

    #[test]
    fn redirecting_directory_component_is_rejected() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();
        let target = root.path().join("target");
        let redirect = root.path().join("redirect");
        std::fs::create_dir(&target).unwrap();
        apply_private_acl(&target, true).unwrap();
        std::os::windows::fs::symlink_dir(&target, &redirect).unwrap();
        assert!(TrustedPathGuard::capture(&redirect).is_err());
    }

    #[test]
    fn junction_directory_component_is_rejected() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();
        let target = root.path().join("junction-target");
        let redirect = root.path().join("junction");
        std::fs::create_dir(&target).unwrap();
        apply_private_acl(&target, true).unwrap();
        let status = std::process::Command::new("cmd.exe")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&redirect)
            .arg(&target)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(TrustedPathGuard::capture(&redirect).is_err());
    }

    #[test]
    fn replacefile_documented_partial_failures_restore_complete_old_set() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        for fault in [
            TestReplaceFault::NoMutation(ERROR_UNABLE_TO_REMOVE_REPLACED),
            TestReplaceFault::NoMutation(ERROR_UNABLE_TO_MOVE_REPLACEMENT),
            TestReplaceFault::OldMovedToBackup(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2),
        ] {
            let (_root, install, extract) = update_tree();
            *TEST_REPLACE_FAULT.lock().unwrap() = Some(fault);
            assert!(
                replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                    .is_err()
            );
            assert_old_set(&install);
        }
    }

    #[test]
    fn private_write_partial_replace_failure_restores_old_file() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        for fault in [
            TestReplaceFault::NoMutation(ERROR_UNABLE_TO_REMOVE_REPLACED),
            TestReplaceFault::NoMutation(ERROR_UNABLE_TO_MOVE_REPLACEMENT),
            TestReplaceFault::OldMovedToBackup(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2),
        ] {
            let root = private_temp();
            let file = root.path().join("session-token");
            atomic_write_private_file(&file, b"old-private-value").unwrap();
            *TEST_REPLACE_FAULT.lock().unwrap() = Some(fault);
            assert!(atomic_write_private_file(&file, b"new-private-value").is_err());
            assert_eq!(std::fs::read(&file).unwrap(), b"old-private-value");
            validate_private_file(&file).unwrap();
            assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
        }
    }

    #[test]
    fn sharing_violation_is_recoverable_and_leaves_no_mixed_set() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, install, extract) = update_tree();
        *TEST_REPLACE_FAULT.lock().unwrap() =
            Some(TestReplaceFault::NoMutation(ERROR_SHARING_VIOLATION));
        assert!(
            replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                .is_err()
        );
        assert_old_set(&install);
    }

    #[test]
    fn backup_update_error_immediately_recovers_the_old_set() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, install, extract) = update_tree();
        let backup = install.join("astrid.exe.bak");
        std::fs::write(&backup, b"older-cli").unwrap();
        let _locked_backup = open_locked_regular_file(&backup).unwrap();
        assert!(
            replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                .is_err()
        );
        assert_old_set(&install);
    }

    #[test]
    #[ignore = "invoked only as a subprocess by process_abort_recovers_on_next_run"]
    fn child_aborts_after_first_replacement() {
        let install = PathBuf::from(std::env::var_os("ASTRID_TEST_INSTALL").unwrap());
        let extract = PathBuf::from(std::env::var_os("ASTRID_TEST_EXTRACT").unwrap());
        TEST_ABORT_AFTER_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]);
        panic!("replacement unexpectedly survived the abort hook");
    }

    #[test]
    fn process_abort_recovers_on_next_run() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let (_root, install, extract) = update_tree();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("platform_fs::windows::native_tests::child_aborts_after_first_replacement")
            .arg("--ignored")
            .arg("--nocapture")
            .env("ASTRID_TEST_INSTALL", &install)
            .env("ASTRID_TEST_EXTRACT", &extract)
            .status()
            .unwrap();
        assert!(!status.success());
        recover_executable_transaction(&install).unwrap();
        assert_old_set(&install);
    }

    #[test]
    #[ignore = "invoked only as a subprocess by private-file reader recovery tests"]
    fn child_aborts_inside_private_file_replace() {
        let file = PathBuf::from(std::env::var_os("ASTRID_TEST_PRIVATE_FILE").unwrap());
        TEST_ABORT_INSIDE_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = atomic_write_private_file(&file, b"new-private-value");
        panic!("private-file replacement unexpectedly survived the abort hook");
    }

    #[test]
    fn real_private_file_readers_recover_old_state_after_process_abort() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();

        let profile_path = root.path().join("alice.toml");
        PrincipalProfile::default()
            .save_to_path(&profile_path)
            .unwrap();
        abort_private_write(&profile_path);
        assert_eq!(
            PrincipalProfile::load_from_path(&profile_path).unwrap(),
            PrincipalProfile::default()
        );
        assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());

        let groups_path = root.path().join("groups.toml");
        GroupConfig::builtin_only()
            .save_to_path(&groups_path)
            .unwrap();
        abort_private_write(&groups_path);
        let groups = GroupConfig::load_from_path(&groups_path).unwrap();
        assert!(groups.get(BUILTIN_ADMIN).is_some());
        assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());

        let token_path = root.path().join("system.token");
        let token = SessionToken::generate();
        let expected_token = token.to_hex();
        token.write_to_file(&token_path).unwrap();
        abort_private_write(&token_path);
        assert_eq!(
            SessionToken::read_from_file(&token_path).unwrap().to_hex(),
            expected_token
        );
        assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
    }

    #[test]
    #[ignore = "invoked only as a subprocess by concurrent_reader_rejects_uncommitted_private_write"]
    fn child_pauses_inside_private_file_replace() {
        let file = PathBuf::from(std::env::var_os("ASTRID_TEST_PRIVATE_FILE").unwrap());
        TEST_PAUSE_INSIDE_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = atomic_write_private_file(&file, b"new-private-value");
        panic!("private-file replacement unexpectedly survived the pause hook");
    }

    #[test]
    fn concurrent_reader_rejects_uncommitted_private_write() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let root = private_temp();
        let token_path = root.path().join("system.token");
        let token = SessionToken::generate();
        let expected_token = token.to_hex();
        token.write_to_file(&token_path).unwrap();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("platform_fs::windows::native_tests::child_pauses_inside_private_file_replace")
            .arg("--ignored")
            .arg("--nocapture")
            .env("ASTRID_TEST_PRIVATE_FILE", &token_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.contains("astrid-private-replace-ready") {
                break;
            }
        }
        assert!(root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
        let error = SessionToken::read_from_file(&token_path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            SessionToken::read_from_file(&token_path).unwrap().to_hex(),
            expected_token
        );
        assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
    }

    #[test]
    fn interrupted_replacement_recovers_at_each_mutation_phase() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        for crash_after in [0, 1] {
            let (_root, install, extract) = update_tree();
            *TEST_CRASH_AFTER_REPLACE.lock().unwrap() = Some(crash_after);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = replace_executable_set(
                        &install,
                        &extract,
                        &["astrid.exe", "astrid-daemon.exe"],
                    );
                }))
                .is_err()
            );
            *TEST_CRASH_AFTER_REPLACE.lock().unwrap() = None;
            recover_executable_transaction(&install).unwrap();
            assert_old_set(&install);
            replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"])
                .unwrap();
            assert_eq!(
                std::fs::read(install.join("astrid.exe")).unwrap(),
                b"new-cli"
            );
            assert_eq!(
                std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
                b"new-daemon"
            );
            assert!(!install.join(TRANSACTION_JOURNAL).exists());
        }

        let (_root, install, extract) = update_tree();
        *TEST_CRASH_BEFORE_COMMIT.lock().unwrap() = true;
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = replace_executable_set(
                    &install,
                    &extract,
                    &["astrid.exe", "astrid-daemon.exe"],
                );
            }))
            .is_err()
        );
        *TEST_CRASH_BEFORE_COMMIT.lock().unwrap() = false;
        recover_executable_transaction(&install).unwrap();
        assert_old_set(&install);
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).unwrap();
        assert_eq!(
            std::fs::read(install.join("astrid.exe")).unwrap(),
            b"new-cli"
        );
        assert_eq!(
            std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
            b"new-daemon"
        );
    }
}
