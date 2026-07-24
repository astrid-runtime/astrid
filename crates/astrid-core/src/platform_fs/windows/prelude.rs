//! Narrow internal prelude for the Windows filesystem implementation.

pub(super) use std::ffi::{OsStr, OsString, c_void};
pub(super) use std::fs::File;
pub(super) use std::io::{self, Read, Seek, Write};
pub(super) use std::mem::size_of;
pub(super) use std::os::windows::ffi::{OsStrExt, OsStringExt};
pub(super) use std::os::windows::fs::MetadataExt;
pub(super) use std::os::windows::io::{AsRawHandle, FromRawHandle};
pub(super) use std::path::{Component, Path, PathBuf, Prefix};
pub(super) use std::ptr::{null, null_mut};

pub(super) use directories::BaseDirs;
pub(super) use serde::{Deserialize, Serialize};
pub(super) use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, ERROR_UNABLE_TO_MOVE_REPLACEMENT,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, ERROR_UNABLE_TO_REMOVE_REPLACED, GENERIC_ALL, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
pub(super) use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
pub(super) use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation, INHERIT_ONLY_ACE,
    INHERITED_ACE, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
pub(super) use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, GetFileInformationByHandle, GetVolumePathNameW, MoveFileExW, OPEN_EXISTING,
    READ_CONTROL, ReplaceFileW, WRITE_DAC, WRITE_OWNER,
};
pub(super) use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
};
pub(super) use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(super) use super::super::{
    AclAccess, AclInheritance, AclPrincipal, AclRule, acl_rules_are_private,
};
