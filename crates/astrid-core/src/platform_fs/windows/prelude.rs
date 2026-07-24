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
pub(super) use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
pub(super) use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
};
pub(super) use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, RtlNtStatusToDosError,
    UNICODE_STRING,
};
pub(super) use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
#[cfg(test)]
pub(super) use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW,
};
pub(super) use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetSecurityDescriptorControl, GetTokenInformation, INHERIT_ONLY_ACE, INHERITED_ACE,
    InitializeSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
pub(super) use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, FileDispositionInfo,
    GetFileInformationByHandle, GetVolumePathNameW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
pub(super) use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
pub(super) use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
pub(super) use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(super) use super::super::{
    AclAccess, AclInheritance, AclPrincipal, AclRule, acl_rules_are_private,
};
