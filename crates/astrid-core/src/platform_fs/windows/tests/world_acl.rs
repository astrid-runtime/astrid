//! Test fixture for appending one untrusted ACE to a real private DACL.

use std::path::Path;

use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_WELL_KNOWN_GROUP,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
};

use super::super::acl::{LocalAllocation, WellKnownSid, explicit_access};
use super::super::path::wide_path;
use super::super::prelude::*;

pub(super) fn set_world_entry(path: &Path, mask: u32, protected: bool) {
    set_world_entry_with_flags(path, mask, protected, 0);
}

pub(super) fn set_world_entry_with_flags(
    path: &Path,
    mask: u32,
    protected: bool,
    inheritance: u32,
) {
    let world = WellKnownSid::get(WinWorldSid).unwrap();
    let mut entries = [explicit_access(
        world.as_ptr(),
        TRUSTEE_IS_WELL_KNOWN_GROUP,
        inheritance,
    )];
    entries[0].grfAccessPermissions = mask;
    let mut existing_dacl: *mut ACL = null_mut();
    let mut existing_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut wide_for_get = wide_path(path).unwrap();
    // SAFETY: the path and out pointers are valid; only the DACL is read.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_for_get.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &raw mut existing_dacl,
            null_mut(),
            &raw mut existing_descriptor,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    let existing_allocation = LocalAllocation(existing_descriptor);
    assert!(!existing_dacl.is_null(), "fixture DACL must already exist");
    let mut acl: *mut ACL = null_mut();
    // SAFETY: the world entry and existing DACL are live and the out pointer
    // is valid. Appending preserves every trusted reader in the private ACL.
    let status = unsafe { SetEntriesInAclW(1, entries.as_mut_ptr(), existing_dacl, &raw mut acl) };
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
    drop(existing_allocation);
    assert_eq!(status, ERROR_SUCCESS);
}
