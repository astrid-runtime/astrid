//! Windows SID, ownership, and DACL construction and validation.

#[path = "acl/ace.rs"]
mod ace;

#[cfg(test)]
use super::path::wide_path;
use super::path::{OwnedHandle, wide_text};
use super::prelude::*;
use ace::{ValidatedAce, ValidatedAcl};

pub(super) const DANGEROUS_PARENT_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
pub(super) const DANGEROUS_EXISTING_PARENT_ACCESS: u32 =
    FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
pub(super) const DANGEROUS_FILE_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

pub(super) struct LocalAllocation(pub(super) *mut c_void);

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

/// Owns the exact protected DACL and absolute descriptor passed at creation.
///
/// The ACL allocation must outlive `NtCreateFile`, because the absolute
/// descriptor stores a pointer to it rather than embedding the ACL bytes.
pub(super) struct PrivateSecurityDescriptor {
    _acl: LocalAllocation,
    descriptor: SECURITY_DESCRIPTOR,
}

impl PrivateSecurityDescriptor {
    pub(super) fn new(is_directory: bool) -> io::Result<Self> {
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
        // SAFETY: all three entries point at live SID buffers and the ACL
        // out-pointer is valid. SetEntriesInAclW copies the SID bytes into the
        // allocation returned through `acl`.
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
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: `descriptor` is an aligned, writable descriptor buffer.
        if unsafe {
            InitializeSecurityDescriptor((&raw mut descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `descriptor` is initialized and `acl` is a live ACL
        // allocation retained by the returned value.
        if unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast(), 1, acl, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `descriptor` is initialized and both masks contain only the
        // documented DACL protection control bit.
        if unsafe {
            SetSecurityDescriptorControl(
                (&raw mut descriptor).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            _acl: allocation,
            descriptor,
        })
    }

    pub(super) fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        &raw const self.descriptor
    }
}

pub(super) struct CurrentUserSid {
    _token: OwnedHandle,
    token_info: Vec<usize>,
}

impl CurrentUserSid {
    pub(super) fn get() -> io::Result<Self> {
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

    pub(super) fn as_ptr(&self) -> PSID {
        let token_user = self.token_info.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: `token_info` was filled by `GetTokenInformation(TokenUser)`,
        // is aligned as `usize`, and lives for the returned SID pointer.
        unsafe { (*token_user).User.Sid }
    }
}

#[repr(align(4))]
pub(super) struct SidBytes([u8; SECURITY_MAX_SID_SIZE as usize]);

pub(super) struct WellKnownSid {
    bytes: SidBytes,
}

impl WellKnownSid {
    pub(super) fn get(kind: i32) -> io::Result<Self> {
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

    pub(super) fn as_ptr(&self) -> PSID {
        self.bytes.0.as_ptr().cast_mut().cast()
    }
}

pub(super) struct RequiredSids {
    pub(super) current_user: CurrentUserSid,
    pub(super) local_system: WellKnownSid,
    pub(super) administrators: WellKnownSid,
    pub(super) trusted_installer: LocalAllocation,
}

impl RequiredSids {
    pub(super) fn get() -> io::Result<Self> {
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

    pub(super) fn classify(&self, sid: PSID) -> AclPrincipal {
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

    pub(super) fn is_trusted(&self, sid: PSID) -> bool {
        self.classify(sid) != AclPrincipal::Other
            // SAFETY: the descriptor SID was validated by `classify`; the
            // TrustedInstaller SID is a live converted SID allocation.
            || (!sid.is_null()
                && unsafe { IsValidSid(sid) } != 0
                && unsafe { EqualSid(sid, self.trusted_installer.0.cast()) } != 0)
    }
}

#[cfg(test)]
pub(super) fn apply_private_acl(path: &Path, is_directory: bool) -> io::Result<()> {
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

pub(super) fn apply_private_acl_to_handle(handle: HANDLE, is_directory: bool) -> io::Result<()> {
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
    // SAFETY: all three entries point at live SID buffers and the ACL
    // out-pointer is valid. A successful allocation is owned below.
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
    // SAFETY: `handle` is a live file handle with WRITE_DAC and the ACL
    // allocation remains live for the call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
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

pub(super) fn explicit_access(sid: PSID, trustee_type: i32, inheritance: u32) -> EXPLICIT_ACCESS_W {
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

#[cfg(test)]
pub(super) fn validate_private_acl(path: &Path, is_directory: bool) -> io::Result<()> {
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
    let description = path.display().to_string();
    let result = if dacl.is_null() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private Windows path has a null DACL: {description}"),
        ))
    } else {
        // SAFETY: GetNamedSecurityInfoW returned `dacl` inside the descriptor
        // allocation retained by `allocation`.
        unsafe { ValidatedAcl::from_raw(dacl, &allocation, &description) }.and_then(|acl| {
            validate_private_acl_parts(
                &required,
                owner,
                &acl,
                descriptor,
                is_directory,
                &description,
            )
        })
    };
    drop(allocation);
    result
}

pub(super) fn validate_private_acl_handle(
    handle: HANDLE,
    is_directory: bool,
    description: &str,
) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is live and all output pointers are valid.
    let status = unsafe {
        GetSecurityInfo(
            handle,
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
    let result = if dacl.is_null() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private Windows path has a null DACL: {description}"),
        ))
    } else {
        // SAFETY: GetSecurityInfo returned `dacl` inside the descriptor
        // allocation retained by `allocation`.
        unsafe { ValidatedAcl::from_raw(dacl, &allocation, description) }.and_then(|acl| {
            validate_private_acl_parts(
                &required,
                owner,
                &acl,
                descriptor,
                is_directory,
                description,
            )
        })
    };
    drop(allocation);
    result
}

fn validate_private_acl_parts(
    required: &RequiredSids,
    owner: PSID,
    acl: &ValidatedAcl<'_>,
    descriptor: PSECURITY_DESCRIPTOR,
    is_directory: bool,
    description: &str,
) -> io::Result<()> {
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

    let mut rules = Vec::with_capacity(usize::try_from(acl.ace_count()).unwrap_or_default());
    for index in 0..acl.ace_count() {
        rules.push(private_acl_rule(required, acl.ace(index)?, is_directory));
    }

    if !acl_rules_are_private(is_directory, dacl_is_protected, owner_is_allowed, &rules) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private Windows path ACL is not restricted to the current user and required system principals: {description}"
            ),
        ));
    }
    Ok(())
}

fn private_acl_rule(required: &RequiredSids, ace: ValidatedAce<'_>, is_directory: bool) -> AclRule {
    let invalid = || AclRule {
        principal: AclPrincipal::Other,
        access: AclAccess::Other,
        inheritance: AclInheritance::InheritedOrOther,
    };
    let ValidatedAce::Allow { flags, mask, sid } = ace else {
        return invalid();
    };
    let expected_flags = if is_directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let inheritance = match flags {
        flags if flags != expected_flags => AclInheritance::InheritedOrOther,
        0 => AclInheritance::None,
        flags if flags == OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE => AclInheritance::Children,
        _ => AclInheritance::InheritedOrOther,
    };
    AclRule {
        principal: required.classify(sid.as_ptr()),
        access: if mask == FILE_ALL_ACCESS {
            AclAccess::AllowFullControl
        } else {
            AclAccess::Other
        },
        inheritance,
    }
}

pub(super) fn validate_trusted_parent_acl_handle(
    handle: HANDLE,
    description: &str,
) -> io::Result<()> {
    validate_trusted_parent_acl_handle_with_mask(
        handle,
        DANGEROUS_EXISTING_PARENT_ACCESS,
        description,
    )
}

pub(super) fn validate_trusted_parent_acl_for_create_handle(
    handle: HANDLE,
    description: &str,
) -> io::Result<()> {
    validate_trusted_parent_acl_handle_with_mask(handle, DANGEROUS_PARENT_ACCESS, description)
}

fn validate_trusted_parent_acl_handle_with_mask(
    handle: HANDLE,
    dangerous_access: u32,
    description: &str,
) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is live with READ_CONTROL and all output pointers are
    // valid for the duration of the call.
    let status = unsafe {
        GetSecurityInfo(
            handle,
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
    let result = if dacl.is_null() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trusted Windows parent has a null DACL: {description}"),
        ))
    } else {
        // SAFETY: GetSecurityInfo returned `dacl` inside the descriptor
        // allocation retained by `allocation`.
        unsafe { ValidatedAcl::from_raw(dacl, &allocation, description) }.and_then(|acl| {
            validate_trusted_parent_acl_parts(&required, owner, &acl, dangerous_access, description)
        })
    };
    drop(allocation);
    result
}

fn validate_trusted_parent_acl_parts(
    required: &RequiredSids,
    owner: PSID,
    acl: &ValidatedAcl<'_>,
    dangerous_access: u32,
    description: &str,
) -> io::Result<()> {
    if !required.is_trusted(owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trusted Windows parent has an untrusted owner: {description}"),
        ));
    }

    for index in 0..acl.ace_count() {
        let (flags, mask, sid) = match acl.ace(index)? {
            ValidatedAce::Allow { flags, mask, sid } => (flags, mask, sid),
            ValidatedAce::Deny { .. } => continue,
            ValidatedAce::Unsupported { ace_type, .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows parent has unsupported ACE type {ace_type}: {description}"
                    ),
                ));
            },
        };
        let applies_to_parent = flags & INHERIT_ONLY_ACE == 0;
        let applies_to_file_child = flags & OBJECT_INHERIT_ACE != 0;
        let applies_to_directory_child = flags & CONTAINER_INHERIT_ACE != 0;
        let unsafe_for_untrusted = (applies_to_parent && mask & dangerous_access != 0)
            || (applies_to_file_child && mask & DANGEROUS_FILE_ACCESS != 0)
            || (applies_to_directory_child && mask & DANGEROUS_PARENT_ACCESS != 0);
        if !required.is_trusted(sid.as_ptr()) && unsafe_for_untrusted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "trusted Windows parent grants write or delete authority to an untrusted principal: {description}"
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_trusted_file_acl_handle(
    handle: HANDLE,
    description: &str,
) -> io::Result<()> {
    let required = RequiredSids::get()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is live with READ_CONTROL and all outputs are valid.
    let status = unsafe {
        GetSecurityInfo(
            handle,
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
    let result = if dacl.is_null() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trusted Windows file has an unsafe owner or null DACL: {description}"),
        ))
    } else {
        // SAFETY: GetSecurityInfo returned `dacl` inside the descriptor
        // allocation retained by `allocation`.
        unsafe { ValidatedAcl::from_raw(dacl, &allocation, description) }
            .and_then(|acl| validate_trusted_file_acl_parts(&required, owner, &acl, description))
    };
    drop(allocation);
    result
}

fn validate_trusted_file_acl_parts(
    required: &RequiredSids,
    owner: PSID,
    acl: &ValidatedAcl<'_>,
    description: &str,
) -> io::Result<()> {
    if !required.is_trusted(owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trusted Windows file has an unsafe owner or null DACL: {description}"),
        ));
    }
    for index in 0..acl.ace_count() {
        let ace = acl.ace(index)?;
        let flags = match ace {
            ValidatedAce::Allow { flags, .. }
            | ValidatedAce::Deny { flags }
            | ValidatedAce::Unsupported { flags, .. } => flags,
        };
        if flags & !(INHERITED_ACE) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("trusted Windows file has unexpected ACE flags: {description}"),
            ));
        }
        match ace {
            ValidatedAce::Deny { .. } => {},
            ValidatedAce::Unsupported { ace_type, .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows file has unsupported ACE type {ace_type}: {description}"
                    ),
                ));
            },
            ValidatedAce::Allow { mask, sid, .. } => {
                if !required.is_trusted(sid.as_ptr()) && mask & DANGEROUS_FILE_ACCESS != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "trusted Windows file is writable by an untrusted principal: {description}"
                        ),
                    ));
                }
            },
        }
    }
    Ok(())
}
