//! Bounded parsing for ACE pointers returned by the Windows ACL APIs.

use std::ffi::c_void;
use std::io;
use std::marker::PhantomData;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::ptr::NonNull;

use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce,
    GetAclInformation, GetLengthSid, IsValidAcl, IsValidSid, PSID,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SID_REVISION,
};

const SID_FIXED_HEADER_SIZE: usize = 8;
const SID_SUBAUTHORITY_SIZE: usize = size_of::<u32>();

#[derive(Clone, Copy, Debug)]
pub(super) struct ValidatedSid<'acl> {
    pointer: PSID,
    _acl: PhantomData<&'acl ACL>,
}

impl ValidatedSid<'_> {
    pub(super) fn as_ptr(self) -> PSID {
        self.pointer
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ValidatedAce<'acl> {
    Allow {
        flags: u32,
        mask: u32,
        sid: ValidatedSid<'acl>,
    },
    Deny {
        flags: u32,
    },
    Unsupported {
        ace_type: u8,
        flags: u32,
    },
}

#[derive(Debug)]
pub(super) struct ValidatedAcl<'owner> {
    pointer: NonNull<ACL>,
    ace_count: u32,
    description: String,
    _owner: PhantomData<&'owner c_void>,
}

impl<'owner> ValidatedAcl<'owner> {
    /// Validates and borrows a Windows ACL owned by `owner`.
    ///
    /// # Safety
    ///
    /// When non-null, `pointer` must point to a complete ACL allocation
    /// described by its header which remains readable and unmodified for the
    /// lifetime of `owner`.
    pub(super) unsafe fn from_raw<T: ?Sized>(
        pointer: *mut ACL,
        _owner: &'owner T,
        description: &str,
    ) -> io::Result<Self> {
        let pointer = NonNull::new(pointer)
            .ok_or_else(|| malformed(description, "the DACL pointer is null"))?;
        // SAFETY: the caller guarantees a live ACL allocation. IsValidAcl
        // validates its header, revision, ACE count, and declared byte span.
        if unsafe { IsValidAcl(pointer.as_ptr()) } == 0 {
            return Err(malformed(description, "the DACL structure is invalid"));
        }

        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: the ACL passed IsValidAcl and the output buffer has the exact
        // documented type and size.
        if unsafe {
            GetAclInformation(
                pointer.as_ptr(),
                (&raw mut info).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION fits in u32"),
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            pointer,
            ace_count: info.AceCount,
            description: description.to_owned(),
            _owner: PhantomData,
        })
    }

    pub(super) fn ace_count(&self) -> u32 {
        self.ace_count
    }

    pub(super) fn ace(&self, index: u32) -> io::Result<ValidatedAce<'_>> {
        if index >= self.ace_count {
            return Err(malformed(
                &self.description,
                "the ACE index exceeds the validated ACL count",
            ));
        }

        let mut raw_ace = MaybeUninit::<*mut c_void>::uninit();
        // SAFETY: the ACL remains live through `self`, the index is in range,
        // and `raw_ace` is a writable out-parameter.
        if unsafe { GetAce(self.pointer.as_ptr(), index, raw_ace.as_mut_ptr()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful GetAce initializes its output pointer.
        let raw_ace = unsafe { raw_ace.assume_init() };
        let raw_ace = NonNull::new(raw_ace)
            .ok_or_else(|| malformed(&self.description, "GetAce returned a null pointer"))?;

        // SAFETY: GetAce returned this pointer from an IsValidAcl-validated ACL
        // which remains live through `self`.
        unsafe { parse_ace(raw_ace, &self.description) }
    }
}

/// Copies the fixed fields of one ACE and bounds a variable-length SID.
///
/// # Safety
///
/// `raw_ace` must point to at least one readable `ACE_HEADER`, and the complete
/// byte span declared by `ACE_HEADER::AceSize` must remain readable for `'acl`.
unsafe fn parse_ace<'acl>(
    raw_ace: NonNull<c_void>,
    description: &str,
) -> io::Result<ValidatedAce<'acl>> {
    // SAFETY: guaranteed by the caller; read_unaligned avoids creating a
    // reference whose alignment or lifetime outlives this copy.
    let header = unsafe { raw_ace.cast::<ACE_HEADER>().as_ptr().read_unaligned() };
    let ace_size = usize::from(header.AceSize);
    if ace_size < size_of::<ACE_HEADER>() {
        return Err(malformed(description, "an ACE is smaller than ACE_HEADER"));
    }
    if ace_size
        .checked_rem(size_of::<u32>())
        .is_some_and(|remainder| remainder != 0)
    {
        return Err(malformed(description, "an ACE is not DWORD aligned"));
    }

    let flags = u32::from(header.AceFlags);
    match u32::from(header.AceType) {
        ACCESS_DENIED_ACE_TYPE => Ok(ValidatedAce::Deny { flags }),
        ace_type if ace_type != ACCESS_ALLOWED_ACE_TYPE => Ok(ValidatedAce::Unsupported {
            ace_type: header.AceType,
            flags,
        }),
        _ => {
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if ace_size < size_of::<ACCESS_ALLOWED_ACE>() {
                return Err(malformed(
                    description,
                    "an access-allowed ACE lacks its fixed fields",
                ));
            }
            let sid_capacity = ace_size.checked_sub(sid_offset).ok_or_else(|| {
                malformed(description, "an access-allowed ACE SID offset overflowed")
            })?;
            if sid_capacity < SID_FIXED_HEADER_SIZE {
                return Err(malformed(
                    description,
                    "an access-allowed ACE contains a truncated SID header",
                ));
            }

            let bytes = raw_ace.as_ptr().cast::<u8>();
            // SAFETY: the validated fixed ACE size includes the Mask field.
            let mask = unsafe {
                bytes
                    .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                    .cast::<u32>()
                    .read_unaligned()
            };
            // SAFETY: `sid_offset` and the complete fixed SID header are
            // within the declared ACE byte span.
            let sid: PSID = unsafe { bytes.add(sid_offset).cast() };
            // SAFETY: the capacity check above proves the fixed SID header is
            // readable. Copy it before asking Windows to inspect the SID:
            // IsValidSid and GetLengthSid may otherwise follow an untrusted
            // SubAuthorityCount beyond the ACE's declared byte span.
            let sid_header = unsafe {
                bytes
                    .add(sid_offset)
                    .cast::<[u8; SID_FIXED_HEADER_SIZE]>()
                    .read_unaligned()
            };
            let expected_sid_length = expected_sid_length(sid_header, sid_capacity, description)?;

            // SAFETY: the fixed SID header was copied and its claimed
            // subauthorities all fit within the declared ACE byte span.
            if unsafe { IsValidSid(sid) } == 0 {
                return Err(malformed(
                    description,
                    "an access-allowed ACE contains an invalid SID",
                ));
            }
            // SAFETY: IsValidSid accepted the fully bounded SID.
            let sid_length = usize::try_from(unsafe { GetLengthSid(sid) })
                .map_err(|_| malformed(description, "the ACE SID length overflowed"))?;
            if sid_length != expected_sid_length || sid_length > sid_capacity {
                return Err(malformed(
                    description,
                    "an access-allowed ACE contains an inconsistent SID length",
                ));
            }

            Ok(ValidatedAce::Allow {
                flags,
                mask,
                sid: ValidatedSid {
                    pointer: sid,
                    _acl: PhantomData,
                },
            })
        },
    }
}

fn expected_sid_length(
    fixed_header: [u8; SID_FIXED_HEADER_SIZE],
    sid_capacity: usize,
    description: &str,
) -> io::Result<usize> {
    if u32::from(fixed_header[0]) != SID_REVISION {
        return Err(malformed(
            description,
            "an access-allowed ACE contains an unsupported SID revision",
        ));
    }

    let subauthority_bytes = usize::from(fixed_header[1])
        .checked_mul(SID_SUBAUTHORITY_SIZE)
        .ok_or_else(|| malformed(description, "the ACE SID length overflowed"))?;
    let expected_length = SID_FIXED_HEADER_SIZE
        .checked_add(subauthority_bytes)
        .ok_or_else(|| malformed(description, "the ACE SID length overflowed"))?;
    if expected_length > sid_capacity {
        return Err(malformed(
            description,
            "an access-allowed ACE contains subauthorities beyond its declared size",
        ));
    }

    Ok(expected_length)
}

fn malformed(description: &str, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("malformed Windows ACL for {description}: {reason}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::ACL_REVISION;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    };

    #[repr(align(4))]
    struct AlignedAce([u8; 64]);

    impl AlignedAce {
        fn with_header(ace_type: u32, ace_size: u16) -> Self {
            let mut result = Self([0; 64]);
            result.0[0] = u8::try_from(ace_type).unwrap();
            result.0[2..4].copy_from_slice(&ace_size.to_le_bytes());
            result
        }

        fn pointer(&mut self) -> NonNull<c_void> {
            NonNull::new(self.0.as_mut_ptr().cast()).unwrap()
        }
    }

    #[repr(align(4))]
    struct AlignedAcl([u8; 64]);

    impl AlignedAcl {
        fn empty() -> Self {
            let mut result = Self([0; 64]);
            result.0[0] = u8::try_from(ACL_REVISION).unwrap();
            result.0[2..4].copy_from_slice(&u16::try_from(size_of::<ACL>()).unwrap().to_le_bytes());
            result
        }

        fn pointer(&mut self) -> *mut ACL {
            self.0.as_mut_ptr().cast()
        }
    }

    #[test]
    fn rejects_null_acl_pointer() {
        let owner = ();
        // SAFETY: null is explicitly accepted for validation and rejected
        // before any dereference.
        let result = unsafe { ValidatedAcl::from_raw(std::ptr::null_mut(), &owner, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_declared_ace_shorter_than_header() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 2);
        // SAFETY: the backing buffer contains a readable header and exceeds its
        // declared byte span.
        let result = unsafe { parse_ace(ace.pointer(), "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_access_allowed_ace_without_fixed_fields() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 8);
        // SAFETY: the backing buffer contains the complete declared byte span.
        let result = unsafe { parse_ace(ace.pointer(), "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_access_allowed_ace_with_truncated_sid_header() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 12);
        // SAFETY: the backing buffer contains the complete declared byte span.
        let result = unsafe { parse_ace(ace.pointer(), "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_sid_subauthorities_beyond_declared_ace_before_windows_validation() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 16);
        ace.0[8] = 1;
        ace.0[9] = 2;
        // SAFETY: the backing buffer contains the complete declared byte span.
        let result = unsafe { parse_ace(ace.pointer(), "test") };
        assert_eq!(
            result.unwrap_err().to_string(),
            "malformed Windows ACL for test: an access-allowed ACE contains \
             subauthorities beyond its declared size"
        );
    }

    #[test]
    fn reports_unsupported_aces_without_typed_body_access() {
        for ace_type in [
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ] {
            let mut ace = AlignedAce::with_header(ace_type, 4);
            // SAFETY: the backing buffer contains the complete declared header.
            let result = unsafe { parse_ace(ace.pointer(), "test") }.unwrap();
            assert!(matches!(result, ValidatedAce::Unsupported { .. }));
        }
    }

    #[test]
    fn validates_synthetic_empty_acl() {
        let mut buffer = AlignedAcl::empty();
        let pointer = buffer.pointer();
        // SAFETY: `pointer` refers to the ACL header owned by `buffer`.
        let acl = unsafe { ValidatedAcl::from_raw(pointer, &buffer, "test") }.unwrap();
        assert_eq!(acl.ace_count(), 0);
    }
}
