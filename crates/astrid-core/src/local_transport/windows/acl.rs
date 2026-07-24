//! Bounded parsing for ACE pointers returned by the Windows ACL APIs.

use std::ffi::c_void;
use std::io;
use std::marker::PhantomData;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::ptr::NonNull;

use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, IsValidAcl, IsValidSid,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SID_REVISION};

const SID_FIXED_HEADER_SIZE: usize = 8;
const SID_SUBAUTHORITY_SIZE: usize = size_of::<u32>();

/// # Safety
///
/// `descriptor` must point to a live Windows security descriptor for the
/// duration of this call.
pub(super) unsafe fn validate_descriptor_control(
    descriptor: PSECURITY_DESCRIPTOR,
) -> io::Result<()> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor is the live allocation returned by
    // GetSecurityInfo and both outputs have the documented types.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(super::last_error(
            "failed to inspect named-pipe security descriptor control",
        ));
    }
    let required = SE_DACL_PRESENT | SE_DACL_PROTECTED;
    let rejected = SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
    if control & required == required && control & rejected == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "named-pipe DACL control is not explicit and protected (control=0x{control:04x})"
            ),
        ))
    }
}

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
    Unsupported,
}

#[derive(Debug)]
pub(super) struct ValidatedAcl<'owner> {
    pointer: NonNull<ACL>,
    ace_count: u32,
    bytes_in_use: usize,
    description: String,
    _owner: PhantomData<&'owner c_void>,
}

impl<'owner> ValidatedAcl<'owner> {
    /// Validates and borrows a Windows ACL owned by `owner`.
    ///
    /// # Safety
    ///
    /// `pointer` must point to a complete ACL allocation described by its
    /// header which remains readable and unmodified for the lifetime of
    /// `owner`.
    pub(super) unsafe fn from_raw<T: ?Sized>(
        pointer: *mut ACL,
        _owner: &'owner T,
        description: &str,
    ) -> io::Result<Self> {
        let pointer =
            NonNull::new(pointer).ok_or_else(|| malformed(description, "the DACL is null"))?;
        // SAFETY: the caller guarantees a live ACL allocation. IsValidAcl
        // validates its header, revision, ACE count, and declared byte span.
        if unsafe { IsValidAcl(pointer.as_ptr()) } == 0 {
            return Err(malformed(description, "the DACL structure is invalid"));
        }
        // SAFETY: IsValidAcl accepted the complete ACL header. Copying avoids
        // creating a borrowed reference to foreign storage.
        let header = unsafe { pointer.as_ptr().read_unaligned() };

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

        let bytes_in_use = usize::try_from(info.AclBytesInUse)
            .map_err(|_| malformed(description, "the DACL byte length overflowed"))?;
        if bytes_in_use > usize::from(header.AclSize) {
            return Err(malformed(
                description,
                "the DACL bytes in use exceed its declared size",
            ));
        }
        if info.AceCount != u32::from(header.AceCount) {
            return Err(malformed(
                description,
                "the DACL ACE count is inconsistent with its header",
            ));
        }
        let ace_count = usize::try_from(info.AceCount)
            .map_err(|_| malformed(description, "the DACL ACE count overflowed"))?;
        let ace_bytes = bytes_in_use
            .checked_sub(size_of::<ACL>())
            .ok_or_else(|| malformed(description, "the DACL is smaller than its header"))?;
        let maximum_aces = ace_bytes
            .checked_div(size_of::<ACE_HEADER>())
            .ok_or_else(|| malformed(description, "the ACE header size is zero"))?;
        if ace_count > maximum_aces {
            return Err(malformed(
                description,
                "the DACL ACE count exceeds its validated byte span",
            ));
        }

        Ok(Self {
            pointer,
            ace_count: info.AceCount,
            bytes_in_use,
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
        // SAFETY: successful GetAce initializes its output pointer.
        let raw_ace = unsafe { raw_ace.assume_init() };
        let raw_ace = NonNull::new(raw_ace)
            .ok_or_else(|| malformed(&self.description, "GetAce returned a null pointer"))?;
        let remaining = self.bytes_remaining_from(raw_ace)?;

        // SAFETY: `bytes_remaining_from` proves the returned pointer lies
        // within the IsValidAcl-validated byte span, which remains live
        // through `self`.
        unsafe { parse_ace(raw_ace, remaining, &self.description) }
    }

    fn bytes_remaining_from(&self, raw_ace: NonNull<c_void>) -> io::Result<usize> {
        let allocation_start = self.pointer.as_ptr().cast::<u8>() as usize;
        let entry_start = raw_ace.as_ptr().cast::<u8>() as usize;
        let allocation_end = allocation_start
            .checked_add(self.bytes_in_use)
            .ok_or_else(|| malformed(&self.description, "the DACL byte span overflowed"))?;
        let first_entry = allocation_start
            .checked_add(size_of::<ACL>())
            .ok_or_else(|| malformed(&self.description, "the DACL header span overflowed"))?;
        if entry_start < first_entry || entry_start >= allocation_end {
            return Err(malformed(
                &self.description,
                "GetAce returned a pointer outside the validated DACL",
            ));
        }
        allocation_end
            .checked_sub(entry_start)
            .ok_or_else(|| malformed(&self.description, "the ACE byte span underflowed"))
    }
}

/// Copies the fixed fields of one ACE and bounds its variable-length SID.
///
/// # Safety
///
/// `raw_ace` must point to `available` readable bytes which remain readable
/// for `'acl`.
unsafe fn parse_ace<'acl>(
    raw_ace: NonNull<c_void>,
    available: usize,
    description: &str,
) -> io::Result<ValidatedAce<'acl>> {
    if available < size_of::<ACE_HEADER>() {
        return Err(malformed(description, "an ACE has a truncated header"));
    }
    // SAFETY: the caller guarantees `available` readable bytes and the check
    // above covers ACE_HEADER. read_unaligned creates no borrowed reference.
    let header = unsafe { raw_ace.cast::<ACE_HEADER>().as_ptr().read_unaligned() };
    let ace_size = usize::from(header.AceSize);
    if ace_size < size_of::<ACE_HEADER>() {
        return Err(malformed(description, "an ACE is smaller than ACE_HEADER"));
    }
    if ace_size > available {
        return Err(malformed(
            description,
            "an ACE extends beyond the validated DACL byte span",
        ));
    }
    if !ace_size.is_multiple_of(size_of::<u32>()) {
        return Err(malformed(description, "an ACE is not DWORD aligned"));
    }
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Ok(ValidatedAce::Unsupported);
    }

    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_size < size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(malformed(
            description,
            "an access-allowed ACE lacks its fixed fields",
        ));
    }
    let sid_capacity = ace_size
        .checked_sub(sid_offset)
        .ok_or_else(|| malformed(description, "an access-allowed ACE SID offset overflowed"))?;
    if sid_capacity < SID_FIXED_HEADER_SIZE {
        return Err(malformed(
            description,
            "an access-allowed ACE contains a truncated SID header",
        ));
    }

    let bytes = raw_ace.as_ptr().cast::<u8>();
    // SAFETY: the fixed ACE-size validation includes the Mask field.
    let mask = unsafe {
        bytes
            .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
            .cast::<u32>()
            .read_unaligned()
    };
    // SAFETY: `sid_offset` and the complete fixed SID header lie within the
    // validated ACE span.
    let sid: PSID = unsafe { bytes.add(sid_offset).cast() };
    // SAFETY: the capacity check proves the fixed SID header is readable.
    // Copy it before asking Windows to follow SubAuthorityCount.
    let sid_header = unsafe {
        bytes
            .add(sid_offset)
            .cast::<[u8; SID_FIXED_HEADER_SIZE]>()
            .read_unaligned()
    };
    let expected_sid_length = expected_sid_length(sid_header, sid_capacity, description)?;

    // SAFETY: the copied header proves every claimed subauthority lies within
    // the validated ACE byte span.
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
        flags: u32::from(header.AceFlags),
        mask,
        sid: ValidatedSid {
            pointer: sid,
            _acl: PhantomData,
        },
    })
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
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_OBJECT_ACE_TYPE;

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
        // SAFETY: null is rejected before it is dereferenced.
        let result = unsafe { ValidatedAcl::from_raw(std::ptr::null_mut(), &owner, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_declared_ace_shorter_than_header() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 2);
        // SAFETY: the backing buffer contains all 64 advertised bytes.
        let result = unsafe { parse_ace(ace.pointer(), ace.0.len(), "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_ace_extending_beyond_validated_acl_span() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 64);
        // SAFETY: the backing buffer contains the 16 bytes supplied as the
        // parser bound; the declared ACE size exceeds that bound.
        let result = unsafe { parse_ace(ace.pointer(), 16, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_access_allowed_ace_without_fixed_fields() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 8);
        // SAFETY: the backing buffer contains the complete declared span.
        let result = unsafe { parse_ace(ace.pointer(), 8, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_access_allowed_ace_with_truncated_sid_header() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 12);
        // SAFETY: the backing buffer contains the complete declared span.
        let result = unsafe { parse_ace(ace.pointer(), 12, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unsupported_sid_revision_before_windows_validation() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 16);
        ace.0[8] = 2;
        // SAFETY: the backing buffer contains the complete declared span.
        let result = unsafe { parse_ace(ace.pointer(), 16, "test") };
        assert!(result.is_err());
    }

    #[test]
    fn rejects_sid_subauthorities_beyond_declared_ace_before_windows_validation() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_ACE_TYPE, 16);
        ace.0[8] = 1;
        ace.0[9] = 2;
        // SAFETY: the backing buffer contains the complete declared span.
        let result = unsafe { parse_ace(ace.pointer(), 16, "test") };
        assert_eq!(
            result.unwrap_err().to_string(),
            "malformed Windows ACL for test: an access-allowed ACE contains \
             subauthorities beyond its declared size"
        );
    }

    #[test]
    fn reports_unsupported_ace_without_typed_body_access() {
        let mut ace = AlignedAce::with_header(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 4);
        // SAFETY: the backing buffer contains the complete declared header.
        let result = unsafe { parse_ace(ace.pointer(), 4, "test") }.unwrap();
        assert!(matches!(result, ValidatedAce::Unsupported));
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
