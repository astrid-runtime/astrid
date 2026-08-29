//! Ring-3 copy validation over the current domain's audited mappings.

use super::abi::MAX_BUFFER_BYTES;

pub(crate) fn finish_copy(buffer: &mut [u8], scratch: &[u8], copied: bool, _to_user: bool) -> bool {
    if copied {
        buffer.copy_from_slice(scratch);
    }
    copied
}

pub(super) fn copy_current_user(
    address: u64,
    buffer: &mut [u8; MAX_BUFFER_BYTES],
    to_user: bool,
) -> bool {
    crate::domains::copy_current_user(address, buffer, to_user)
}
