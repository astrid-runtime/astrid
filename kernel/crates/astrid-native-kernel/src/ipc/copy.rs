//! Ring-3 copy validation over the current domain's audited mappings.

use super::abi::MAX_BUFFER_BYTES;

pub(super) fn copy_current_user(
    address: u64,
    buffer: &mut [u8; MAX_BUFFER_BYTES],
    to_user: bool,
) -> bool {
    crate::domains::copy_current_user(address, buffer, to_user)
}
