//! Select the authenticated connection identity for one completed read.

pub(super) fn select<T>(uplink: bool, data: bool, binding: Option<T>) -> Option<T> {
    binding.filter(|_| uplink && data)
}
