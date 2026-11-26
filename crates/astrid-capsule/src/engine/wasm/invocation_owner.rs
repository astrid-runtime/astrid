//! Admission for principal runtimes whose owner was reserved at load.

use astrid_core::PrincipalUid;

mod admission;

/// Unstamped runtimes use invocation-scoped authority. A stamped runtime
/// requires an actual observation of its immutable owner.
pub(super) fn accepts(expected: Option<PrincipalUid>, observed: Option<PrincipalUid>) -> bool {
    admission::accepts(
        expected.map(|uid| *uid.as_bytes()),
        observed.map(|uid| *uid.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamped_runtime_requires_its_own_registered_uid() {
        let owner = PrincipalUid::from_bytes([1; 32]);
        let peer = PrincipalUid::from_bytes([2; 32]);
        assert!(accepts(Some(owner), Some(owner)));
        assert!(!accepts(Some(owner), Some(peer)));
        assert!(!accepts(Some(owner), None));
        assert!(accepts(None, None));
        assert!(accepts(None, Some(peer)));
    }
}
