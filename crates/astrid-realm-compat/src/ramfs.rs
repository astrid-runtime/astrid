//! Owner-bound ephemeral namespace. Not a host directory and not a volume.
//!
//! The namespace is zero-state: isolation is the immutable [`HostPrincipal`]
//! owner encoded in the type, not a shared unit guarded only by job preflight.
//! There is no global table. One owner-bound namespace exists per execution.

use astrid_provider::{HostPrincipal, ProviderError};

/// Empty ramfs bound to one host principal.
///
/// There is no host path, `home://` URI, cwd fallback, or volume region.
/// Guest paths, argv, and payloads cannot select this namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EphemeralRamfs {
    owner: HostPrincipal,
}

impl EphemeralRamfs {
    /// Bind an empty ephemeral namespace to `owner`.
    #[must_use]
    pub const fn for_owner(owner: HostPrincipal) -> Self {
        Self { owner }
    }

    /// Immutable owner of this namespace. Not a guest UID.
    #[must_use]
    pub const fn owner(self) -> HostPrincipal {
        self.owner
    }

    /// Distinct per-principal namespace identity. Not a path.
    #[must_use]
    pub const fn namespace_id(self) -> HostPrincipal {
        self.owner
    }

    /// Host path probe. Always `None`: this namespace is not ambient host FS.
    #[must_use]
    pub const fn as_host_path(&self) -> Option<&'static str> {
        let _ = self;
        None
    }

    /// Reject a caller that does not own this namespace.
    ///
    /// This check is independent of job descriptor preflight.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] when `caller` is not the owner.
    pub fn require_owner(self, caller: HostPrincipal) -> Result<Self, ProviderError> {
        if caller.as_bytes() == self.owner.as_bytes() {
            Ok(self)
        } else {
            Err(ProviderError::PrincipalMismatch)
        }
    }

    /// Observe the empty namespace. Requires the matching owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a non-owner caller.
    pub fn observe(self, caller: HostPrincipal) -> Result<(), ProviderError> {
        let _ = self.require_owner(caller)?;
        Ok(())
    }

    /// Touch the empty namespace. Requires the matching owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a non-owner caller.
    pub fn touch(self, caller: HostPrincipal) -> Result<(), ProviderError> {
        let _ = self.require_owner(caller)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::EphemeralRamfs;
    use crate::fixtures::{alice_principal, bob_principal};
    use astrid_provider::ProviderError;

    #[test]
    fn ramfs_has_no_host_path_or_home_uri() {
        let ramfs = EphemeralRamfs::for_owner(alice_principal());
        assert!(ramfs.as_host_path().is_none());
        assert_ne!(ramfs.as_host_path(), Some("home://"));
        assert_ne!(ramfs.as_host_path(), Some("/"));
    }

    #[test]
    fn owner_is_encoded_and_namespaces_are_distinct() {
        let alice = EphemeralRamfs::for_owner(alice_principal());
        let bob = EphemeralRamfs::for_owner(bob_principal());
        assert_eq!(alice.owner(), alice_principal());
        assert_eq!(alice.namespace_id(), alice_principal());
        assert_ne!(alice, bob);
        assert_ne!(alice.namespace_id(), bob.namespace_id());
        assert_eq!(alice.observe(alice_principal()), Ok(()));
        assert_eq!(alice.touch(alice_principal()), Ok(()));
    }

    #[test]
    fn alice_namespace_rejects_bob_without_descriptor_preflight() {
        let alice = EphemeralRamfs::for_owner(alice_principal());
        assert_eq!(
            alice.require_owner(bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            alice.observe(bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            alice.touch(bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        let bob = EphemeralRamfs::for_owner(bob_principal());
        assert_eq!(
            bob.observe(alice_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            bob.touch(alice_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
    }
}
