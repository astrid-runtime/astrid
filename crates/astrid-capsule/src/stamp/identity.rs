use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::PrincipalDirectory;

use super::StampedInvocation;

/// Identity availability at a host ingress boundary.
///
/// The variants are readable by host consumers. Minting a
/// [`StampedInvocation`] still requires the crate-private resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressIdentity {
    /// The host has resolved the alias to an immutable principal UID.
    Stamped(StampedInvocation),
    /// The wire alias is valid, but no durable UID is currently available.
    Compatibility { principal: PrincipalId },
    /// No principal was supplied by this ingress.
    Unspecified,
}

impl IngressIdentity {
    /// Keep a cached stamp only when `binding_alias` still names that UID.
    ///
    /// Recv may pass a previously captured stamp as a hint. Unregister, rename,
    /// or rebind of the current owner/publisher alias must drop the hint so
    /// resolution observes live directory truth.
    #[must_use]
    pub(crate) fn revalidated_cached_uid(
        directory: &PrincipalDirectory,
        binding_alias: &PrincipalId,
        cached: PrincipalUid,
    ) -> Option<PrincipalUid> {
        match directory.uid_for(binding_alias) {
            Ok(uid) if uid == cached => Some(cached),
            _ => None,
        }
    }

    /// Resolve an ingress identity at the trusted host boundary.
    ///
    /// Crate-private so a downstream crate cannot mint a stamp from a local
    /// [`PrincipalDirectory`] or an arbitrary [`PrincipalUid`]. A trusted host
    /// UID always wins. Otherwise the live principal directory may resolve the
    /// validated wire alias. An alias with no directory entry remains visible
    /// only through the compatibility branch. The resulting stamp is
    /// attribution, not authority.
    #[must_use]
    pub(crate) fn from_host_context(
        directory: &PrincipalDirectory,
        wire_principal: Option<&PrincipalId>,
        trusted_uid: Option<PrincipalUid>,
    ) -> Self {
        if let Some(uid) = trusted_uid {
            return Self::Stamped(StampedInvocation::from_trusted_uid(uid));
        }

        let Some(principal) = wire_principal else {
            return Self::Unspecified;
        };

        match directory.uid_for(principal) {
            Ok(uid) => Self::Stamped(StampedInvocation::from_trusted_uid(uid)),
            Err(_) => Self::Compatibility {
                principal: principal.clone(),
            },
        }
    }

    /// Borrow the trusted stamp, if this ingress is UID-bound.
    #[must_use]
    pub fn trusted_stamp(&self) -> Option<&StampedInvocation> {
        match self {
            Self::Stamped(stamp) => Some(stamp),
            Self::Compatibility { .. } | Self::Unspecified => None,
        }
    }

    /// Borrow the compatibility alias, if no UID stamp is available.
    #[must_use]
    pub fn compatibility_principal(&self) -> Option<&PrincipalId> {
        match self {
            Self::Compatibility { principal } => Some(principal),
            Self::Stamped(_) | Self::Unspecified => None,
        }
    }
}
