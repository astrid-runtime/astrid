use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::PrincipalDirectory;

use super::StampedInvocation;

/// Identity availability at a host ingress boundary.
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
    /// Resolve an ingress identity without deriving authority from wire text.
    ///
    /// A trusted host UID always wins. Otherwise the live principal directory
    /// may resolve the validated wire alias. An alias with no directory entry
    /// remains visible only through the compatibility branch.
    #[must_use]
    pub fn from_host_context(
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
