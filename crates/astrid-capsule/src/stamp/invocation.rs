use astrid_core::PrincipalUid;

/// Host attribution of a principal UID for the current capsule invocation.
///
/// This value records who the host bound to the invocation. It is not live
/// authority: it does not grant rights, resource scope, or budget, and it
/// cannot substitute for `ResourceAuthority` or admitted-table preflight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StampedInvocation {
    principal: PrincipalUid,
}

impl StampedInvocation {
    /// Construct an invocation stamp from an already trusted host identity.
    #[must_use]
    pub(crate) fn from_trusted_uid(principal: PrincipalUid) -> Self {
        Self { principal }
    }

    /// Return the immutable principal identity carried by this stamp.
    #[must_use]
    pub fn principal(&self) -> PrincipalUid {
        self.principal
    }
}
