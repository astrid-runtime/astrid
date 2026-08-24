use astrid_core::PrincipalUid;

/// A host-created invocation identity that cannot be constructed from wire
/// aliases or guest payloads.
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
