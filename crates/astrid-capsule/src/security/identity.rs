//! Manifest authority for guest identity storage operations.
use vstd::prelude::*;

verus! {

/// Identity operations that can be gated by the security gate.
///
/// Typed enum prevents string-matching bugs. Each variant maps to a
/// required capability level in the manifest's `identity` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOperation {
    /// Resolve a platform user to an AstridUserId (requires "resolve").
    Resolve,
    /// Create a platform link (requires "link").
    Link,
    /// Remove a platform link (requires "link").
    Unlink,
    /// List links for a user (requires "link").
    ListLinks,
    /// Create a new user (requires "admin").
    CreateUser,
}

impl IdentityOperation {
    pub open spec fn required_name(self) -> Seq<char> {
        match self {
            Self::Resolve => "resolve"@,
            Self::Link | Self::Unlink | Self::ListLinks => "link"@,
            Self::CreateUser => "admin"@,
        }
    }

    /// Minimum required grant in the public manifest vocabulary.
    #[must_use]
    pub fn required_capability(self) -> (required: &'static str)
        ensures required@ == self.required_name(),
    {
        match self {
            Self::Resolve => "resolve",
            Self::Link | Self::Unlink | Self::ListLinks => "link",
            Self::CreateUser => "admin",
        }
    }

    pub(crate) open spec fn accepts(self, grant: Seq<char>) -> bool {
        grant == "admin"@ || match self {
            Self::Resolve => grant == "resolve"@ || grant == "link"@,
            Self::Link | Self::Unlink | Self::ListLinks => grant == "link"@,
            Self::CreateUser => false,
        }
    }

    pub(crate) fn permitted_by(self, grants: &[String]) -> (permitted: bool)
        ensures permitted == (exists|i: int| 0 <= i < grants.len() && self.accepts(grants[i]@)),
    {
        let required = self.required_capability();
        let mut i = 0;
        while i < grants.len()
            invariant i <= grants.len(), required@ == self.required_name(),
                forall|j: int| 0 <= j < i ==> !self.accepts(grants[j]@),
            decreases grants.len() - i,
        {
            let grant = grants[i].as_str();
            if grant == required || grant == "admin" || (required == "resolve" && grant == "link") {
                assert(self.accepts(grants[i as int]@));
                return true;
            }
            i += 1;
        }
        false
    }
}

}
