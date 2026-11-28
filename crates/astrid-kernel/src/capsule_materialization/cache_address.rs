//! Exact logical identity of a durable capsule cache directory.

use vstd::prelude::*;

verus! {

pub(crate) struct Address<'a> {
    pub(crate) owner: &'a [u8],
    pub(crate) capsule: &'a [u8],
    pub(crate) digest: &'a [u8],
}

impl Address<'_> {
    pub(crate) fn matches(&self, expected: &Address) -> (accepted: bool)
        ensures accepted == (self.owner@ == expected.owner@ &&
            self.capsule@ == expected.capsule@ && self.digest@ == expected.digest@),
    {
        if self.owner != expected.owner || self.capsule != expected.capsule ||
            self.digest != expected.digest { return false; }
        assert(self.owner@ =~= expected.owner@);
        assert(self.capsule@ =~= expected.capsule@);
        assert(self.digest@ =~= expected.digest@);
        true
    }
}

}
