//! Publication currency for owner-scoped validation memos.
use super::RootState;
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoEpoch(u64);

impl MemoEpoch {
    pub(crate) closed spec fn value(self) -> u64 { self.0 }

    pub(super) fn new(value:u64) -> (epoch:Self)
        ensures epoch.value() == value,
    { Self(value) }

    pub(super) fn after_purge(self) -> (next:u64)
        ensures next as int == if self.value() == u64::MAX { u64::MAX as int } else { self.value() as int + 1 },
    { self.0.saturating_add(1) }

    pub(super) fn is_current(self,observed:Self) -> (current:bool)
        ensures current == (self.value() < u64::MAX && self.value() == observed.value()),
    { self.0 != u64::MAX && self.0 == observed.0 }

    /// Recheck the owner's full root under the publisher's projection guard.
    pub(super) fn admits_root<P,E,F:FnOnce(&P)->Result<Option<RootState>,E>>(
        self,observed:Self,owner:&P,expected:Option<RootState>,sample:F,
    ) -> (admitted:bool)
        requires sample.requires((owner,)),
        ensures if self.value() == u64::MAX || self.value() != observed.value() {
            !admitted
        } else if admitted { sample.ensures((owner,),Ok(expected)) }
        else {
            (exists|wrong:Option<RootState>| wrong != expected && #[trigger] sample.ensures((owner,),Ok(wrong))) ||
            (exists|error:E| #[trigger] sample.ensures((owner,),Err(error)))
        },
    {
        if !self.is_current(observed) { return false; }
        let actual = match sample(owner) {
            Ok(value) => value,
            Err(_error) => {
                assert(sample.ensures((owner,),Err(_error)));
                return false;
            },
        };
        let equal = match (actual,expected) {
            (Some(root),Some(wanted)) => root.same(wanted),
            (None,None) => true,
            _ => false,
        };
        assert(sample.ensures((owner,),Ok(actual)));
        equal
    }
}
}
