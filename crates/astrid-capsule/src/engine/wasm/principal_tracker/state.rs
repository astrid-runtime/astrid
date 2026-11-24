//! Transitions performed while the principal invocation tracker is locked.

use vstd::prelude::*;

verus! {

pub(super) struct PrincipalInvocation {
    retired: bool,
    active: usize,
}

impl PrincipalInvocation {

    pub(super) closed spec fn is_retired(&self) -> bool {
        self.retired
    }

    pub(super) closed spec fn active_count(&self) -> usize {
        self.active
    }

    pub(super) fn new() -> (state: Self)
        ensures !state.is_retired(), state.active_count() == 0,
    {
        Self { retired: false, active: 0 }
    }

    pub(super) fn active(&self) -> (active: usize)
        ensures active == self.active_count(),
    {
        self.active
    }

    pub(super) fn begin(&mut self) -> (admitted: bool)
        ensures
            final(self).is_retired() == old(self).is_retired(),
            admitted == (!old(self).is_retired() && old(self).active_count() < usize::MAX),
            final(self).active_count() as int == old(self).active_count() as int + if admitted { 1int } else { 0int },
    {
        if self.retired {
            return false;
        }
        let Some(active) = self.active.checked_add(1) else {
            return false;
        };
        self.active = active;
        true
    }

    pub(super) fn finish(&mut self)
        ensures
            final(self).is_retired() == old(self).is_retired(),
            final(self).active_count() as int == if old(self).active_count() == 0 { 0 } else { old(self).active_count() as int - 1 },
    {
        self.active = self.active.saturating_sub(1);
    }

    pub(super) fn retire(&mut self)
        ensures final(self).is_retired(), final(self).active_count() == old(self).active_count(),
    {
        self.retired = true;
    }

    pub(super) fn resume(&mut self)
        ensures !final(self).is_retired(), final(self).active_count() == old(self).active_count(),
    {
        self.retired = false;
    }

    pub(super) fn discardable(&self) -> (empty: bool)
        ensures empty == (!self.is_retired() && self.active_count() == 0),
    {
        !self.retired && self.active == 0
    }
}

}
