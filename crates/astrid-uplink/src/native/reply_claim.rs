//! Exclusive admission for a pending human response on one native socket.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase { Available, Claimed, Spent }

impl Phase {
    pub(super) fn claim(&mut self, registered: u128, offered: u128, closed: bool) -> (ok: bool)
        ensures ok == (!closed && registered == offered && *old(self) == Phase::Available),
            *final(self) == if ok { Phase::Claimed } else { *old(self) },
    {
        if closed || registered != offered || !matches!(self, Phase::Available) { return false; }
        *self = Phase::Claimed;
        true
    }

    pub(super) fn finish(&mut self, registered: u128, offered: u128, committed: bool) -> (remove: bool)
        ensures remove == (registered == offered && *old(self) == Phase::Claimed && committed),
            *final(self) == if registered == offered && *old(self) == Phase::Claimed {
                if committed { Phase::Spent } else { Phase::Available }
            } else { *old(self) },
    {
        if registered != offered || !matches!(self, Phase::Claimed) { return false; }
        if committed {
            *self = Phase::Spent;
            true
        } else {
            *self = Phase::Available;
            false
        }
    }
}

}
