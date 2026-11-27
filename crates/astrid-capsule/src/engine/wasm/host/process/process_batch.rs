//! Dispatch an owned snapshot to a process cleanup callback outside the registry mutex.
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;
verus! {
// Native reaping supplies this operation. The trace exists only in the proof.
pub(super) trait Reaper<T> {
    spec fn calls(&self) -> Seq<T>;

    fn reap(&mut self, entry: T)
        ensures final(self).calls() == old(self).calls().push(entry);
}

/// Dispatch the owned batch outside the registry lock, preserving order.
pub(super) fn reap_batch<T, R: Reaper<T>>(entries: Vec<T>, reaper: &mut R)
    ensures final(reaper).calls() == old(reaper).calls() + entries@,
{
    let ghost initial = reaper.calls();
    let mut iter = entries.into_iter();
    loop
        invariant
            iter.decrease().is_some(),
            initial == old(reaper).calls(),
            reaper.calls() + iter.remaining() == initial + entries@,
        decreases iter.decrease().unwrap(),
    {
        let ghost remaining = iter.remaining();
        let Some(entry) = iter.next() else {
            assert(reaper.calls() + remaining == initial + entries@);
            assert(reaper.calls() + remaining =~= reaper.calls());
            assert(reaper.calls() == old(reaper).calls() + entries@);
            return;
        };
        reaper.reap(entry);
        assert(reaper.calls() + iter.remaining() =~= initial + entries@);
    }
}
}
