//! Stabilize canonical recovery files before resuming or checkpointing the WAL.
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Target { Arena, Roots, Representations }

pub(super) trait Files {
    type Error;
    spec fn calls(&self) -> Seq<Target>;
    spec fn pending(&self) -> Map<Target,Seq<u8>>;
    spec fn durable(&self) -> Map<Target,Seq<u8>>;
    spec fn arena_target(&self) -> (int,Seq<u8>);
    spec fn roots_target(&self) -> (int,Seq<u8>);
    spec fn volume_id(&self) -> Option<int>;
    spec fn has_representations(&self) -> bool;
    fn representations_present(&self) -> (yes:bool)
        ensures yes == self.has_representations();
    fn sync(&mut self,target:Target) -> (out:Result<(),Self::Error>)
        requires target == Target::Representations ==> old(self).has_representations(),
        ensures final(self).roots_target()==old(self).roots_target() && final(self).arena_target()==old(self).arena_target(),
            final(self).volume_id()==old(self).volume_id(),
            final(self).calls() == old(self).calls().push(target),
            final(self).pending() == old(self).pending(), final(self).has_representations() == old(self).has_representations(),
            out.is_ok() && old(self).volume_id().is_none() ==> final(self).durable() == old(self).durable().insert(target,old(self).pending()[target]);
}

#[must_use]
pub(super) struct Prepared<W> { wal:W }

impl<W> Prepared<W> {
    pub(super) closed spec fn wal(self) -> W {self.wal}
    pub(super) fn finish<T,F:FnOnce(W)->T>(self,finish:F) -> (value:T)
        requires finish.requires((self.wal(),)), ensures finish.ensures((self.wal(),),value),
    { finish(self.wal) }
}

/// The live checkpoint publishes any new representation before syncing the root journal.
/// Each completed phase supplies the handle for the next phase; the final handle permits retirement.
pub(super) fn stabilize_fold<S,E,A,R,J,V>(initial:S,arena:A,representations:R,roots:J,volume:V)
    -> (out:Result<Prepared<S>,E>)
    where A:FnOnce(S)->Result<S,E>,R:FnOnce(S)->Result<S,E>,J:FnOnce(S)->Result<S,E>,V:FnOnce(S)->Result<S,E>,
    requires arena.requires((initial,)),forall|s:S| #[trigger] representations.requires((s,)),
        forall|s:S| #[trigger] roots.requires((s,)),forall|s:S| #[trigger] volume.requires((s,)),
    ensures match out {
        Ok(stable)=>exists|a:S,r:S,j:S| #[trigger] arena.ensures((initial,),Ok(a)) &&
            #[trigger] representations.ensures((a,),Ok(r)) && #[trigger] roots.ensures((r,),Ok(j)) &&
            volume.ensures((j,),Ok(stable.wal())),
        Err(e)=>arena.ensures((initial,),Err(e)) ||
            exists|a:S| #[trigger] arena.ensures((initial,),Ok(a)) && (representations.ensures((a,),Err(e)) ||
            exists|r:S| #[trigger] representations.ensures((a,),Ok(r)) && (roots.ensures((r,),Err(e)) ||
            exists|j:S| #[trigger] roots.ensures((r,),Ok(j)) && volume.ensures((j,),Err(e)))),
    },
{
    let a=arena(initial)?;
    let r=representations(a)?;
    let j=roots(r)?;
    let wal=volume(j)?;
    Ok(Prepared {wal})
}

pub(super) enum Error<E> { Arena(E), Roots(E), Representations(E) }
pub(super) fn stabilize<M:Files,W>(files:&mut M,wal:W) -> (out:Result<Prepared<W>,Error<M::Error>>)
    requires old(files).pending().contains_key(Target::Arena),old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
    ensures ({
        let a = Target::Arena; let r = Target::Roots; let x = Target::Representations;
        let arena = old(files).calls().push(a); let roots = arena.push(r); let all = roots.push(x);
        let both = old(files).durable().insert(a,old(files).pending()[a]).insert(r,old(files).pending()[r]);
        &&& out matches Ok(stable) ==> stable.wal() == wal
        &&& final(files).roots_target()==old(files).roots_target() && final(files).arena_target()==old(files).arena_target()
        &&& final(files).volume_id()==old(files).volume_id()
        &&& final(files).pending() == old(files).pending()
        &&& match out {
            Ok(_) => if old(files).has_representations() {
                final(files).calls() == all && (old(files).volume_id().is_none() ==> final(files).durable() == both.insert(x,old(files).pending()[x]))
            } else {final(files).calls() == roots && (old(files).volume_id().is_none() ==> final(files).durable() == both)},
            Err(Error::Arena(_)) => final(files).calls() == arena,
            Err(Error::Roots(_)) => final(files).calls() == roots,
            Err(Error::Representations(_)) => old(files).has_representations() && final(files).calls() == all,
        }
    }),
{
    if let Err(e) = files.sync(Target::Arena) {return Err(Error::Arena(e));}
    if let Err(e) = files.sync(Target::Roots) {return Err(Error::Roots(e));}
    if !files.representations_present() {return Ok(Prepared {wal});}
    if let Err(e) = files.sync(Target::Representations) {return Err(Error::Representations(e));}
    Ok(Prepared {wal})
}
}

#[cfg(test)]
mod tests {
    use super::stabilize_fold;
    use std::cell::RefCell;

    #[test]
    fn live_fold_stops_at_each_failed_sync_before_releasing_the_wal() {
        for failure in [Some(0), Some(1), Some(2), Some(3), None] {
            let calls = RefCell::new(Vec::new());
            let sync = |phase: usize| {
                let calls = &calls;
                move |handle| {
                    calls.borrow_mut().push(phase);
                    assert_eq!(handle, (47, phase));
                    if failure == Some(phase) {
                        Err(phase)
                    } else {
                        Ok((47, phase + 1))
                    }
                }
            };
            let result = stabilize_fold((47, 0), sync(0), sync(1), sync(2), sync(3))
                .map(|stable| stable.finish(|handle| handle));
            assert_eq!(result, failure.map_or(Ok((47, 4)), Err));
            let count = failure.map_or(4, |phase| phase + 1);
            assert_eq!(calls.into_inner(), (0..count).collect::<Vec<_>>());
        }
    }
}
