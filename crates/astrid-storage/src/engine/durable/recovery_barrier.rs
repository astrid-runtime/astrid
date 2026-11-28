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
    spec fn volume_id(&self) -> Option<int>;
    spec fn has_representations(&self) -> bool;
    fn representations_present(&self) -> (yes:bool)
        ensures yes == self.has_representations();
    fn sync(&mut self,target:Target) -> (out:Result<(),Self::Error>)
        requires target == Target::Representations ==> old(self).has_representations(),
        ensures final(self).volume_id()==old(self).volume_id(),
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

pub(super) enum Error<E> { Arena(E), Roots(E), Representations(E) }
pub(super) fn stabilize<M:Files,W>(files:&mut M,wal:W) -> (out:Result<Prepared<W>,Error<M::Error>>)
    requires old(files).pending().contains_key(Target::Arena),old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
    ensures ({
        let a = Target::Arena; let r = Target::Roots; let x = Target::Representations;
        let arena = old(files).calls().push(a); let roots = arena.push(r); let all = roots.push(x);
        let both = old(files).durable().insert(a,old(files).pending()[a]).insert(r,old(files).pending()[r]);
        &&& out matches Ok(stable) ==> stable.wal() == wal
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
