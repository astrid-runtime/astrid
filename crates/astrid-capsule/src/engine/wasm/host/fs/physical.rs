//! Rebuild the missing suffix before deriving the VFS address from the physical gate.
use vstd::prelude::*;

verus! {

pub(super) trait PhysicalPath<N>: Sized {
    spec fn parts(&self) -> Seq<N>;
    spec fn pushed(parts:Seq<N>, name:N) -> Seq<N>;
    spec fn stripped(parts:Seq<N>, root:Seq<N>) -> Option<Seq<N>>;

    fn append(&mut self, name:N)
        ensures final(self).parts() == Self::pushed(old(self).parts(),name);

    fn relative(&self, root:&Self) -> (out:Option<Self>)
        ensures match out { Some(p) => Self::stripped(self.parts(),root.parts()) == Some(p.parts()),
            None => Self::stripped(self.parts(),root.parts()).is_none() };
}

/// The resolver discovers missing names from the leaf towards its ancestor.
pub(super) open spec fn rebuild<N,P:PhysicalPath<N>>(ancestor:Seq<N>, missing:Seq<N>) -> Seq<N>
    decreases missing.len(),
{
    if missing.len() == 0 { ancestor }
    else { rebuild::<N,P>(P::pushed(ancestor,missing.last()), missing.drop_last()) }
}

pub(super) fn confine<N,P:PhysicalPath<N>>(root:&P, mut physical:P, mut missing:Vec<N>)
    -> (out:Result<(P,P),P>)
    ensures ({
        let full = rebuild::<N,P>(physical.parts(),missing@);
        match out {
            Ok((gate,address)) => gate.parts() == full && P::stripped(full,root.parts()) == Some(address.parts()),
            Err(path) => path.parts() == full && P::stripped(full,root.parts()).is_none(),
        }
    }),
{
    let ghost expected = rebuild::<N,P>(physical.parts(),missing@);
    while let Some(name) = missing.pop()
        invariant rebuild::<N,P>(physical.parts(),missing@) == expected,
        ensures physical.parts() == expected,
        decreases missing.len(),
    {
        physical.append(name);
    }
    match physical.relative(root) {
        Some(relative) => Ok((physical,relative)),
        None => Err(physical),
    }
}
}
