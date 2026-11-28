//! Canonical media must be stable before handing the scanned WAL to its continuation.
use crate::recovery_barrier::{self as barrier,Error,Files,Target};
use vstd::prelude::*;

verus! {

/// Carry the actual WAL state through stabilization. Every error identifies the last attempted sync.
fn handoff<M:Files,W,V,F:FnOnce(W)->V>(files:&mut M,wal:W,finish:F) -> (out:Result<V,Error<M::Error>>)
    requires finish.requires((wal,)),old(files).pending().contains_key(Target::Arena),
        old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
    ensures ({
        let a = Target::Arena; let r = Target::Roots; let x = Target::Representations;
        let first = old(files).calls().push(a); let second = first.push(r); let third = second.push(x);
        match out {
            Ok(result) => {
                &&& finish.ensures((wal,),result)
                &&& final(files).durable()[a] == old(files).pending()[a]
                &&& final(files).durable()[r] == old(files).pending()[r]
                &&& if old(files).has_representations() {
                    final(files).calls() == third && final(files).durable()[x] == old(files).pending()[x]
                } else {final(files).calls() == second && final(files).durable().get(x) == old(files).durable().get(x)}
            },
            Err(Error::Arena(_)) => final(files).calls() == first,
            Err(Error::Roots(_)) => final(files).calls() == second,
            Err(Error::Representations(_)) => old(files).has_representations() && final(files).calls() == third,
        }
    }),
{
    let stable = barrier::stabilize(files,wal)?;
    Ok(stable.finish(finish))
}
}
