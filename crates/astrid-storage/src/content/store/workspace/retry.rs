//! Sample the owner's current header before each attempt to finish a workspace.
use vstd::prelude::*;

verus! {
pub(super) enum Step<T> { Conflict, Done(T) }

#[cfg(verus_keep_ghost)]
pub(super) ghost enum Event<P,I,H,T,E> {
    Read(P,Result<H,E>),
    Apply(P,I,H,Result<Step<T>,E>),
}

pub(super) trait Backend<P,I,H,T,E> {
    spec fn events(&self) -> Seq<Event<P,I,H,T,E>>;
    fn read(&mut self, owner:&P) -> (r:Result<H,E>)
        ensures final(self).events() == old(self).events().push(Event::Read(*owner,r));
    fn apply(&mut self, owner:&P,id:I,header:H) -> (r:Result<Step<T>,E>)
        ensures final(self).events() == old(self).events().push(Event::Apply(*owner,id,header,r));
}

pub(super) open spec fn conflicts<P,I,H,T,E>(trace:Seq<Event<P,I,H,T,E>>,owner:P,id:I,n:nat) -> bool {
    trace.len() == 2*n && forall|i:int| 0 <= i < n ==> match #[trigger] trace[2*i] {
        Event::Read(p,Ok(h)) => p == owner && trace[2*i+1] == Event::Apply(owner,id,h,Ok(Step::Conflict)),
        _ => false,
    }
}

pub(super) open spec fn complete<P,I,H,T,E>(trace:Seq<Event<P,I,H,T,E>>,owner:P,id:I,n:nat,out:Result<T,E>) -> bool {
    let prefix = trace.take(2*(n as int));
    &&& conflicts(prefix,owner,id,n)
    &&& if trace.len() == 2*n+1 {
        match out { Err(e) => trace[2*(n as int)] == Event::Read(owner,Err(e)), Ok(_) => false }
    } else {
        trace.len() == 2*n+2 && match trace[2*(n as int)] {
            Event::Read(p,Ok(h)) => p == owner && trace[2*(n as int)+1] == Event::Apply(owner,id,h,match out {
                Ok(t) => Ok(Step::Done(t)), Err(e) => Err(e),
            }),
            _ => false,
        }
    }
}

#[verifier::exec_allows_no_decreases_clause]
pub(super) fn run<P,I:Copy,H,T,E,B:Backend<P,I,H,T,E>>(backend:&mut B,owner:&P,id:I) -> (out:Result<T,E>)
    ensures final(backend).events().take(old(backend).events().len() as int) == old(backend).events(),
        exists|n:nat| #[trigger] complete(final(backend).events().skip(old(backend).events().len() as int),*owner,id,n,out),
{
    let ghost start = backend.events();
    let ghost mut n:nat = 0;
    loop
        invariant start == old(backend).events(), start.len() <= backend.events().len(),
            backend.events().take(start.len() as int) == start,
            conflicts(backend.events().skip(start.len() as int),*owner,id,n),
    {
        let ghost before = backend.events().skip(start.len() as int);
        let h = match backend.read(owner) {
            Ok(h) => h,
            Err(e) => {
                let ghost tail = backend.events().skip(start.len() as int);
                assert(tail =~= before.push(Event::Read(*owner,Err(e))));
                assert(tail.take(2*(n as int)) =~= before);
                assert(complete(tail,*owner,id,n,Err(e)));
                return Err(e);
            }
        };
        let r = backend.apply(owner,id,h);
        let ghost tail = backend.events().skip(start.len() as int);
        assert(tail =~= before.push(Event::Read(*owner,Ok(h))).push(Event::Apply(*owner,id,h,r)));
        assert(tail.take(2*(n as int)) =~= before);
        match r {
            Ok(Step::Conflict) => {
                assert forall|i:int| 0 <= i < n+1 implies match #[trigger] tail[2*i] {
                    Event::Read(p,Ok(h)) => p == *owner && tail[2*i+1] == Event::Apply(*owner,id,h,Ok(Step::Conflict)),
                    _ => false,
                } by { if i < n { assert(before[2*i] == tail[2*i]); } }
                proof { n = n+1; }
                assert(backend.events().take(start.len() as int) =~= start);
            },
            Ok(Step::Done(t)) => { assert(complete(tail,*owner,id,n,Ok(t))); return Ok(t); },
            Err(e) => { assert(complete(tail,*owner,id,n,Err(e))); return Err(e); },
        }
    }
}
}
