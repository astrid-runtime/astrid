//! One bounded acquisition of a leaf relative to its retained directory.
use vstd::prelude::*;

verus! {

pub(super) enum CreateError<E> { Exists, Other(E) }

#[cfg(verus_keep_ghost)]
pub(super) enum Call<T,I,H,E> {
    Probe(T,Result<bool,E>),
    Create(T,Result<H,CreateError<E>>),
    Observe(T,Result<I,E>),
    Open(T,Result<H,E>),
    Confirm(T,I,H,Result<(),E>),
}

/// The native adapter supplies descriptor-relative metadata, exclusive create
/// and validated existing-file open. The call history is proof-only.
pub(super) trait LeafAccess<T,I,H,E> {
    spec fn calls(&self) -> Seq<Call<T,I,H,E>>;

    fn probe(&mut self,target:&T) -> (r:Result<bool,E>)
        ensures final(self).calls() == old(self).calls().push(Call::Probe(*target,r));

    fn create(&mut self,target:&T) -> (r:Result<H,CreateError<E>>)
        ensures final(self).calls() == old(self).calls().push(Call::Create(*target,r));

    fn observe(&mut self,target:&T) -> (r:Result<I,E>)
        ensures final(self).calls() == old(self).calls().push(Call::Observe(*target,r));

    fn open_existing(&mut self,target:&T) -> (r:Result<H,E>)
        ensures final(self).calls() == old(self).calls().push(Call::Open(*target,r));

    fn confirm(&mut self,target:&T,identity:I,file:&H) -> (r:Result<(),E>)
        ensures final(self).calls() == old(self).calls().push(Call::Confirm(*target,identity,*file,r));
}

pub(super) open spec fn checked_existing<T,I,H,E>(before:Seq<Call<T,I,H,E>>,target:T,out:Result<H,E>,after:Seq<Call<T,I,H,E>>) -> bool {
    match after[before.len() as int] {
        Call::Observe(t,observed) => t == target && {
            let seen = before.push(Call::Observe(target,observed));
            match observed {
                Err(e) => out == Err(e) && after == seen,
                Ok(id) => match after[seen.len() as int] {
                    Call::Open(t,opened) => t == target && {
                        let acquired = seen.push(Call::Open(target,opened));
                        match opened {
                            Err(e) => out == Err(e) && after == acquired,
                            Ok(h) => match out {
                                Ok(result) => result == h && after == acquired.push(Call::Confirm(target,id,h,Ok(()))),
                                Err(e) => after == acquired.push(Call::Confirm(target,id,h,Err(e))),
                            },
                        }
                    },
                    _ => false,
                },
            }
        },
        _ => false,
    }
}

fn existing<T,I,H,E,A:LeafAccess<T,I,H,E>>(io:&mut A,target:&T) -> (out:Result<H,E>)
    ensures checked_existing(old(io).calls(),*target,out,final(io).calls()),
{
    let id = io.observe(target)?;
    let file = io.open_existing(target)?;
    io.confirm(target,id,&file)?;
    Ok(file)
}

/// A create race falls back once to the same parent and name. All other
/// errors stop at the failing observation. The successful handle is preserved.
pub(super) fn open<T,I,H,E,A:LeafAccess<T,I,H,E>>(io:&mut A,target:&T) -> (out:Result<H,E>)
    ensures ({
        let old_calls = old(io).calls();
        let seen = old_calls.push(Call::Probe(*target,Ok(true)));
        let missing = old_calls.push(Call::Probe(*target,Ok(false)));
        let final_calls = final(io).calls();
        ||| (out matches Err(e) && final_calls == old_calls.push(Call::Probe(*target,Err(e))))
        ||| checked_existing(seen,*target,out,final_calls)
        ||| (out matches Ok(h) && final_calls == missing.push(Call::Create(*target,Ok(h))))
        ||| (out matches Err(e) && final_calls == missing.push(Call::Create(*target,Err(CreateError::Other(e)))))
        ||| checked_existing(missing.push(Call::Create(*target,Err(CreateError::Exists))),*target,out,final_calls)
    }),
{
    if io.probe(target)? { return existing(io,target); }
    match io.create(target) {
        Ok(file) => Ok(file),
        Err(CreateError::Exists) => existing(io,target),
        Err(CreateError::Other(e)) => Err(e),
    }
}
}
