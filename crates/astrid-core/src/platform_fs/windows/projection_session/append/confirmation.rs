//! Final checks before Windows returns an acquired append handle.
use vstd::prelude::*;

verus! {

pub(super) enum Failure<E> { Native(E), CrossVolume }

#[cfg(verus_keep_ghost)]
pub(super) enum Call<H,D,P,E> {
    Volume(H,Result<u32,E>),
    Directory(D,Option<E>),
    Recapture(P,H,Option<E>),
}

/// The native adapter observes handle identity and checks the exact private
/// directory contract. Its call history is erased in the compiled runtime.
pub(super) trait Checks<H,D,P,E> {
    spec fn calls(&self) -> Seq<Call<H,D,P,E>>;

    fn volume(&mut self,handle:&H) -> (r:Result<u32,E>)
        ensures final(self).calls() == old(self).calls().push(Call::Volume(*handle,r));

    fn directory(&mut self,guard:&D) -> (r:Option<E>)
        ensures final(self).calls() == old(self).calls().push(Call::Directory(*guard,r));

    fn recapture(&mut self,path:&P,root:&H) -> (r:Option<E>)
        ensures final(self).calls() == old(self).calls().push(Call::Recapture(*path,*root,r));
}

pub(super) fn finish<H,D,P,E,A:Checks<H,D,P,E>>(
    io:&mut A,file:H,root:&H,parent:&D,root_directory:&D,path:&P,
) -> (out:Result<H,Failure<E>>)
    ensures ({
        let prior = old(io).calls();
        let calls = final(io).calls();
        match calls[prior.len() as int] {
            Call::Volume(h,v) => h == file && {
                let leaf = prior.push(Call::Volume(file,v));
                match v {
                    Err(e) => out == Err(Failure::Native(e)) && calls == leaf,
                    Ok(leaf_volume) => match calls[leaf.len() as int] {
                        Call::Volume(r,w) => r == *root && {
                            let both = leaf.push(Call::Volume(*root,w));
                            match w {
                                Err(e) => out == Err(Failure::Native(e)) && calls == both,
                                Ok(root_volume) => if leaf_volume != root_volume {
                                    out == Err(Failure::CrossVolume) && calls == both
                                } else {
                                    let parent_ok = both.push(Call::Directory(*parent,None));
                                    let root_ok = parent_ok.push(Call::Directory(*root_directory,None));
                                    match out {
                                        Ok(accepted) => accepted == file && calls == root_ok.push(Call::Recapture(*path,*root,None)),
                                        Err(Failure::Native(e)) =>
                                            calls == both.push(Call::Directory(*parent,Some(e))) ||
                                            calls == parent_ok.push(Call::Directory(*root_directory,Some(e))) ||
                                            calls == root_ok.push(Call::Recapture(*path,*root,Some(e))),
                                        Err(Failure::CrossVolume) => false,
                                    }
                                },
                            }
                        },
                        _ => false,
                    },
                }
            },
            _ => false,
        }
    }),
{
    let leaf_volume = match io.volume(&file) {
        Ok(volume) => volume,
        Err(error) => return Err(Failure::Native(error)),
    };
    let root_volume = match io.volume(root) {
        Ok(volume) => volume,
        Err(error) => return Err(Failure::Native(error)),
    };
    if leaf_volume != root_volume {
        return Err(Failure::CrossVolume);
    }
    if let Some(error) = io.directory(parent) {
        return Err(Failure::Native(error));
    }
    if let Some(error) = io.directory(root_directory) {
        return Err(Failure::Native(error));
    }
    if let Some(error) = io.recapture(path,root) {
        return Err(Failure::Native(error));
    }
    Ok(file)
}
}
