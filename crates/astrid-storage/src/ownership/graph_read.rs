//! Select and validate the ownership graph fetched for this read.
use vstd::prelude::*;

verus! {
pub(super) open spec fn selected<B,G,E,M:FnOnce()->G,D:FnOnce(B)->Result<G,E>>(
    raw:Option<B>,missing:M,decode:D,g:G) -> bool {
    match raw {None=>missing.ensures((),g),Some(bytes)=>decode.ensures((bytes,),Ok(g))}
}

pub(super) fn admit<B,G,E,M:FnOnce()->G,D:FnOnce(B)->Result<G,E>,V:FnOnce(&G)->Result<(),E>>(
    read:Result<Option<B>,E>,missing:M,decode:D,validate:V) -> (out:Result<G,E>)
    requires read == Ok(None) ==> missing.requires(()),
        read matches Ok(Some(bytes)) ==> decode.requires((bytes,)),
        forall|raw:Option<B>,g:G| read==Ok(raw) && #[trigger] selected(raw,missing,decode,g) ==> validate.requires((&g,)),
    ensures match read {
        Err(e) => out==Err(e),
        Ok(raw) => match out {
            Ok(g) => selected(raw,missing,decode,g) && validate.ensures((&g,),Ok(())),
            Err(e) => (raw matches Some(bytes) && decode.ensures((bytes,),Err(e))) ||
                exists|g:G| #[trigger] selected(raw,missing,decode,g) && validate.ensures((&g,),Err(e)),
        },
    },
{
    let raw=read?;
    let graph=match raw {None=>missing(),Some(bytes)=>decode(bytes)?};
    assert(selected(raw,missing,decode,graph));
    validate(&graph)?;
    Ok(graph)
}
}
