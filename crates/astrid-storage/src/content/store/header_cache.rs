//! Select a cached content header only for the owner's sampled root.
use super::{ObjectId, RootState};
use vstd::prelude::*;

verus! {

fn select<P,H,L>(owner:&P, root:Option<RootState>, lookup:L) -> (out:Option<H>)
    where L:FnOnce(&P,ObjectId)->Option<(Option<RootState>,H)>,
    requires root matches Some(r) ==> lookup.requires((owner,r.commit)),
    ensures match root {
        None => out.is_none(),
        Some(r) => match out {
            Some(h) => lookup.ensures((owner,r.commit),Some((Some(r),h))),
            None => lookup.ensures((owner,r.commit),None) || exists|observed:Option<RootState>,h:H|
                observed != root && #[trigger] lookup.ensures((owner,r.commit),Some((observed,h))),
        },
    },
{
    let sampled = root?;
    let (recorded,header) = lookup(owner,sampled.commit)?;
    match recorded { Some(cached) if cached.same(sampled) => return Some(header), _ => {} }
    assert(lookup.ensures((owner,sampled.commit),Some((recorded,header))));
    None
}

/// Decode against the same sample when selection cannot supply a current header.
pub(super) fn read<P,H,E,L,D>(owner:&P,root:Option<RootState>,lookup:L,decode:D) -> (out:Result<H,E>)
    where L:FnOnce(&P,ObjectId)->Option<(Option<RootState>,H)>, D:FnOnce(&P,Option<RootState>)->Result<H,E>,
    requires root matches Some(r) ==> lookup.requires((owner,r.commit)), decode.requires((owner,root)),
    ensures match root {
        None => decode.ensures((owner,root),out),
        Some(r) => (out matches Ok(h) && lookup.ensures((owner,r.commit),Some((Some(r),h)))) ||
            (decode.ensures((owner,root),out) && (lookup.ensures((owner,r.commit),None) ||
                exists|observed:Option<RootState>,h:H| observed != root && #[trigger] lookup.ensures((owner,r.commit),Some((observed,h))))),
    },
{
    match select(owner,root,lookup) {
        Some(header) => Ok(header),
        None => decode(owner,root),
    }
}

}
