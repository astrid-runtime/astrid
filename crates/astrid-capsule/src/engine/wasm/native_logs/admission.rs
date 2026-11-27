//! Keep the operation covering an engine-managed log alive through its use.
use vstd::prelude::*;

verus! {

pub(super) enum Operation<'a,G> {
    Borrowed { _borrowed: &'a G },
    Owned { _owned: G },
}

/// Reuse only an operation covering this tracker and the current owner alias.
/// A different owner or tracker requires a fresh admission before file access.
pub(super) fn admit<'a,T,P,G,C,B>(tracker:&T,principal:&P,existing:Option<&'a G>,covers:C,begin:B)
    -> (out:Option<Operation<'a,G>>)
    where C:FnOnce(&G,&T,&P)->bool, B:FnOnce(&T,&P)->Option<G>,
    requires existing matches Some(g) ==> covers.requires((g,tracker,principal)),
        begin.requires((tracker,principal)),
    ensures ({
        let uncovered = existing.is_none() ||
            (existing matches Some(g) && covers.ensures((g,tracker,principal),false));
        match out {
            Some(Operation::Borrowed{_borrowed:g}) => existing == Some(g) && covers.ensures((g,tracker,principal),true),
            Some(Operation::Owned{_owned:g}) => uncovered && begin.ensures((tracker,principal),Some(g)),
            None => uncovered && begin.ensures((tracker,principal),None),
        }
    }),
{
    match existing {
        Some(g) if covers(g,tracker,principal) => return Some(Operation::Borrowed{_borrowed:g}),
        _ => {},
    }
    match begin(tracker,principal) {
        Some(g) => Some(Operation::Owned{_owned:g}),
        None => None,
    }
}

}
