//! Visit the selected entries of an owned checkpoint leaf in wire order.
use super::encoding;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

verus! {

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry<V> {
    pub(super) key: Vec<u8>,
    pub(super) value: V,
}

/// The successful callback transitions for exactly the matching prefix.
pub(super) open spec fn visited<S,V,E,F:Fn(S,Entry<V>)->Result<S,E>>(
    rows:Seq<Entry<V>>, n:nat, start:Seq<u8>, end:Seq<u8>, initial:S, state:S, visit:F,
) -> bool
    decreases n,
{
    if n == 0 { state == initial } else {
        let entry = rows[n-1];
        if encoding::range_contains(start,end,entry.key@) {
            exists|prior:S| visited(rows,(n-1) as nat,start,end,initial,prior,visit) &&
                #[trigger] visit.ensures((prior,entry),Ok(state))
        } else { visited(rows,(n-1) as nat,start,end,initial,state,visit) }
    }
}

pub(super) fn visit<S,V,E,F:Fn(S,Entry<V>)->Result<S,E>>(
    rows:Vec<Entry<V>>, start:&[u8], end:&[u8], initial:S, callback:F,
) -> (out:Result<S,E>)
    requires forall|s:S,r:Entry<V>| #[trigger] callback.requires((s,r)),
    ensures match out {
        Ok(s) => visited(rows@,rows@.len(),start@,end@,initial,s,callback),
        Err(e) => exists|i:int,s:S| 0 <= i < rows.len() &&
            visited(rows@,i as nat,start@,end@,initial,s,callback) &&
            encoding::range_contains(start@,end@,rows@[i].key@) &&
            #[trigger] callback.ensures((s,rows@[i]),Err(e)),
    },
{
    let mut iter = rows.into_iter();
    let mut state = initial;
    let ghost mut n:nat = 0;
    loop
        invariant
            n <= rows.len(), iter.remaining() == rows@.skip(n as int),
            visited(rows@,n,start@,end@,initial,state,callback),
            forall|s:S,r:Entry<V>| #[trigger] callback.requires((s,r)),
        decreases rows.len()-n,
    {
        let Some(entry) = iter.next() else {
            assert(n == rows.len());
            return Ok(state);
        };
        assert(entry == rows@[n as int]);
        if encoding::entry_in_range(&entry.key,start,end) {
            let ghost prior = state;
            match callback(state,entry) {
                Ok(next) => { state = next; },
                Err(error) => {
                    assert(callback.ensures((prior,rows@[n as int]),Err(error)));
                    return Err(error);
                },
            }
        }
        assert(visited(rows@,n+1,start@,end@,initial,state,callback));
        proof { n = n+1; };
    }
}
}
