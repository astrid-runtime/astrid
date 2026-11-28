//! Root-journal transitions at restart, from canonical owner and root bytes to the recovered index.
use crate::{RootState, owner_codec::{self, Owner}, root_wire};
use std::collections::BTreeMap;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv,prelude::*};

verus! {
/// Canonical bytes are required even when a decoder can produce a principal.
fn journal_name(saved:&[u8],recoded:Option<Vec<u8>>) -> (owner:Option<Owner>)
    ensures owner.is_some() == ((saved@ == seq![0u8] ||
        (saved.len() == 33 && (saved[0] == 1 || saved[0] == 2))) &&
        (recoded matches Some(v) ==> v@ == saved@)),
        owner matches Some(o) ==> o.bytes() == saved@,
{
    crate::journal_history::principal(saved,owner_codec::decode,|o:&Owner| -> (v:Vec<u8>)
        ensures v@ == (match recoded {Some(other)=>other@,None=>o.bytes()}),
        {match recoded {Some(other)=>other,None=>o.encode()}})
}

/// A canonical journal payload updates only its decoded owner's history and retains the frame offset.
fn journal_transition<K:Ord+Copy,F>(history:&mut BTreeMap<K,(RootState,u64)>,owner:Owner,
    scheme:root_wire::Scheme,expected:Option<RootState>,replacement:RootState,offset:u64,
    key_of:F,keys:Ghost<spec_fn(Seq<u8>)->K>) -> (accepted:bool)
    where F:FnOnce(Owner)->K,
    requires btree_map_inv(old(history)),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        forall|o:Owner| #[trigger] key_of.requires((o,)),
        forall|o:Owner,k:K| #[trigger] key_of.ensures((o,),k) ==> k == (keys@)(o.bytes()),
    ensures ({
        let k = (keys@)(owner.bytes());
        let actual = if old(history)@.contains_key(k) {Some(old(history)@[k].0)} else {None};
        let next = match actual {None => 0int,Some(r) => r.generation.value() as int + 1};
        &&& accepted == (actual == expected && replacement.generation.value() == next)
        &&& final(history)@ == if accepted {old(history)@.insert(k,(replacement,offset))} else {old(history)@}
    }),
{
    use crate::journal_history as journal;
    let name = owner.encode();
    let prior = match expected {Some(r) => Some(journal::to_wire(r)),None => None};
    let next = journal::to_wire(replacement);
    let body = root_wire::encode(&name,scheme,prior,next).unwrap();
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(name.len() as u64));
    let (saved,mut cursor) = match root_wire::read_owner(&body) {Ok(pair) => pair, Err(_) => {assert(false);return false;}};
    assert(saved@ =~= name@);
    let recovered = journal::principal(saved,owner_codec::decode,|o:&Owner| -> (bytes:Vec<u8>)
        ensures bytes@ == o.bytes(), {o.encode()}).unwrap();
    let k = key_of(recovered);
    let ghost start = cursor as int;
    assert(body@.skip(start) =~= root_wire::prior(prior,scheme) + next.wire(scheme));
    assert(root_wire::tail(body@,start,scheme,prior,next));
    let (e,r) = match root_wire::read_tail(&body,&mut cursor,scheme) {Ok(pair) => pair, Err(_) => {assert(false);return false;}};
    proof {
        root_wire::unique_tail(body@,start,scheme,e,r,prior,next);
        assert(r.generation =~= next.generation); assert(r.commit =~= next.commit);
        if let Some(a) = e {
            assert(a.generation =~= prior.unwrap().generation); assert(a.commit =~= prior.unwrap().commit);
        }
        assert(e == prior && r == next);
    }
    let saved_expected = match e {
        Some(root) => {
            let restored = journal::from_wire(root);
            proof {journal::unique(root,restored,expected.unwrap());}
            Some(restored)
        },
        None => None,
    };
    let saved_next = journal::from_wire(r);
    proof {journal::unique(r,saved_next,replacement);}
    let ghost seen = if history@.contains_key(k) {Some(history@[k].0)} else {None};
    match journal::apply(history,k,saved_expected,saved_next,offset) {
        Ok(()) => true,
        Err(journal::Rejection::Conflict(actual)) => {assert(actual == seen && actual != expected);false},
        Err(journal::Rejection::Overflow) => {assert(seen == expected && seen.unwrap().generation.value() == u64::MAX);false},
        Err(journal::Rejection::Generation) => {assert(seen == expected && (seen matches Some(r) ==> r.generation.value() < u64::MAX));false},
    }
}

}
