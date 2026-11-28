//! Apply canonical principal root transitions while scanning the root journal.
use super::{
    ObjectId, RootGeneration, RootState,
    root_transition::{self, Advance},
    root_wire,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) open spec fn represents(w:root_wire::Root,r:RootState) -> bool {
    w.commit@ == r.commit.digest() && w.generation@ == vstd::bytes::spec_u64_to_le_bytes(r.generation.value())
}

pub(super) fn to_wire(root:RootState) -> (w:root_wire::Root)
    ensures represents(w,root),
{
    root_wire::Root {generation:root_wire::little_endian(root.generation.get()),commit:*root.commit.as_bytes()}
}

pub(super) fn from_wire(w:root_wire::Root) -> (r:RootState)
    ensures represents(w,r),
{
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    RootState {generation:RootGeneration::new(u64::from_le_bytes(w.generation)),commit:ObjectId::new(w.commit)}
}

pub(super) proof fn unique(w:root_wire::Root,a:RootState,b:RootState)
    requires represents(w,a),represents(w,b),ensures a == b,
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    ObjectId::same_digest(a.commit,b.commit);
    a.generation.same_value(b.generation);
}

pub(super) fn principal<P,D,E>(bytes:&[u8],decode:D,encode:E) -> (out:Option<P>)
    where D:FnOnce(&[u8])->Option<P>, E:FnOnce(&P)->Vec<u8>,
    requires decode.requires((bytes,)),
        forall|p:P| #[trigger] decode.ensures((bytes,),Some(p)) ==> encode.requires((&p,)),
    ensures match out {
        Some(p) => decode.ensures((bytes,),Some(p)) && exists|v:Vec<u8>| #[trigger] encode.ensures((&p,),v) && v@ == bytes@,
        None => decode.ensures((bytes,),None) || exists|p:P,v:Vec<u8>|
            #[trigger] decode.ensures((bytes,),Some(p)) && #[trigger] encode.ensures((&p,),v) && v@ != bytes@,
    },
{
    let owner = decode(bytes)?;
    let canonical = encode(&owner);
    if canonical.as_slice() == bytes {Some(owner)} else {None}
}

pub(super) enum Rejection { Conflict(Option<RootState>), Overflow, Generation }

pub(super) fn apply<P:Ord>(history:&mut BTreeMap<P,(RootState,u64)>,owner:P,expected:Option<RootState>,
    replacement:RootState,offset:u64) -> (out:Result<(),Rejection>)
    requires btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
    ensures btree_map_inv(final(history)), ({
        let actual = if old(history)@.contains_key(owner) {Some(old(history)@[owner].0)} else {None};
        let next = match actual {None => 0int,Some(r) => r.generation.value() as int + 1};
        &&& out.is_ok() == (actual == expected && replacement.generation.value() == next)
        &&& final(history)@ == if out.is_ok() {old(history)@.insert(owner,(replacement,offset))} else {old(history)@}
        &&& match out {
            Err(Rejection::Conflict(seen)) => seen == actual && seen != expected,
            Err(Rejection::Overflow) => actual == expected && next > u64::MAX,
            Err(Rejection::Generation) => actual == expected && next <= u64::MAX && replacement.generation.value() != next,
            Ok(()) => true,
        }
    }),
{
    let actual = history.get(&owner).map(|row:&(RootState,u64)| -> (r:RootState) ensures r == row.0 {row.0});
    match root_transition::compare(actual,expected) {
        Advance::Conflict => Err(Rejection::Conflict(actual)),
        Advance::Overflow => Err(Rejection::Overflow),
        Advance::Next(n) if replacement.generation.get() != n => Err(Rejection::Generation),
        Advance::Next(_) => {history.insert(owner,(replacement,offset)); Ok(())},
    }
}
}
