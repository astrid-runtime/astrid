//! Apply a decoded root-journal record to the actual recovered principal map.
use super::{
    RootState, journal_history as history, journal_payload::Record, journal_snapshot as snapshot,
    journal_transition as transition, root_wire,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) enum CodecError { Order, Principal }
pub(super) enum Error { Transition(Option<RootState>,transition::Error), Snapshot(snapshot::SnapshotError<CodecError>) }

pub(super) open spec fn bound_name<P,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>>(bytes:Seq<u8>,p:P,decode:D,recode:C) -> bool {
    exists|b:&[u8]| b@==bytes && #[trigger] transition::named(b,p,decode,recode)
}

pub(super) open spec fn accepted<P,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>>(record:Record,data:Seq<u8>,at:u64,
    scheme:root_wire::Scheme,before:Map<P,(RootState,u64)>,after:Map<P,(RootState,u64)>,decode:D,recode:C) -> bool {
    match record {
        Record::Transition(r)=>data==transition::wire(r.principal@,scheme,r.expected,r.replacement) &&
            exists|name:&[u8],p:P| name@==r.principal@ && #[trigger] transition::named(name,p,decode,recode) && {
                let actual=if before.contains_key(p) {Some(before[p].0)} else {None};
                &&& actual==r.expected && r.replacement.generation.value()==match actual {None=>0int,Some(root)=>root.generation.value() as int+1}
                &&& after==before.insert(p,(r.replacement,at))
            },
        Record::Snapshot(rows)=>at==0 && before.is_empty() && snapshot::ordered(rows@) &&
            data==snapshot::prefix(rows@,rows.len() as nat,scheme) && exists|ids:Seq<P>| ids.len()==rows.len() &&
                #[trigger] snapshot::image(rows@,ids,after) && forall|i:int| 0<=i<ids.len() ==>
                    #[trigger] bound_name(rows@[i].0@,ids[i],decode,recode),
    }
}

pub(super) open spec fn rejected<P,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>>(r:Record,data:Seq<u8>,at:u64,
    scheme:root_wire::Scheme,prior:Map<P,(RootState,u64)>,decode:D,recode:C,error:Error) -> bool {
    match (r,error) {
        (Record::Transition(t),Error::Transition(expected,e))=>expected==t.expected &&
            transition::replay_refused(t,data,scheme,prior,decode,recode,e),
        (Record::Snapshot(rows),Error::Snapshot(e))=>match e {
            snapshot::SnapshotError::Position=>at!=0 || !prior.is_empty(),
            snapshot::SnapshotError::Noncanonical=>data!=snapshot::prefix(rows@,rows.len() as nat,scheme),
            snapshot::SnapshotError::Codec(CodecError::Order)=>!snapshot::ordered(rows@),
            snapshot::SnapshotError::Codec(CodecError::Principal)=>exists|i:int| 0<=i<rows.len() && #[trigger] transition::invalid_name(rows@[i].0@,decode,recode),
            snapshot::SnapshotError::Duplicate=>exists|i:int,j:int,p:P| 0<=i<j<rows.len() &&
                #[trigger] bound_name(rows@[i].0@,p,decode,recode) && #[trigger] bound_name(rows@[j].0@,p,decode,recode),
        },
        _=>false,
    }
}

#[verifier::spinoff_prover]
pub(super) fn apply<P:Ord,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy>(table:&mut BTreeMap<P,(RootState,u64)>,
    record:Record,data:&[u8],at:u64,scheme:root_wire::Scheme,decode:D,recode:C) -> (out:Result<(),Error>)
    requires btree_map_inv(old(table)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
    ensures btree_map_inv(final(table)),out.is_err() ==> final(table)@==old(table)@,
        out.is_ok() ==> accepted(record,data@,at,scheme,old(table)@,final(table)@,decode,recode),
        out matches Err(e) ==> rejected(record,data@,at,scheme,old(table)@,decode,recode,e),
        out matches Err(Error::Transition(_,_)) ==> record is Transition,
        out matches Err(Error::Snapshot(_)) ==> record is Snapshot,
{
    match record {
        Record::Transition(r)=>match r.replay(table,scheme,at,data,decode,recode) {
            Ok(())=>{assert(accepted(record,data@,at,scheme,old(table)@,table@,decode,recode));Ok(())},
            Err(e)=>{
                Err(Error::Transition(r.expected,e))
            },
        },
        Record::Snapshot(rows)=>{
            let encode=|rows:&Vec<(Vec<u8>,RootState)>| -> (out:Result<Vec<u8>,CodecError>)
                ensures out.is_err()==!snapshot::ordered(rows@),out matches Err(e) ==> e is Order,
                    out matches Ok(v) ==> snapshot::ordered(rows@) && v@==snapshot::prefix(rows@,rows.len() as nat,scheme),
            {snapshot::encode_ordered(rows,scheme).ok_or(CodecError::Order)};
            let owner=|bytes:&Vec<u8>| -> (out:Result<P,CodecError>)
                ensures out matches Err(e) ==> e is Principal && transition::invalid_name(bytes@,decode,recode),
                    out matches Ok(p) ==> bound_name(bytes@,p,decode,recode),
            {
                let b=bytes.as_slice();
                let result=history::principal(b,decode,recode);
                if let Some(p)=result {
                    assert(transition::named(b,p,decode,recode));assert(bound_name(bytes@,p,decode,recode));Ok(p)
                } else {
                    assert(transition::rejected_name(b,decode,recode));assert(transition::invalid_name(bytes@,decode,recode));Err(CodecError::Principal)
                }
            };
            let ghost original=rows@;
            match snapshot::restore(table,at,data,rows,encode,owner) {
                Ok(())=>{
                    proof {
                        let ids=choose|ids:Seq<P>| ids.len()==original.len() && snapshot::decoded(original,ids,owner) &&
                            #[trigger] snapshot::image(original,ids,table@);
                        assert forall|i:int| 0<=i<ids.len() implies #[trigger] bound_name(original[i].0@,ids[i],decode,recode) by {
                            assert(owner.ensures((&original[i].0,),Ok(ids[i])));
                        }
                    }
                    assert(accepted(record,data@,at,scheme,old(table)@,table@,decode,recode));
                    Ok(())
                },
                Err(e)=>{
                    proof {
                        match e {
                            snapshot::SnapshotError::Duplicate=>{
                                let (i,j,p)=choose|i:int,j:int,p:P| 0<=i<j<original.len() &&
                                    #[trigger] owner.ensures((&original[i].0,),Ok(p)) && #[trigger] owner.ensures((&original[j].0,),Ok(p));
                                assert(bound_name(original[i].0@,p,decode,recode) && bound_name(original[j].0@,p,decode,recode));
                            },
                            snapshot::SnapshotError::Codec(CodecError::Principal)=>{
                                let i=choose|i:int| 0<=i<original.len() && #[trigger] owner.ensures((&original[i].0,),Err(CodecError::Principal));
                                assert(transition::invalid_name(original[i].0@,decode,recode));
                            },
                            _=>{},
                        }
                        assert(rejected(record,data@,at,scheme,old(table)@,decode,recode,Error::Snapshot(e)));
                    }
                    Err(Error::Snapshot(e))
                },
            }
        },
    }
}

pub(super) enum VisitError { Decode(usize,super::journal_payload::Error), Apply(Error) }

pub(super) open spec fn step<P,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>>(data:Seq<u8>,at:u64,
    scheme:root_wire::Scheme,before:Map<P,(RootState,u64)>,after:Map<P,(RootState,u64)>,decode:D,recode:C) -> bool {
    exists|r:Record| #[trigger] accepted(r,data,at,scheme,before,after,decode,recode) && match r {
        Record::Transition(t)=>data.len()>=8 && super::journal_payload::tag(data)==t.principal.len() && t.principal.len()<snapshot::SENTINEL,
        Record::Snapshot(rows)=>super::journal_payload::snapshot_header(data,rows.len()),
    }
}

/// Refusals carry the decoder's wire evidence or a byte-bound decoded record
/// and the predicate that caused its application to fail against the prior map.
pub(super) open spec fn refusal<P,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>>(data:Seq<u8>,at:u64,
    scheme:root_wire::Scheme,prior:Map<P,(RootState,u64)>,decode:D,recode:C,e:VisitError) -> bool {
    match e {
        VisitError::Decode(cursor,reason)=>super::journal_payload::decode_failure(data,cursor,scheme,reason),
        VisitError::Apply(reason)=>exists|r:Record| #[trigger] super::journal_payload::decoded(r,data,scheme) &&
            rejected(r,data,at,scheme,prior,decode,recode,reason),
    }
}

/// Failed decoding and failed replay preserve the entire previous history.
pub(super) fn offer<P:Ord,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy>(
    table:&mut BTreeMap<P,(RootState,u64)>,at:u64,data:&[u8],scheme:root_wire::Scheme,decode:D,recode:C)
    -> (out:Result<(),VisitError>)
    requires btree_map_inv(old(table)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
    ensures btree_map_inv(final(table)),out.is_err() ==> final(table)@==old(table)@,
        out.is_ok() ==> step(data@,at,scheme,old(table)@,final(table)@,decode,recode),
        out matches Err(e) ==> refusal(data@,at,scheme,old(table)@,decode,recode,e),
{
    let mut cursor=0;
    let r=match super::journal_payload::decode(data,&mut cursor,scheme) {
        Ok(r)=>r,Err(e)=>return Err(VisitError::Decode(cursor,e)),
    };
    let ghost parsed=r;
    match apply(table,r,data,at,scheme,decode,recode) {
        Ok(())=>{
            assert(accepted(parsed,data@,at,scheme,old(table)@,table@,decode,recode));
            Ok(())
        },
        Err(e)=>{
            proof {
                assert(super::journal_payload::decoded(parsed,data@,scheme));
                if let Record::Snapshot(rows)=parsed {
                    assert(super::journal_payload::snapshot_header(data@,rows.len()));
                }
            }
            Err(VisitError::Apply(e))
        },
    }
}
}
