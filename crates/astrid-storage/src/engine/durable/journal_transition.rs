//! Bind a scanned transition's canonical bytes to the recovered principal root.
use super::{RootState, journal_history as history, root_wire};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) struct Record {
    pub(super) principal:Vec<u8>,
    pub(super) expected:Option<RootState>,
    pub(super) replacement:RootState,
}

pub(super) open spec fn root(r:RootState,s:root_wire::Scheme) -> Seq<u8> {
    vstd::bytes::spec_u64_to_le_bytes(r.generation.value()) + s.algorithm@ + s.construction@ +
        seq![32u8,0,0,0] + r.commit.digest()
}

pub(super) open spec fn wire(name:Seq<u8>,s:root_wire::Scheme,e:Option<RootState>,r:RootState) -> Seq<u8> {
    vstd::bytes::spec_u64_to_le_bytes(name.len() as u64) + name +
        (match e {Some(p)=>seq![1u8]+root(p,s),None=>seq![0u8]}) + root(r,s)
}

pub(super) fn encode(name:&[u8],scheme:root_wire::Scheme,expected:Option<RootState>,replacement:RootState)
    -> (out:Option<Vec<u8>>)
    ensures out.is_some() == (name.len() < u64::MAX),
        out matches Some(bytes) ==> bytes@ == wire(name@,scheme,expected,replacement),
{
    let prior = expected.map(history::to_wire);
    let next = history::to_wire(replacement);
    root_wire::encode(name,scheme,prior,next)
}

pub(super) enum DecodeError { Length, Principal(root_wire::ReadError), Tail(root_wire::TailError) }

/// Decode the transition body following a journal header. Keep the reader's
/// cursor on failure so native diagnostics can inspect an invalid identity.
pub(super) fn decode(bytes:&[u8],cursor:&mut usize,length:u64,scheme:root_wire::Scheme)
    -> (out:Result<Record,DecodeError>)
    ensures out matches Ok(r) ==> {
        let at=*old(cursor) as int;
        &&& *final(cursor)==bytes.len() && at+length<=bytes.len()
        &&& r.principal@==bytes@.subrange(at,at+length)
        &&& exists|e:Option<root_wire::Root>,n:root_wire::Root|
            #[trigger] root_wire::tail(bytes@,at+length,scheme,e,n) && history::represents(n,r.replacement) &&
            match (e,r.expected) {(None,None)=>true,(Some(a),Some(b))=>history::represents(a,b),_=>false}
    },
        forall|e:Option<root_wire::Root>,n:root_wire::Root| length<=usize::MAX &&
            #[trigger] root_wire::tail(bytes@,*old(cursor) as int+length,scheme,e,n) ==> out.is_ok(),
{
    let Ok(len)=usize::try_from(length) else {return Err(DecodeError::Length);};
    let name=match root_wire::take(bytes,cursor,len) {Ok(v)=>v,Err(e)=>return Err(DecodeError::Principal(e))};
    let mut principal=Vec::new();
    principal.extend_from_slice(name);
    let ghost pos=*cursor as int;
    let (expected,replacement)=match root_wire::read_tail(bytes,cursor,scheme) {
        Ok(pair)=>pair,Err(e)=>return Err(DecodeError::Tail(e)),
    };
    assert(root_wire::tail(bytes@,pos,scheme,expected,replacement));
    let prior=expected.map(|w:root_wire::Root| -> (r:RootState) ensures history::represents(w,r), {history::from_wire(w)});
    Ok(Record{principal,expected:prior,replacement:history::from_wire(replacement)})
}

pub(super) enum Error { Length, Noncanonical, Principal, History(history::Rejection) }

pub(super) open spec fn named<P,D:FnOnce(&[u8])->Option<P>,E:FnOnce(&P)->Vec<u8>>(
    name:&[u8],owner:P,decode:D,encode:E) -> bool {
    decode.ensures((name,),Some(owner)) && exists|v:Vec<u8>| #[trigger] encode.ensures((&owner,),v) && v@ == name@
}

pub(super) open spec fn history_reason(seen:Option<RootState>,expected:Option<RootState>,next:RootState,error:history::Rejection) -> bool {
    let generation=match seen {None=>0int,Some(r)=>r.generation.value() as int+1};
    match error {
        history::Rejection::Conflict(actual)=>actual==seen && actual!=expected,
        history::Rejection::Overflow=>seen==expected && generation>u64::MAX,
        history::Rejection::Generation=>seen==expected && generation<=u64::MAX && next.generation.value()!=generation,
    }
}

pub(super) open spec fn rejected_name<P,D:FnOnce(&[u8])->Option<P>,C:FnOnce(&P)->Vec<u8>>(name:&[u8],decode:D,recode:C) -> bool {
    decode.ensures((name,),None) || exists|p:P,v:Vec<u8>| #[trigger] decode.ensures((name,),Some(p)) && #[trigger] recode.ensures((&p,),v) && v@!=name@
}

pub(super) open spec fn invalid_name<P,D:FnOnce(&[u8])->Option<P>,C:FnOnce(&P)->Vec<u8>>(bytes:Seq<u8>,decode:D,recode:C) -> bool {
    exists|name:&[u8]| name@==bytes && #[trigger] rejected_name(name,decode,recode)
}

pub(super) open spec fn replay_refused<P,D:FnOnce(&[u8])->Option<P>,C:FnOnce(&P)->Vec<u8>>(t:Record,data:Seq<u8>,scheme:root_wire::Scheme,
    prior:Map<P,(RootState,u64)>,decode:D,recode:C,e:Error) -> bool {
    match e {
        Error::Length=>t.principal.len()>=u64::MAX,
        Error::Noncanonical=>data!=wire(t.principal@,scheme,t.expected,t.replacement),
        Error::Principal=>invalid_name(t.principal@,decode,recode),
        Error::History(h)=>exists|name:&[u8],owner:P| name@==t.principal@ && #[trigger] named(name,owner,decode,recode) &&
            history_reason(if prior.contains_key(owner) {Some(prior[owner].0)} else {None},t.expected,t.replacement,h),
    }
}

impl Record {
    pub(super) fn replay<P:Ord,D:FnOnce(&[u8])->Option<P>,E:FnOnce(&P)->Vec<u8>>(
        &self,history:&mut BTreeMap<P,(RootState,u64)>,scheme:root_wire::Scheme,at:u64,
        payload:&[u8],decode:D,recode:E) -> (out:Result<(),Error>)
        requires btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            forall|n:&[u8]| n@ == self.principal@ ==> #[trigger] decode.requires((n,)),
            forall|n:&[u8],p:P| n@ == self.principal@ && #[trigger] decode.ensures((n,),Some(p)) ==> recode.requires((&p,)),
        ensures btree_map_inv(final(history)),
            out matches Err(e) ==> replay_refused(*self,payload@,scheme,old(history)@,decode,recode,e),
            out.is_err() ==> final(history)@ == old(history)@,
            (out matches Err(Error::Length)) == (self.principal.len() >= u64::MAX),
            (out matches Err(Error::Noncanonical)) == (self.principal.len() < u64::MAX &&
                payload@ != wire(self.principal@,scheme,self.expected,self.replacement)),
            out matches Err(Error::Principal) ==> exists|n:&[u8]| n@ == self.principal@ && (
                #[trigger] decode.ensures((n,),None) || exists|p:P,v:Vec<u8>| #[trigger] decode.ensures((n,),Some(p))
                    && #[trigger] recode.ensures((&p,),v) && v@ != n@),
            (out.is_ok() || (out matches Err(Error::History(_)))) ==> exists|n:&[u8],p:P|
                n@ == self.principal@ && #[trigger] named(n,p,decode,recode) && {
                    let actual = if old(history)@.contains_key(p) {Some(old(history)@[p].0)} else {None};
                    let next = match actual {None=>0int,Some(r)=>r.generation.value() as int + 1};
                    &&& out matches Err(Error::History(e)) ==> history_reason(actual,self.expected,self.replacement,e)
                    &&& out.is_ok() == (actual == self.expected && self.replacement.generation.value() == next)
                    &&& out matches Err(Error::History(e)) ==> history_reason(actual,self.expected,self.replacement,e)
                    &&& out.is_ok() ==> final(history)@ == old(history)@.insert(p,(self.replacement,at))
                },
    {
        let name = self.principal.as_slice();
        let canonical = encode(name,scheme,self.expected,self.replacement).ok_or(Error::Length)?;
        if canonical.as_slice() != payload {return Err(Error::Noncanonical);}
        assert(canonical@ =~= payload@);
        let Some(owner)=history::principal(name,decode,recode) else {
                assert(rejected_name(name,decode,recode));
                assert(invalid_name(self.principal@,decode,recode));
            return Err(Error::Principal);
        };
        assert(named(name,owner,decode,recode));
        let result = history::apply(history,owner,self.expected,self.replacement,at);
        match result { Ok(())=>Ok(()), Err(reason)=>{assert(replay_refused(*self,payload@,scheme,old(history)@,decode,recode,Error::History(reason)));Err(Error::History(reason))} }
    }
}
}
