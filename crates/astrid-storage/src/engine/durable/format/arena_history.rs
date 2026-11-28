//! Fold the authenticated arena frames visited during native recovery.
#[cfg(verus_keep_ghost)]
use super::recovered_record;
use super::{
    ArenaLocation, ObjectId, ObjectRecord,
    frame_repair::FrameReader,
    frame_scan::Visitor,
    recovered_record::{ArenaIndex, IndexError},
    root_wire::Scheme,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use {
    super::frame_scan::Call,
    vstd::laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
};

verus! {
pub(super) struct History<I,H> {
    index:ArenaIndex,scheme:Scheme,identify:I,checksum:H,
    #[cfg(verus_keep_ghost)]
    calls:Ghost<Seq<Call>>,
}

pub(super) open spec fn step<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    call:Call,prior:Map<ObjectId,ArenaLocation>,entries:Map<ObjectId,ArenaLocation>,loc:ArenaLocation,scheme:Scheme,identify:I,checksum:H) -> bool
{
    let (at,body)=call;
    &&& loc.offset==at && loc.payload_len==body.len()
    &&& exists|b:&[u8]| b@==body && #[trigger] checksum.ensures((loc.payload_len,b),loc.checksum)
    &&& exists|id:ObjectId| #[trigger] recovered_record::authenticated(body,scheme,id,identify) &&
        if prior.contains_key(id) {recovered_record::agrees(prior[id],loc) && entries==prior}
        else {entries==prior.insert(id,loc)}
}

proof fn accepted_step<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(at:u64,data:&[u8],prior:Map<ObjectId,ArenaLocation>,entries:Map<ObjectId,ArenaLocation>,loc:ArenaLocation,id:ObjectId,scheme:Scheme,identify:I,checksum:H)
    requires loc.offset==at,loc.payload_len==data.len(),checksum.ensures((loc.payload_len,data),loc.checksum),
        recovered_record::authenticated(data@,scheme,id,identify),
        if prior.contains_key(id) {recovered_record::agrees(prior[id],loc) && entries==prior} else {entries==prior.insert(id,loc)},
    ensures step((at,data@),prior,entries,loc,scheme,identify,checksum),
{
    assert(exists|k:ObjectId| #[trigger] recovered_record::authenticated(data@,scheme,k,identify) &&
        if prior.contains_key(k) {recovered_record::agrees(prior[k],loc) && entries==prior} else {entries==prior.insert(k,loc)});
    assert(exists|b:&[u8]| b@==data@ && #[trigger] checksum.ensures((loc.payload_len,b),loc.checksum));
}

#[cfg(verus_keep_ghost)]
type State=(Map<ObjectId,ArenaLocation>,Option<ArenaLocation>);

spec fn sequence<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    calls:Seq<Call>,states:Seq<State>,last:State,scheme:Scheme,identify:I,checksum:H) -> bool
{
    &&& states.len()==calls.len()+1 && states[0]==(Map::<ObjectId,ArenaLocation>::empty(),None::<ArenaLocation>)
    &&& states.last()==last
    &&& forall|j:int| 0<=j<calls.len() ==> (#[trigger] states[j+1]).1.is_some() &&
        step(calls[j],states[j].0,states[j+1].0,states[j+1].1.unwrap(),scheme,identify,checksum)
}

pub(super) closed spec fn folded<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    calls:Seq<Call>,entries:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,scheme:Scheme,identify:I,checksum:H) -> bool
{
    exists|states:Seq<State>| #[trigger] sequence(calls,states,(entries,tail),scheme,identify,checksum)
}

pub(super) proof fn empty<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    map:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,scheme:Scheme,identify:I,checksum:H)
    requires folded(Seq::empty(),map,tail,scheme,identify,checksum),
    ensures map==Map::<ObjectId,ArenaLocation>::empty(),tail.is_none(),
{
    let states=choose|s:Seq<State>| #[trigger] sequence(Seq::empty(),s,(map,tail),scheme,identify,checksum);
    assert(states[0]==states.last());
}

pub(super) open spec fn placement<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    call:Call,key:ObjectId,loc:ArenaLocation,scheme:Scheme,identify:I,checksum:H) -> bool
{
    &&& loc.offset==call.0 && loc.payload_len==call.1.len()
    &&& recovered_record::authenticated(call.1,scheme,key,identify)
    &&& exists|b:&[u8]| b@==call.1 && #[trigger] checksum.ensures((loc.payload_len,b),loc.checksum)
}

proof fn placement_at<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    calls:Seq<Call>,s:Seq<State>,n:nat,key:ObjectId,scheme:Scheme,identify:I,checksum:H)
    requires sequence(calls,s,s.last(),scheme,identify,checksum),n<=calls.len(),s[n as int].0.contains_key(key),
    ensures exists|j:int| 0<=j<n && #[trigger] placement(calls[j],key,s[n as int].0[key],scheme,identify,checksum),
    decreases n,
{
    if n==0 {assert(false);return;}
    let j=n as int-1;
    let prior=s[j].0;
    let next=s[j+1].0;
    let loc=s[j+1].1.unwrap();
    assert(step(calls[j],prior,next,loc,scheme,identify,checksum));
    let id=choose|id:ObjectId| #[trigger] recovered_record::authenticated(calls[j].1,scheme,id,identify) &&
        if prior.contains_key(id) {recovered_record::agrees(prior[id],loc) && next==prior}
        else {next==prior.insert(id,loc)};
    if prior.contains_key(key) {
        assert(prior[key]==next[key]);
        placement_at(calls,s,j as nat,key,scheme,identify,checksum);
    } else {
        assert(id==key && loc==next[key]);
        assert(placement(calls[j],key,loc,scheme,identify,checksum));
    }
}

pub(super) proof fn locate<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    calls:Seq<Call>,map:Map<ObjectId,ArenaLocation>,tail:Option<ArenaLocation>,key:ObjectId,scheme:Scheme,identify:I,checksum:H)
    requires folded(calls,map,tail,scheme,identify,checksum),map.contains_key(key),
    ensures exists|j:int| 0<=j<calls.len() && #[trigger] placement(calls[j],key,map[key],scheme,identify,checksum),
{
    let s=choose|s:Seq<State>| #[trigger] sequence(calls,s,(map,tail),scheme,identify,checksum);
    placement_at(calls,s,calls.len(),key,scheme,identify,checksum);
}

proof fn advance<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    calls:Seq<Call>,call:Call,prior:Map<ObjectId,ArenaLocation>,previous:Option<ArenaLocation>,
    next:Map<ObjectId,ArenaLocation>,loc:ArenaLocation,scheme:Scheme,identify:I,checksum:H)
    requires folded(calls,prior,previous,scheme,identify,checksum), step(call,prior,next,loc,scheme,identify,checksum),
    ensures folded(calls.push(call),next,Some(loc),scheme,identify,checksum),
{
    let s=choose|s:Seq<State>| #[trigger] sequence(calls,s,(prior,previous),scheme,identify,checksum);
    let v=s.push((next,Some(loc)));
    let t=calls.push(call);
    assert forall|j:int| 0<=j<t.len() implies (#[trigger] v[j+1]).1.is_some() &&
        step(t[j],v[j].0,v[j+1].0,v[j+1].1.unwrap(),scheme,identify,checksum) by {
        if j<calls.len() { assert(s[j+1]==v[j+1]); } else { assert(j==calls.len()); }
    }
    assert(sequence(t,v,(next,Some(loc)),scheme,identify,checksum));
}

pub(super) open spec fn refusal<I:Fn(&ObjectRecord)->ObjectId,H:Fn(u64,&[u8])->[u8;32]>(
    entries:Map<ObjectId,ArenaLocation>,body:Seq<u8>,scheme:Scheme,identify:I,checksum:H,e:IndexError) -> bool {
    match e {
        IndexError::Record(err)=>recovered_record::refused(body,scheme,identify,err),
        IndexError::Collision(id)=>entries.contains_key(id) && recovered_record::authenticated(body,scheme,id,identify) &&
            exists|b:&[u8],sum:[u8;32]| b@==body && #[trigger] checksum.ensures((body.len() as u64,b),sum) &&
                (entries[id].payload_len!=body.len() || entries[id].checksum!=sum),
    }
}

impl<I:Fn(&ObjectRecord)->ObjectId+Copy,H:Fn(u64,&[u8])->[u8;32]+Copy> History<I,H> {
    pub(super) closed spec fn valid(&self) -> bool {
        &&& self.index.valid() && obeys_cmp::<ObjectId>() && obeys_cmp_concrete_eq::<ObjectId>()
        &&& forall|r:&ObjectRecord| #[trigger] self.identify.requires((r,))
        &&& forall|n:u64,b:&[u8]| #[trigger] self.checksum.requires((n,b))
        &&& folded(self.calls@,self.index.entries(),self.index.tail(),self.scheme,self.identify,self.checksum)
    }
    pub(super) fn new(scheme:Scheme,identify:I,checksum:H) -> (v:Self)
        requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
            forall|n:u64,b:&[u8]| #[trigger] checksum.requires((n,b)),
        ensures v.valid(), v.trace()==Seq::<Call>::empty(),v.settings()==(scheme,identify,checksum),
    {
        proof {
            let initial:State=(Map::empty(),None);
            assert(sequence(Seq::empty(),seq![initial],initial,scheme,identify,checksum));
        }
        Self{index:ArenaIndex::new(),scheme,identify,checksum,#[cfg(verus_keep_ghost)] calls:Ghost(Seq::empty())}
    }
    pub(super) closed spec fn state(&self) -> (Map<ObjectId,ArenaLocation>,Option<ArenaLocation>) {
        (self.index.entries(),self.index.tail())
    }
    pub(super) proof fn certificate(&self)
        requires self.valid(),
        ensures folded(self.trace(),self.state().0,self.state().1,self.settings().0,self.settings().1,self.settings().2),
    {}
    pub(super) closed spec fn trace(&self) -> Seq<Call> {self.calls@}
    pub(super) closed spec fn settings(&self) -> (Scheme,I,H) {(self.scheme,self.identify,self.checksum)}
    pub(super) fn finish(self) -> (out:(BTreeMap<ObjectId,ArenaLocation>,Option<ArenaLocation>))
        requires self.valid(),
        ensures vstd::std_specs::btree::btree_map_inv(&out.0),
            folded(self.trace(),out.0@,out.1,self.settings().0,self.settings().1,self.settings().2),
    {self.index.finish()}
}

impl<R:FrameReader,I:Fn(&ObjectRecord)->ObjectId+Copy,H:Fn(u64,&[u8])->[u8;32]+Copy> Visitor<R> for History<I,H> {
    type Error=IndexError;
    open spec fn ready(&self) -> bool {self.valid()}
    open spec fn calls(&self) -> Seq<Call> {self.trace()}
    #[cfg(verus_keep_ghost)]
    type Config=(Scheme,I,H);
    open spec fn config(&self) -> Self::Config {self.settings()}
    open spec fn refused(&self,prior:&Self,body:Seq<u8>,e:IndexError) -> bool {
        self.state()==prior.state() && refusal(prior.state().0,body,self.settings().0,self.settings().1,self.settings().2,e)
    }
    fn visit(&mut self,_reader:&mut R,at:u64,data:&[u8]) -> (out:Result<(),IndexError>) {
        let result=self.index.accept(at,data,self.scheme,self.identify,self.checksum);
        #[cfg(verus_keep_ghost)]
        {
            self.calls=Ghost(self.calls@.push((at,data@)));
            proof {
                assert(self.calls@.drop_last() =~= old(self).calls@);
                if result.is_ok() {
                    let prior=old(self).index.entries();
                    let loc=self.index.tail().unwrap();
                    let id=choose|id:ObjectId| #[trigger] recovered_record::authenticated(data@,self.scheme,id,self.identify) &&
                        if prior.contains_key(id) {recovered_record::agrees(prior[id],loc) && self.index.entries()==prior}
                        else {self.index.entries()==prior.insert(id,loc)};
                    assert(recovered_record::authenticated(data@,self.scheme,id,self.identify));
                    assert(self.checksum.ensures((loc.payload_len,data),loc.checksum));
                    assert(self.calls@.last()==(at,data@));
                    accepted_step(at,data,prior,self.index.entries(),loc,id,self.scheme,self.identify,self.checksum);
                    advance(old(self).calls@,(at,data@),prior,old(self).index.tail(),self.index.entries(),loc,self.scheme,self.identify,self.checksum);
                } else if let Err(IndexError::Collision(id))=result {
                    let sum=choose|sum:[u8;32]| #[trigger] self.checksum.ensures((data.len() as u64,data),sum) &&
                        (old(self).index.entries()[id].payload_len!=data.len() || old(self).index.entries()[id].checksum!=sum);
                    assert(self.checksum.ensures((data.len() as u64,data),sum));
                }
                if let Err(ref e)=result {
                    assert(refusal(old(self).state().0,data@,self.scheme,self.identify,self.checksum,*e));
                }
            }
        }
        result
    }
}
}
