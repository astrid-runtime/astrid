//! Accumulate the snapshot and deltas from authenticated checkpoint frames.
use super::{
    IndexState, checkpoint_wire as wire, frame_repair::FrameReader, frame_scan::Visitor,
    root_wire::Scheme,
};
#[cfg(verus_keep_ghost)]
use super::{ObjectId, frame_scan::Call};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(super) struct History<V> {
    state: Option<IndexState>,
    scheme: Scheme,
    validate: V,
    #[cfg(verus_keep_ghost)]
    calls: Ghost<Seq<Call>>,
    #[cfg(verus_keep_ghost)]
    states: Ghost<Seq<IndexState>>,
}

pub(super) open spec fn step<E,V:Fn(&IndexState,u64)->Result<(),E>>(call:Call,prior:Option<IndexState>,
    next:IndexState,scheme:Scheme,validate:V) -> bool {
    let (at,b)=call;
    &&& b.len()>0
    &&& match prior {
        None=>b[0]==wire::SNAPSHOT_RECORD && wire::snapshot_at(b,1,b.len() as int,scheme,next) &&
            validate.ensures((&next,at),Ok(())),
        Some(old)=>b[0]==wire::DELTA_RECORD && exists|add:IndexState| #[trigger] validate.ensures((&add,at),Ok(())) &&
            wire::delta_at(b,1,b.len() as int,scheme,old,add,next),
    }
}

pub(super) open spec fn chain<E,V:Fn(&IndexState,u64)->Result<(),E>>(calls:Seq<Call>,states:Seq<IndexState>,scheme:Scheme,validate:V) -> bool {
    &&& calls.len()==states.len()
    &&& forall|i:int| 0<=i<calls.len() ==> step(#[trigger] calls[i],if i==0 {None} else {Some(states[i-1])},states[i],scheme,validate)
}

impl<E,V:Fn(&IndexState,u64)->Result<(),E>+Copy> History<V> {
    pub(super) closed spec fn valid(&self) -> bool {
        &&& obeys_cmp::<ObjectId>() && obeys_cmp_concrete_eq::<ObjectId>()
        &&& forall|s:&IndexState,at:u64| #[trigger] self.validate.requires((s,at))
        &&& chain(self.calls@,self.states@,self.scheme,self.validate)
        &&& self.state.is_some()==(self.states@.len()>0)
        &&& self.state matches Some(s) ==> s==self.states@.last() && btree_map_inv(&s.objects)
    }
    pub(super) closed spec fn trace(&self) -> Seq<Call> {self.calls@}
    pub(super) closed spec fn settings(&self) -> (Scheme,V) {(self.scheme,self.validate)}

    pub(super) fn new(scheme:Scheme,validate:V) -> (out:Self)
        requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),forall|s:&IndexState,at:u64| #[trigger] validate.requires((s,at)),
        ensures out.valid(),out.trace()==Seq::<Call>::empty(),out.settings()==(scheme,validate),
    {
        Self {state:None,scheme,validate,
            #[cfg(verus_keep_ghost)] calls:Ghost(Seq::empty()),
            #[cfg(verus_keep_ghost)] states:Ghost(Seq::empty())}
    }

    pub(super) fn finish(self) -> (out:Option<IndexState>)
        requires self.valid(),
        ensures out.is_some()==(self.trace().len()>0),
            out matches Some(s) ==> btree_map_inv(&s.objects) && exists|states:Seq<IndexState>|
                #[trigger] chain(self.trace(),states,self.settings().0,self.settings().1) && states.last()==s,
    {
        proof {
            assert(chain(self.trace(),self.states@,self.settings().0,self.settings().1));
            if self.state.is_some() {assert(self.states@.last()==self.state.unwrap());}
        }
        self.state
    }
}

impl<R:FrameReader,E,V:Fn(&IndexState,u64)->Result<(),E>+Copy> Visitor<R> for History<V> {
    type Error=wire::RecordError<E>;
    open spec fn ready(&self) -> bool {self.valid()}
    open spec fn calls(&self) -> Seq<Call> {self.trace()}
    #[cfg(verus_keep_ghost)]
    type Config=(Scheme,V);
    open spec fn config(&self) -> Self::Config {self.settings()}
    closed spec fn refused(&self,_prior:&Self,_body:Seq<u8>,_e:Self::Error) -> bool {self.state.is_none()}

    fn visit(&mut self,_reader:&mut R,at:u64,bytes:&[u8]) -> (out:Result<(),Self::Error>) {
        let validate=self.validate;
        let check=|s:&IndexState| -> (r:Result<(),E>) ensures validate.ensures((s,at),r), {validate(s,at)};
        let prior=self.state.take();
        let ghost before=prior;
        #[cfg(verus_keep_ghost)]
        {self.calls=Ghost(self.calls@.push((at,bytes@)));}
        let next=wire::record(bytes,prior,self.scheme,check)?;
        #[cfg(verus_keep_ghost)]
        {
            let ghost extended=self.states@.push(next);
            proof {
                if let Some(old)=before {
                    let add=choose|v:IndexState| #[trigger] check.ensures((&v,),Ok(())) && wire::delta_at(bytes@,1,bytes.len() as int,self.scheme,old,v,next);
                    assert(validate.ensures((&add,at),Ok(())));
                }
                assert(step((at,bytes@),before,next,self.scheme,validate));
                assert forall|i:int| 0<=i<self.calls@.len() implies step(#[trigger] self.calls@[i],
                    if i==0 {None} else {Some(extended[i-1])},extended[i],self.scheme,validate) by {
                    if i<old(self).trace().len() {
                        assert(self.calls@[i]==old(self).trace()[i]);
                        assert(step(old(self).trace()[i],if i==0 {None} else {Some(self.states@[i-1])},self.states@[i],self.scheme,validate));
                    } else {assert(i==old(self).trace().len());}
                }
            }
            self.states=Ghost(extended);
        }
        self.state=Some(next);
        Ok(())
    }
}
}
