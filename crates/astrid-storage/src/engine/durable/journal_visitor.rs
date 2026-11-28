//! The map accumulated by native startup as it scans root-journal frames.
use super::{
    RootState,
    frame_repair::FrameReader,
    frame_scan::Visitor,
    journal_apply::{self, VisitError},
    root_wire,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use {
    super::frame_scan::Call,
    vstd::{
        laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
        std_specs::btree::btree_map_inv,
    },
};

verus! {
pub(super) struct RootHistory<P:Ord,D,C> {
    table:BTreeMap<P,(RootState,u64)>,scheme:root_wire::Scheme,decode:D,recode:C,
    #[cfg(verus_keep_ghost)]
    calls:Ghost<Seq<(u64,Seq<u8>)>>,
    #[cfg(verus_keep_ghost)]
    states:Ghost<Seq<Map<P,(RootState,u64)>>>,
}

#[cfg(verus_keep_ghost)]
pub(super) struct Model<P,D,C> {
    pub(super) table:Map<P,(RootState,u64)>,pub(super) scheme:root_wire::Scheme,pub(super) decode:D,pub(super) recode:C,
    pub(super) calls:Seq<Call>,pub(super) states:Seq<Map<P,(RootState,u64)>>,
}

impl<P:Ord,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy> RootHistory<P,D,C> {
    pub(super) closed spec fn model(&self) -> Model<P,D,C> {
        Model {table:self.table@,scheme:self.scheme,decode:self.decode,recode:self.recode,calls:self.calls@,states:self.states@}
    }

    pub(super) closed spec fn valid(&self) -> bool {
        &&& btree_map_inv(&self.table) && obeys_cmp::<P>() && obeys_cmp_concrete_eq::<P>()
        &&& forall|b:&[u8]| #[trigger] self.decode.requires((b,))
        &&& forall|p:&P| #[trigger] self.recode.requires((p,))
        &&& self.states@.len()==self.calls@.len()+1 && self.states@[0]==Map::<P,(RootState,u64)>::empty()
        &&& self.states@.last()==self.table@
        &&& forall|i:int| 0<=i<self.calls@.len() ==> #[trigger] journal_apply::step(self.calls@[i].1,self.calls@[i].0,self.scheme,
            self.states@[i],self.states@[i+1],self.decode,self.recode)
    }

    pub(super) proof fn certificate(&self)
        requires self.valid(),
        ensures {
            let m=self.model();
            &&& m.states.len()==m.calls.len()+1 && m.states[0]==Map::<P,(RootState,u64)>::empty()
            &&& m.table==m.states.last()
            &&& forall|i:int| 0<=i<m.calls.len() ==> #[trigger] journal_apply::step(m.calls[i].1,m.calls[i].0,m.scheme,
                m.states[i],m.states[i+1],m.decode,m.recode)
        },
    {}

    pub(super) fn new(scheme:root_wire::Scheme,decode:D,recode:C) -> (s:Self)
        requires obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        ensures s.valid(),s.model().calls==Seq::<Call>::empty(),s.model().scheme==scheme,s.model().decode==decode,s.model().recode==recode,
    {
        let ghost initial:Seq<Map<P,(RootState,u64)>>=seq![Map::empty()];
        Self {table:BTreeMap::new(),scheme,decode,recode,#[cfg(verus_keep_ghost)] calls:Ghost(Seq::empty()),#[cfg(verus_keep_ghost)] states:Ghost(initial)}
    }

    pub(super) fn add(&mut self,offset:u64,bytes:&[u8]) -> (out:Result<(),VisitError>)
        requires old(self).valid(),
        ensures final(self).model().calls==old(self).model().calls.push((offset,bytes@)),final(self).model().scheme==old(self).model().scheme,
            final(self).model().decode==old(self).model().decode,final(self).model().recode==old(self).model().recode,
            out.is_ok() ==> final(self).valid() && final(self).model().states==old(self).model().states.push(final(self).model().table),
            out matches Err(e) ==> journal_apply::refusal(bytes@,old(self).model().scheme,e),
            out.is_err() ==> final(self).model().table==old(self).model().table && final(self).model().states==old(self).model().states,
    {
        let result=journal_apply::offer(&mut self.table,offset,bytes,self.scheme,self.decode,self.recode);
        #[cfg(verus_keep_ghost)]
        {
        self.calls=Ghost(self.calls@.push((offset,bytes@)));
        if result.is_ok() {
            self.states=Ghost(self.states@.push(self.table@));
            proof {
                assert forall|i:int| 0<=i<self.calls@.len() implies #[trigger] journal_apply::step(self.calls@[i].1,self.calls@[i].0,self.scheme,
                    self.states@[i],self.states@[i+1],self.decode,self.recode) by {
                    if i<old(self).calls@.len() {
                        assert(journal_apply::step(old(self).calls@[i].1,old(self).calls@[i].0,old(self).scheme,
                            old(self).states@[i],old(self).states@[i+1],old(self).decode,old(self).recode));
                    }
                }
            }
        }
        }
        result
    }

    pub(super) fn finish(self) -> (table:BTreeMap<P,(RootState,u64)>)
        requires self.valid(),ensures table@==self.model().states.last() && btree_map_inv(&table),
    {self.table}
}

impl<R:FrameReader,P:Ord,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy> Visitor<R> for RootHistory<P,D,C> {
    type Error=VisitError;
    open spec fn ready(&self) -> bool {self.valid()}
    open spec fn calls(&self) -> Seq<Call> {self.model().calls}
    #[cfg(verus_keep_ghost)]
    type Config=(root_wire::Scheme,D,C);
    open spec fn config(&self) -> Self::Config {(self.model().scheme,self.model().decode,self.model().recode)}
    open spec fn refused(&self,prior:&Self,bytes:Seq<u8>,e:VisitError) -> bool {
        &&& self.model().states==prior.model().states && self.model().table==prior.model().table
        &&& journal_apply::refusal(bytes,prior.model().scheme,e)
    }
    fn visit(&mut self,_reader:&mut R,at:u64,bytes:&[u8]) -> Result<(),VisitError> {self.add(at,bytes)}
}
}
