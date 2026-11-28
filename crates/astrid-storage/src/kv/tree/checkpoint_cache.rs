//! Transaction-local decoded pages for one principal.
use super::{
    ObjectFormatVersion, ObjectId, ObjectRecord,
    checkpoint_descent::Loaded,
    checkpoint_leaf::Entry,
    checkpoint_page::{Branch, Handle, Leaf, Node},
    checkpoint_range::Child,
    checkpoint_record as record,
    checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
#[cfg(verus_keep_ghost)]
pub(super) ghost enum Slot {Inline(Seq<u8>),Spilled(ObjectId,u64)}
pub(super) open spec fn slot(v:ValueSlot) -> Slot {
    match v {ValueSlot::Inline(d) => Slot::Inline(d@),ValueSlot::Spilled {object,length} => Slot::Spilled(object,length)}
}
pub(super) open spec fn entry(e:Entry<ValueSlot>) -> (Seq<u8>,Slot) {(e.key@,slot(e.value))}
pub(super) open spec fn pointer(c:Child<ObjectId,NodeTotals>) -> (Seq<u8>,ObjectId,u16,NodeTotals) {
    (c.lower_bound@,c.object,c.level,c.totals)
}
#[cfg(verus_keep_ghost)]
pub(super) ghost enum Image {
    Leaf(Seq<(Seq<u8>,Slot)>,NodeTotals),
    Branch(u16,Seq<(Seq<u8>,ObjectId,u16,NodeTotals)>,NodeTotals),
}
pub(super) open spec fn image(h:Loaded) -> (ObjectId,Image) {
    (h.object,match h.node {
        Node::Leaf(l) => Image::Leaf(l.entries@.map(|i:int,e| entry(e)),l.totals),
        Node::Branch(b) => Image::Branch(b.level,b.children@.map(|i:int,c| pointer(c)),b.totals),
    })
}

fn owned(h:&Loaded) -> (out:Loaded)
    ensures image(out) == image(*h), record::ordered(h.node) ==> record::ordered(out.node),
{
    let node = match &h.node {
        Node::Leaf(l) => {
            let mut entries = Vec::<Entry<ValueSlot>>::with_capacity(l.entries.len());
            let mut i = 0usize;
            while i < l.entries.len()
                invariant i <= l.entries.len(),entries.len() == i,
                    forall|j:int| 0 <= j < i ==> entry(#[trigger] entries@[j]) == entry(l.entries@[j]),
                decreases l.entries.len()-i,
            {
                let e = &l.entries[i];
                let value = match &e.value {
                    ValueSlot::Inline(data) => ValueSlot::Inline(data.clone()),
                    ValueSlot::Spilled {object,length} => ValueSlot::Spilled {object:*object,length:*length},
                };
                entries.push(Entry {key:e.key.clone(),value});
                i = i.saturating_add(1);
            }
            assert(entries@.map(|i:int,e| entry(e)) =~= l.entries@.map(|i:int,e| entry(e)));
            assert forall|j:int| 1 <= j < entries.len() && super::checkpoint_leaf_summary::ordered(l.entries@,l.entries.len() as nat)
                implies super::encoding::below(entries@[j-1].key@,(#[trigger] entries@[j]).key@) by {
                assert(entry(entries@[j-1]) == entry(l.entries@[j-1]));
            }
            Node::Leaf(Leaf {entries,totals:l.totals})
        },
        Node::Branch(b) => {
            let mut children = Vec::<Child<ObjectId,NodeTotals>>::with_capacity(b.children.len());
            let mut i = 0usize;
            while i < b.children.len()
                invariant i <= b.children.len(),children.len() == i,
                    forall|j:int| 0 <= j < i ==> pointer(#[trigger] children@[j]) == pointer(b.children@[j]),
                decreases b.children.len()-i,
            {
                let c = &b.children[i];
                children.push(Child {lower_bound:c.lower_bound.clone(),object:c.object,level:c.level,totals:c.totals});
                i = i.saturating_add(1);
            }
            assert(children@.map(|i:int,c| pointer(c)) =~= b.children@.map(|i:int,c| pointer(c)));
            assert forall|j:int| 1 <= j < children.len() && super::checkpoint_summary::ordered(b.children@,b.children.len() as nat)
                implies super::encoding::below(children@[j-1].lower_bound@,(#[trigger] children@[j]).lower_bound@) by {
                assert(pointer(children@[j-1]) == pointer(b.children@[j-1]));
            }
            Node::Branch(Branch {children,level:b.level,totals:b.totals})
        },
    };
    Handle {object:h.object,node}
}

pub(super) struct Cache<'a,P> {principal:&'a P,pages:BTreeMap<ObjectId,Loaded>}
pub(super) enum Error<E> {Load(E),Decode(record::ReadError<E>)}

impl<'a,P> Cache<'a,P> {
    pub(super) closed spec fn contents(&self) -> Map<ObjectId,Loaded> {self.pages@}
    pub(super) closed spec fn owner(&self) -> &'a P { self.principal }
    pub(super) closed spec fn valid(&self) -> bool {
        btree_map_inv(&self.pages) && forall|id:ObjectId| self.pages@.contains_key(id) ==>
            (#[trigger] self.pages@[id]).object == id && record::ordered(self.pages@[id].node)
    }
    pub(super) fn new(principal:&'a P) -> (c:Self)
        ensures c.valid(), c.contents() == Map::<ObjectId,Loaded>::empty(), c.owner() == principal,
    { Self {principal,pages:BTreeMap::new()} }

    pub(super) fn principal(&self) -> (p:&'a P) ensures p == self.owner(), { self.principal }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {self.pages.is_empty()}

    pub(super) fn admit<E,V:Fn(&[u8])->Result<(),E>+Copy>(&mut self,id:ObjectId,r:&ObjectRecord,
        version:ObjectFormatVersion,validate:V) -> (out:Result<Loaded,record::ReadError<E>>)
        requires old(self).valid(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            forall|k:&[u8]| #[trigger] validate.requires((k,)),
        ensures final(self).valid(), final(self).owner() == old(self).owner(),
            (out matches Err(record::ReadError::Envelope(record::EnvelopeError::Header))) ==
                (r.contents().1 != version.number() || r.contents().4 != 0 || r.contents().5 != super::ObjectClass::Metadata),
            (out matches Err(record::ReadError::Envelope(record::EnvelopeError::Kind))) ==
                (r.contents().1 == version.number() && r.contents().4 == 0 && r.contents().5 == super::ObjectClass::Metadata &&
                    !(r.contents().0 is KvLeaf) && !(r.contents().0 is KvBranch)),
            match out {
                Ok(h) => h.node is Leaf == (r.contents().0 == super::ObjectKind::KvLeaf) && h.object == id && record::ordered(h.node) && record::parsed(r,h.node,validate) && r.contents().1 == version.number() &&
                    exists|cached:Loaded| #[trigger] image(cached) == image(h) &&
                        final(self).contents() == old(self).contents().insert(id,cached),
                Err(e) => final(self).contents() == old(self).contents() && record::refusal(r,validate,e),
            },
    {
        let h = record::read(id,r,version,validate)?;
        let copy = owned(&h);
        self.pages.insert(id,copy);
        Ok(h)
    }

    pub(super) fn lookup<E,L:FnOnce(&P,ObjectId)->Result<ObjectRecord,E>,V:Fn(&[u8])->Result<(),E>+Copy>(
        &mut self,id:ObjectId,version:ObjectFormatVersion,load:L,validate:V) -> (out:Result<Loaded,Error<E>>)
        requires old(self).valid(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            load.requires((old(self).owner(),id)),forall|k:&[u8]| #[trigger] validate.requires((k,)),
        ensures final(self).valid(),final(self).owner() == old(self).owner(),
            out matches Ok(h) ==> h.object == id && record::ordered(h.node) && final(self).contents().contains_key(id) &&
                image(final(self).contents()[id]) == image(h),
            if old(self).contents().contains_key(id) {
                final(self).contents() == old(self).contents() && out.is_ok()
            } else {match out {
                Ok(h) => exists|r:ObjectRecord| #[trigger] load.ensures((old(self).owner(),id),Ok(r)) &&
                    record::parsed(&r,h.node,validate) && r.contents().1 == version.number(),
                Err(Error::Load(e)) => final(self).contents() == old(self).contents() && load.ensures((old(self).owner(),id),Err(e)),
                Err(Error::Decode(e)) => final(self).contents() == old(self).contents() &&
                    exists|r:ObjectRecord| #[trigger] load.ensures((old(self).owner(),id),Ok(r)) && record::refusal(&r,validate,e),
            }},
            forall|other:ObjectId| other != id ==> #[trigger] final(self).contents().contains_key(other) == old(self).contents().contains_key(other) &&
                (old(self).contents().contains_key(other) ==> final(self).contents()[other] == old(self).contents()[other]),
    {
        if let Some(h) = self.pages.get(&id) {return Ok(owned(h));}
        let r = match load(self.principal,id) {Ok(r) => r,Err(e) => return Err(Error::Load(e))};
        match self.admit(id,&r,version,validate) {Ok(h) => Ok(h),Err(e) => Err(Error::Decode(e))}
    }
}
}
