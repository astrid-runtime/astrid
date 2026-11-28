//! Root selection and FIFO eviction for a published owner snapshot.
use super::{
    RootState,
    hot_lookup::{self, CachedValue},
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_deep_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
const ENTRY_ACCOUNTING_BYTES:usize = 128;
#[derive(Clone)]
pub(super) struct OwnerSnapshot {
    pub(super) root:Option<RootState>,
    pub(super) entries:BTreeMap<Vec<u8>,CachedValue>,
    pub(super) insertion_order:VecDeque<Vec<u8>>,
    pub(super) resident_bytes:usize,
}

impl OwnerSnapshot {
    pub(super) open spec fn vacant(&self,root:Option<RootState>) -> bool {
        &&& self.root == root
        &&& btree_map_inv(&self.entries)
        &&& self.entries.deep_view() == Map::<Seq<u8>,Option<Seq<u8>>>::empty()
        &&& self.insertion_order@ == Seq::<Vec<u8>>::empty()
        &&& self.resident_bytes == 0
    }

    pub(super) fn empty(root:Option<RootState>) -> (out:Self)
        ensures out.vacant(root),
    {
        let entries = BTreeMap::new();
        proof {
            vstd::std_specs::btree::lemma_btree_map_deepview_dom(entries);
            assert(entries.deep_view().dom() =~= Set::<Seq<u8>>::empty());
            assert(entries.deep_view() =~= Map::<Seq<u8>,Option<Seq<u8>>>::empty());
        }
        Self {root,entries,insertion_order:VecDeque::new(),resident_bytes:0}
    }

    pub(super) open spec fn same_image(&self,other:&Self) -> bool {
        &&& self.root == other.root
        &&& self.entries.deep_view() == other.entries.deep_view()
        &&& self.insertion_order.deep_view() == other.insertion_order.deep_view()
        &&& self.resident_bytes == other.resident_bytes
        &&& btree_map_inv(&self.entries) == btree_map_inv(&other.entries)
    }

    pub(super) fn for_root<F>(previous:Arc<Self>,root:Option<RootState>,take:F) -> (out:Self)
        where F:FnOnce(Arc<Self>)->Self,
        requires previous.root == root ==> take.requires((previous,)),
            previous.root == root ==> forall|s:Self| #[trigger] take.ensures((previous,),s) ==> s.same_image(&previous),
        ensures if previous.root == root {out.same_image(&previous)} else {out.vacant(root)},
    {
        if hot_lookup::same_root(previous.root,root) {take(previous)} else {Self::empty(root)}
    }

    pub(super) open spec fn charge(key:Seq<u8>,value:Option<Seq<u8>>) -> int {
        vstd::math::min(usize::MAX as int,128 + 2 * key.len() + match value {Some(b) => b.len() as int,None => 0})
    }

    pub(super) fn entry_bytes(key:&[u8],value:&CachedValue) -> (charge:usize)
        ensures charge as int == Self::charge(key@,value.bytes_view()),
    {
        let bytes = match value { CachedValue::Present(v) => v.len(),CachedValue::Missing => 0 };
        ENTRY_ACCOUNTING_BYTES.saturating_add(key.len().saturating_mul(2)).saturating_add(bytes)
    }

    /// Install a row under this snapshot's root and report whether its old FIFO position needs removal.
    pub(super) fn replace_row(&mut self,key:&Vec<u8>,value:CachedValue,charge:usize) -> (replaced:bool)
        requires btree_map_inv(&old(self).entries),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
        ensures btree_map_inv(&final(self).entries),final(self).root == old(self).root,
            final(self).entries.deep_view() == old(self).entries.deep_view().insert(key@,value.bytes_view()),
            replaced == old(self).entries.deep_view().contains_key(key@),
            final(self).insertion_order@ == old(self).insertion_order@,
            final(self).resident_bytes as int == vstd::math::min(usize::MAX as int,charge as int +
                if replaced {vstd::math::max(0,old(self).resident_bytes as int -
                    Self::charge(key@,old(self).entries.deep_view()[key@]))} else {old(self).resident_bytes as int}),
    {
        let old = hot_lookup::remove_row(&mut self.entries,key);
        if let Some(prior) = &old {
            self.resident_bytes = self.resident_bytes.saturating_sub(Self::entry_bytes(key,prior));
        }
        self.resident_bytes = self.resident_bytes.saturating_add(charge);
        let owned = key.clone();
        assert(owned@ =~= key@);
        hot_lookup::store_row(&mut self.entries,owned,value);
        old.is_some()
    }

    pub(super) fn remove_oldest(&mut self) -> (removed:bool)
        requires btree_map_inv(&old(self).entries),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
        ensures btree_map_inv(&final(self).entries),final(self).root == old(self).root,
            removed == (old(self).insertion_order@.len() > 0),
            if removed {
                final(self).entries.deep_view() == old(self).entries.deep_view().remove(old(self).insertion_order@[0]@) &&
                final(self).insertion_order@ == old(self).insertion_order@.skip(1)
            } else {
                final(self).entries.deep_view() == old(self).entries.deep_view() &&
                final(self).insertion_order@ == old(self).insertion_order@
            },
            final(self).resident_bytes as int == if removed && old(self).entries.deep_view().contains_key(old(self).insertion_order@[0]@) {
                let k = old(self).insertion_order@[0]@;
                vstd::math::max(0,old(self).resident_bytes as int - Self::charge(k,old(self).entries.deep_view()[k]))
            } else {old(self).resident_bytes as int},
    {
        broadcast use vstd::std_specs::btree::group_btree_axioms;
        let Some(key) = self.insertion_order.pop_front() else {return false;};
        assert(key.deep_view() =~= key@);
        if let Some(value) = hot_lookup::remove_row(&mut self.entries,&key) {
            self.resident_bytes = self.resident_bytes.saturating_sub(Self::entry_bytes(&key,&value));
        }
        true
    }

    /// Each budget pass may discard rows and keeps the surviving snapshot at the same root.
    pub(super) fn trim<F>(&mut self,over:F) where F:Fn(&Self)->bool,
        requires btree_map_inv(&old(self).entries),obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),
            forall|s:&Self| over.requires((s,)),
        ensures btree_map_inv(&final(self).entries),final(self).root == old(self).root,
            final(self).resident_bytes <= old(self).resident_bytes,
            forall|k:Seq<u8>| #[trigger] final(self).entries.deep_view().contains_key(k) ==>
                final(self).entries.deep_view().get(k) == old(self).entries.deep_view().get(k),
            !over.ensures((&*old(self),),true) ==> *final(self) == *old(self),
            final(self).insertion_order@.len() == 0 || over.ensures((&*final(self),),false),
    {
        loop
            invariant btree_map_inv(&self.entries),self.root == old(self).root,
                obeys_cmp::<Vec<u8>>(),obeys_cmp_deep_eq::<Vec<u8>>(),forall|s:&Self| over.requires((s,)),
                !over.ensures((&*old(self),),true) ==> *self == *old(self),
                self.resident_bytes <= old(self).resident_bytes,
                forall|k:Seq<u8>| #[trigger] self.entries.deep_view().contains_key(k) ==>
                    self.entries.deep_view().get(k) == old(self).entries.deep_view().get(k),
            decreases self.insertion_order@.len(),
        {
            if !over(self) || !self.remove_oldest() {return;}
        }
    }
}
}
