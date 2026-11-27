//! Carry a prepared physical identity to its appended arena location.
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

verus! {

#[derive(Clone, Debug)]
pub(super) struct Prepared<K,B> {
    object: K,
    blob: B,
    canonical_length: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Placed<K,B,L> {
    pub(super) object: K,
    pub(super) blob: B,
    pub(super) canonical_length: u64,
    pub(super) location: L,
}

impl<K,B> Prepared<K,B> {
    pub(super) closed spec fn fields(self) -> (K,B,u64) {
        (self.object,self.blob,self.canonical_length)
    }

    /// Identify the exact canonical body before the arena offset is available.
    pub(super) fn from_bytes<P,E,F:FnOnce(P,&[u8])->Result<B,E>>(
        object:K, profile:P, bytes:&[u8], identify:F,
    ) -> (out:Result<Self,E>)
        requires identify.requires((profile,bytes)),
        ensures match out {
            Ok(prepared) => prepared.fields().0 == object && prepared.fields().2 == bytes.len() &&
                identify.ensures((profile,bytes),Ok(prepared.fields().1)),
            Err(error) => identify.ensures((profile,bytes),Err(error)),
        },
    {
        let blob = identify(profile,bytes)?;
        Ok(Self {object, blob, canonical_length:bytes.len() as u64})
    }

    pub(super) fn place<L>(self, location:L) -> (out:Placed<K,B,L>)
        ensures out.object == self.fields().0 && out.blob == self.fields().1 &&
            out.canonical_length == self.fields().2 && out.location == location,
    {
        Placed {object:self.object, blob:self.blob, canonical_length:self.canonical_length, location}
    }
}

/// An absent description leaves the catalogue alone. A present description
/// installs only under the object name carried by that description.
pub(super) fn install<K:Ord+Copy,B,L>(
    direct:&mut BTreeMap<K,Placed<K,B,L>>, prepared:Option<Prepared<K,B>>, location:L,
)
    requires btree_map_inv(old(direct)), obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(),
    ensures btree_map_inv(final(direct)),
        match prepared {
            None => final(direct)@ == old(direct)@,
            Some(p) => {
                let (object,blob,length) = p.fields();
                final(direct)@ == old(direct)@.insert(object,Placed {
                    object,blob,canonical_length:length,location
                })
            },
        },
{
    if let Some(description) = prepared {
        let placed = description.place(location);
        direct.insert(placed.object,placed);
    }
}

pub(super) open spec fn catalogue<K,B,L>(prior:Map<K,Placed<K,B,L>>, prepared:Seq<Option<Prepared<K,B>>>,
    locations:Seq<L>, n:nat) -> Map<K,Placed<K,B,L>>
    decreases n,
{
    if n == 0 { prior } else {
        let map = catalogue(prior,prepared,locations,(n-1) as nat);
        match prepared[n-1] {
            None => map,
            Some(p) => {
                let (object,blob,canonical_length) = p.fields();
                map.insert(object,Placed {object,blob,canonical_length,location:locations[n-1]})
            },
        }
    }
}

/// Publish the same append positions into all three in-memory structures.
pub(super) fn install_appended<K:Ord+Copy,B,L:Copy>(
    index:&mut BTreeMap<K,L>, delta:&mut Vec<(K,L)>, direct:&mut BTreeMap<K,Placed<K,B,L>>,
    ids:&[K], descriptions:Vec<Option<Prepared<K,B>>>, locations:&[L],
) -> (ok:bool)
    requires obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(old(index)), btree_map_inv(old(direct)),
    ensures ok == (ids.len() == descriptions.len() && ids.len() == locations.len()),
        btree_map_inv(final(index)), btree_map_inv(final(direct)),
        if ok {
            &&& final(index)@ == super::arena_index::applied(old(index)@,ids@,locations@,ids@.len())
            &&& final(delta)@ == old(delta)@ + Seq::new(ids@.len(),|i:int| (ids@[i],locations@[i]))
            &&& final(direct)@ == catalogue(old(direct)@,descriptions@,locations@,ids@.len())
        } else {
            final(index)@ == old(index)@ && final(delta)@ == old(delta)@ && final(direct)@ == old(direct)@
        },
{
    if ids.len() != descriptions.len() || !super::arena_index::publish_batch(index,delta,ids,locations) {
        return false;
    }
    let mut iter = descriptions.into_iter();
    let mut i = 0usize;
    while i < locations.len()
        invariant obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(direct),
            i <= locations.len() == descriptions.len() == ids.len(), iter.remaining() == descriptions@.skip(i as int),
            direct@ == catalogue(old(direct)@,descriptions@,locations@,i as nat),
        decreases locations.len()-i,
    {
        let Some(description) = iter.next() else {unreachable!()};
        assert(description == descriptions@[i as int]);
        install(direct,description,locations[i]);
        assert(iter.remaining() =~= descriptions@.skip(i as int+1));
        i = i.saturating_add(1);
    }
    true
}

}
