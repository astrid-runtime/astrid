//! Follow staging and checkpoint-index publication into the pending WAL map.
use crate::{root_wire::Scheme, verified_record as record};
use vstd::prelude::*;

verus! {

/// A later row for another key cannot change this object's physical placement.
pub(super) proof fn last_placement<K,L>(initial:Map<K,L>,keys:Seq<K>,locations:Seq<L>,row:int,n:nat)
    requires 0 <= row < n <= keys.len() == locations.len(),
        forall|j:int| row < j < n ==> #[trigger] keys[j] != keys[row],
    ensures ({
        let map = crate::arena_index::applied(initial,keys,locations,n);
        map.contains_key(keys[row]) && map[keys[row]] == locations[row]
    }),
    decreases n,
{
    if row < n-1 {
        last_placement(initial,keys,locations,row,(n-1) as nat);
        assert(keys[n-1] != keys[row]);
    }
}

type Description<B> = crate::direct_placement::Prepared<crate::ObjectId,B>;
type Direct<B,L> = crate::direct_placement::Placed<crate::ObjectId,B,L>;

proof fn last_direct<B,L>(
    initial:Map<crate::ObjectId,Direct<B,L>>, descriptions:Seq<Option<Description<B>>>, locations:Seq<L>,
    row:int,n:nat,
)
    requires 0 <= row < n <= descriptions.len() == locations.len(), descriptions[row].is_some(),
        forall|j:int| row < j < n && #[trigger] descriptions[j].is_some() ==>
            descriptions[j].unwrap().fields().0 != descriptions[row].unwrap().fields().0,
    ensures ({
        let (key,blob,length) = descriptions[row].unwrap().fields();
        let map = crate::direct_placement::catalogue(initial,descriptions,locations,n);
        map.contains_key(key) && map[key] == (Direct {object:key,blob,canonical_length:length,location:locations[row]})
    }),
    decreases n,
{
    if row < n-1 {
        last_direct(initial,descriptions,locations,row,(n-1) as nat);
        if descriptions[n-1].is_some() {
            assert(descriptions[n-1].unwrap().fields().0 != descriptions[row].unwrap().fields().0);
        }
    }
}

/// Follow the publisher's staged-first order. The selected index row is the
/// last append for this name, and the later prepared frame can never replace
/// its record, its direct metadata or its location.
fn staged_first<L:Copy,B,R,F:Fn(&Direct<B,L>)->Direct<B,L>>(
    index:&mut std::collections::BTreeMap<crate::ObjectId,L>,delta:&mut Vec<(crate::ObjectId,L)>,
    direct:&mut std::collections::BTreeMap<crate::ObjectId,Direct<B,L>>,
    descriptions:Vec<Option<Description<B>>>,
    objects:&mut std::collections::BTreeMap<crate::ObjectId,crate::overlay_object::Object<R,L,Direct<B,L>>>,
    ids:&[crate::ObjectId],locations:&[L],row:usize,
    staged:std::sync::Arc<[u8]>,record:R,prepared:std::sync::Arc<[u8]>,other:R,copy:F,
) -> (accepted:bool)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        vstd::std_specs::btree::btree_map_inv(old(index)), vstd::std_specs::btree::btree_map_inv(old(direct)),
        vstd::std_specs::btree::btree_map_inv(old(objects)), ids.len() == locations.len(), row < ids.len(),
        descriptions.len() == ids.len(), descriptions@[row as int].is_some(),
        forall|j:int| 0 <= j < ids.len() && #[trigger] descriptions@[j].is_some() ==>
            descriptions@[j].unwrap().fields().0 == ids@[j],
        !old(objects)@.contains_key(ids@[row as int]),
        forall|j:int| row < j < ids.len() ==> #[trigger] ids@[j] != ids@[row as int],
        forall|d:&Direct<B,L>| #[trigger] copy.requires((d,)),
        forall|d:&Direct<B,L>,c:Direct<B,L>| #[trigger] copy.ensures((d,),c) ==> c == *d,
    ensures vstd::std_specs::btree::btree_map_inv(final(objects)), ({
        let key = ids@[row as int];
        let stored = final(objects)@[key];
        &&& accepted == ((*staged)@ == (*prepared)@)
        &&& final(objects)@ == old(objects)@.insert(key,stored)
        &&& stored.location == Some(locations@[row as int]) && stored.record == record && stored.payload == staged
        &&& stored.direct matches Some(metadata) && metadata.object == key && metadata.location == locations@[row as int]
            && metadata.blob == descriptions@[row as int].unwrap().fields().1
            && metadata.canonical_length == descriptions@[row as int].unwrap().fields().2
        &&& final(delta)@[old(delta).len()+row] == (key,locations@[row as int])
    }),
{
    use crate::overlay_object::{Object,install};
    let before = Ghost(index@);
    let ghost old_direct = direct@;
    let ghost rows = descriptions@;
    let published = crate::direct_placement::install_appended(index,delta,direct,ids,descriptions,locations);
    assert(published);
    let id = ids[row];
    proof {
        last_placement(before@,ids@,locations@,row as int,ids@.len());
        assert forall|j:int| row < j < ids.len() && #[trigger] rows[j].is_some() implies
            rows[j].unwrap().fields().0 != rows[row as int].unwrap().fields().0 by {
            assert(ids@[j] != ids@[row as int]);
        }
        last_direct(old_direct,rows,locations@,row as int,ids@.len());
    }
    let Some((location,metadata)) = crate::arena_index::placement(id,index,direct) else {unreachable!()};
    let candidate = Object::staged(staged,record,location,metadata.map(copy));
    let installed = install(objects,id,candidate);
    assert(installed.is_ok());
    install(objects,id,Object::prepared(prepared,other)).is_ok()
}

/// One writer-selected description, from canonical bytes through the actual
/// append and catalogue update to the retained staged-first WAL object.
fn staged_body<H:Fn(u64,&[u8])->Result<[u8;32],()>>(
    frame:std::sync::Arc<[u8]>,next:std::sync::Arc<[u8]>,id:crate::ObjectId,scheme:Scheme,
    profile:u64,location:u64,identify:H,Ghost(digest):Ghost<spec_fn(u64,Seq<u8>)->[u8;32]>,
) -> (out:Option<(bool,Direct<[u8;32],u64>)>)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|p:&[u8]| #[trigger] identify.requires((profile,p)),
        forall|p:&[u8],v:Result<[u8;32],()>| #[trigger] identify.ensures((profile,p),v) ==> v == Ok(digest(profile,p@)),
    ensures out.is_some() == record::tag((*frame)@,0,scheme),
        out matches Some((accepted,metadata)) ==> accepted == ((*frame)@ == (*next)@) && metadata.object == id &&
            metadata.location == location && metadata.blob == digest(profile,(*frame)@.skip(40)) &&
            metadata.canonical_length as int == (*frame)@.len()-40,
{
    use std::collections::BTreeMap;
    let body = record::canonical_suffix(&frame,scheme).ok()?;
    let description = Description::from_bytes(id,profile,body,identify).ok()?;
    let mut index = BTreeMap::new();
    let mut delta = Vec::new();
    let mut direct = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let clone = |d:&Direct<[u8;32],u64>| -> (copy:Direct<[u8;32],u64>) ensures copy == *d, {
        Direct {object:d.object,blob:d.blob,canonical_length:d.canonical_length,location:d.location}
    };
    let accepted = staged_first(&mut index,&mut delta,&mut direct,vec![Some(description)],&mut objects,
        &[id],&[location],0,frame,0u8,next,1u8,clone);
    let stored = objects.get(&id)?;
    Some((accepted,clone(stored.direct.as_ref()?)))
}

}
