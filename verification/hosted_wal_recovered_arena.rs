//! Install authenticated fresh WAL payloads as one framed object-arena batch.
use super::*;

verus! {
pub(super) enum ArenaError<E> { Append(crate::arena_frame::BatchError<E>), Sync(E) }

fn payload_of(row:&(ObjectId,Vec<u8>)) -> (b:&[u8])
    ensures b@==row.1@,
{row.1.as_slice()}

pub(super) proof fn same_extent(a:Seq<(ObjectId,Vec<u8>)>,b:Seq<(ObjectId,Vec<u8>)>,n:nat)
    requires n<=a.len(),n<=b.len(),forall|i:int| 0<=i<n ==> (#[trigger] a[i]).1.len()==b[i].1.len(),
    ensures raw_extent(a,n)==raw_extent(b,n),
    decreases n,
{
    if n>0 {
        same_extent(a,b,(n-1) as nat);
        assert(a[n-1].1.len()==b[n-1].1.len());
    }
}

proof fn packed_extent<H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    rows:&[(ObjectId,Vec<u8>)],hash:H,base:u64,packed:Seq<u8>,locs:Seq<crate::ArenaLocation>)
    requires locs.len()<=rows.len(),crate::arena_frame::packed(rows,payload_of,hash,base,crate::arena_frame::ARENA_MAGIC,
        crate::arena_frame::FRAME_VERSION,Seq::empty(),packed,locs),
    ensures packed.len()<=raw_extent(rows@,locs.len()),
    decreases locs.len(),
{
    use crate::arena_frame as frame;
    if locs.len()>0 {
        let n=locs.len()-1;
        let loc=locs[n];
        let at=loc.offset as int-base;
        let prev=packed.take(at);
        packed_extent(rows,hash,base,prev,locs.drop_last());
        let b=choose|b:&[u8]| #[trigger] payload_of.ensures((&rows@[n],),b) && b.len()==loc.payload_len &&
            hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),loc.checksum) &&
            packed==prev+frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum)+b@;
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum).len()==52);
        assert(b@==rows@[n].1@);
    }
}

pub(super) open spec fn arena_contains(raw:Seq<u8>,image:Seq<u8>,prior:nat) -> bool {
    exists|loc:crate::ArenaLocation| #[trigger] arena_entry(loc,raw,image,prior)
}

pub(super) open spec fn arena_entry(loc:crate::ArenaLocation,raw:Seq<u8>,image:Seq<u8>,prior:nat) -> bool {
    let start=loc.offset as int;
    &&& start>=prior && start+52+loc.payload_len<=image.len()
    &&& loc.payload_len==raw.len()
    &&& image.subrange(start,start+52+loc.payload_len)==crate::arena_frame::header_bytes(
        crate::arena_frame::ARENA_MAGIC,crate::arena_frame::FRAME_VERSION,loc.payload_len,loc.checksum)+raw
}

pub(super) open spec fn boundary(index:Map<ObjectId,crate::ArenaLocation>,keys:Seq<ObjectId>,n:int,start:u64) -> int {
    if n==0 {start as int} else {let loc=index[keys[n-1]];loc.offset as int+52+loc.payload_len}
}

pub(super) open spec fn layout(index:Map<ObjectId,crate::ArenaLocation>,keys:Seq<ObjectId>,start:u64,end:nat) -> bool {
    &&& keys.no_duplicates() && keys.to_set()==index.dom()
    &&& boundary(index,keys,keys.len() as int,start)==end
    &&& forall|j:int| 0<=j<keys.len() ==> (#[trigger] index[keys[j]]).offset==boundary(index,keys,j,start)
}

pub(super) open spec fn keys(rows:Seq<(ObjectId,Vec<u8>)>) -> Seq<ObjectId> {rows.map_values(|r:(ObjectId,Vec<u8>)| r.0)}

/// Append one canonical arena batch and pair every identity with the location
/// returned for that payload. Only synchronized locations are released for indexing.
#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
pub(super) fn append_fresh_arena<A:crate::arena_frame::ReplayArena,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    arena:&mut A,rows:&[(ObjectId,Vec<u8>)],hash:H)
    -> (out:Result<(BTreeMap<ObjectId,crate::ArenaLocation>,crate::frontier::JournalFlush<()>),ArenaError<A::Error>>)
    requires old(arena).image().len()<=u64::MAX,obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|i:int,j:int| 0<=i<j<rows.len() ==> (#[trigger] rows@[i].0)!=(#[trigger] rows@[j].0),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
    ensures final(arena).target()==old(arena).target(),
        out matches Err(ArenaError::Sync(e)) ==> A::sync_failed(old(arena).target(),e),
        out matches Ok((index,flush)) ==> {
            &&& flush is StableFile ==> final(arena).stable()==final(arena).image()
            &&& layout(index@,keys(rows@),old(arena).image().len() as u64,final(arena).image().len())
            &&& btree_map_inv(&index)
            &&& final(arena).image().take(old(arena).image().len() as int)==old(arena).image()
            &&& forall|i:int| 0<=i<rows.len() ==> {
                let row=#[trigger] rows@[i];
                &&& index@.contains_key(row.0)
                &&& arena_entry(index@[row.0],row.1@,final(arena).image(),old(arena).image().len())
                &&& crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,row.1@,index@[row.0].checksum)
            }
            &&& forall|k:ObjectId| #[trigger] index@.contains_key(k) ==> exists|i:int| 0<=i<rows.len() && #[trigger] rows@[i].0==k
        },
        out matches Err(ArenaError::Append(crate::arena_frame::BatchError::Seek(e))) ==> old(arena).seek_failed(e) && final(arena).image()==old(arena).image(),
        out matches Err(ArenaError::Append(crate::arena_frame::BatchError::Write(e))) ==> A::write_failed(old(arena).target(),e),
        out matches Err(ArenaError::Append(crate::arena_frame::BatchError::Overflow)) ==> final(arena).image()==old(arena).image() &&
            (raw_extent(rows@,rows.len() as nat)>isize::MAX || old(arena).image().len()+raw_extent(rows@,rows.len() as nat)>u64::MAX),
{
    use crate::arena_frame as frame;
    let ghost prior=arena.image();
    let ghost base=prior.len() as u64;
    let written=match frame::append_batch(arena,rows,payload_of,hash,frame::ARENA_MAGIC,frame::FRAME_VERSION,(Vec::new(),Vec::new())) {
        Ok(l)=>l,Err(e)=>{
            proof {
                if e is Overflow {
                    let (prefix,ls,body)=choose|prefix:Seq<u8>,ls:Seq<crate::ArenaLocation>,body:&[u8]|
                        #[trigger] frame::refused_at(rows,payload_of,hash,base,frame::ARENA_MAGIC,frame::FRAME_VERSION,Seq::empty(),prefix,ls,body);
                    packed_extent(rows,hash,base,prefix,ls);
                    assert(body@==rows@[ls.len() as int].1@);
                    raw_extent_le(rows@,ls.len()+1,rows.len() as nat);
                    assert(raw_extent(rows@,ls.len()+1)==raw_extent(rows@,ls.len())+72+body.len());
                }
            }
            return Err(ArenaError::Append(e))
        },
    };
    let ghost packed=choose|s:Seq<u8>| arena.image()==prior+s &&
        #[trigger] frame::packed(rows,payload_of,hash,base,frame::ARENA_MAGIC,frame::FRAME_VERSION,Seq::empty(),s,written@);
    let (locations,flush)=match frame::release_replayed(arena,written) {
        Ok(locations)=>locations,Err(e)=>return Err(ArenaError::Sync(e)),
    };
    assert(arena.image().take(prior.len() as int) =~= prior);
    let mut index=BTreeMap::new();
    let mut i=0usize;
    while i<locations.len()
        invariant i<=locations.len(),btree_map_inv(&index),
            forall|j:int| 0<=j<i ==> index@[#[trigger] rows@[j].0]==locations@[j],
            forall|j:int| 0<=j<i ==> index@.contains_key(#[trigger] rows@[j].0) &&
                arena_entry(index@[rows@[j].0],rows@[j].1@,arena.image(),prior.len()) &&
                frame::hashed(hash,frame::ARENA_MAGIC,rows@[j].1@,index@[rows@[j].0].checksum),
            forall|k:ObjectId| #[trigger] index@.contains_key(k) ==> exists|j:int| 0<=j<i && #[trigger] rows@[j].0==k,
        decreases locations.len()-i,
    {
        let loc=locations[i];
        proof {
            crate::hosted_acknowledged_root::packed_row(rows,payload_of,hash,base,frame::ARENA_MAGIC,frame::FRAME_VERSION,Seq::empty(),packed,locations@,i as int);
            let start=loc.offset as int-base;
            let b=choose|b:&[u8]| #[trigger] payload_of.ensures((&rows@[i as int],),b) && b.len()==loc.payload_len &&
                hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),loc.checksum) &&
                packed.subrange(start,start+52+loc.payload_len)==frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum)+b@;
            assert(arena.image().subrange(loc.offset as int,loc.offset as int+52+loc.payload_len) =~= packed.subrange(start,start+52+loc.payload_len));
            assert(arena_entry(loc,rows@[i as int].1@,arena.image(),prior.len()));
            assert(frame::hashed(hash,frame::ARENA_MAGIC,rows@[i as int].1@,loc.checksum));
        }
        let ghost previous=index@;
        index.insert(rows[i].0,loc);
        assert forall|j:int| 0<=j<=i implies index@[#[trigger] rows@[j].0]==locations@[j] by {
            if j<i {
                assert(rows@[j].0!=rows@[i as int].0);
                assert(previous[rows@[j].0]==locations@[j]);
            }
        }
        i+=1;
    }
    proof {
        let ids=keys(rows@);
        assert(ids.to_set() =~= index@.dom()) by {
            assert forall|k:ObjectId| index@.contains_key(k) implies ids.contains(k) by {
                let i=choose|i:int| 0<=i<rows.len() && #[trigger] rows@[i].0==k;
                assert(ids[i]==k);
            }
            assert forall|k:ObjectId| ids.contains(k) implies index@.contains_key(k) by {
                let i=ids.index_of(k);assert(rows@[i].0==k);
            }
        }
        assert forall|j:int,k:int| 0<=j<k<ids.len() implies ids[j]!=ids[k] by {assert(rows@[j].0!=rows@[k].0);}
        assert(ids.no_duplicates());
        if locations.len()>0 {
            let loc=locations@.last();
            let at=loc.offset as int-base;
            let b=choose|b:&[u8]| #[trigger] payload_of.ensures((&rows@[locations.len()-1],),b) && b.len()==loc.payload_len &&
                hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),loc.checksum) &&
                packed==packed.take(at)+frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum)+b@;
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum).len()==52);
            assert(index@[ids[locations.len()-1]]==loc);
        }
        assert(boundary(index@,ids,ids.len() as int,base)==arena.image().len());
        assert forall|j:int| 0<=j<ids.len() implies (#[trigger] index@[ids[j]]).offset==boundary(index@,ids,j,base) by {
            assert(index@[rows@[j].0]==locations@[j]);
            crate::hosted_acknowledged_root::packed_row(rows,payload_of,hash,base,frame::ARENA_MAGIC,frame::FRAME_VERSION,Seq::empty(),packed,locations@,j);
            if j>0 {assert(index@[rows@[j-1].0]==locations@[j-1]);}
        }
    }
    Ok((index,flush))
}

}
