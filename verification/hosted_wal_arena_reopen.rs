//! Reopen synchronized replay frames and revalidate the recovered journal roots.
use super::*;
verus! {
type ReadError<E> = crate::positional_read::SpanError<E,crate::indexed_frame::Error>;

spec fn read_failure<M:crate::positional_read::Media>(media:&M,loc:crate::ArenaLocation,source:ObjectRecord,e:ReadError<M::Error>) -> bool {
    match e {
        crate::positional_read::SpanError::Capacity=>true,
        crate::positional_read::SpanError::Read(crate::positional_read::Error::Io(e))=>
            crate::positional_read::failed_within(media,loc.offset,52+loc.payload_len as nat,e),
        crate::positional_read::SpanError::Consumer(crate::indexed_frame::Error::Record(
            crate::verified_record::Error::Decode(crate::verified_record::DecodeError::Record(crate::verified_record::BodyError::Allocation))))=>
                source.contents().3.len()>0,
        _=>false,
    }
}

/// Authenticate an indexed fresh record again after reopening the arena.
/// Only the durable location, identity and read parameters are executable.
#[verifier::spinoff_prover]
#[verifier::rlimit(40)]
fn read_fresh<M:crate::positional_read::Media,H,I>(
    media:&M,loc:crate::ArenaLocation,id:ObjectId,scheme:root_wire::Scheme,limit:u64,
    hash:H,identify:I,Ghost(source):Ghost<ObjectRecord>)
    -> (out:Result<ObjectRecord,crate::positional_read::SpanError<M::Error,crate::indexed_frame::Error>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&ObjectRecord)->[u8;32]+Copy,
    requires loc.payload_len<=limit,loc.offset as int+52+loc.payload_len<=u64::MAX,
        scheme.algorithm@!=seq![0u8,0u8],scheme.construction@!=seq![0u8,0u8],
        ObjectRecord::labels_ordered(source.contents().3),
        arena_entry(loc,crate::recovered_record::encoding(scheme,id,source),media.image(),0),
        crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,crate::recovered_record::encoding(scheme,id,source),loc.checksum),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
        forall|a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,loc.payload_len,a),d) &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,loc.payload_len,b),e) ==> d==e,
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|r:&ObjectRecord,d:[u8;32]| crate::hosted_record_roundtrip::same_fields(*r,source) &&
            #[trigger] identify.ensures((r,),d) ==> d@==id.digest(),
    ensures match out {Ok(r)=>crate::hosted_record_roundtrip::same_fields(r,source),Err(e)=>read_failure(media,loc,source,e)},
{
    use crate::{arena_frame as frame,indexed_frame as indexed,positional_read as io,verified_record as record};
    let size=52+loc.payload_len;
    let ghost raw=crate::recovered_record::encoding(scheme,id,source);
    let consume=|data:&[u8],base:u64| -> (result:Result<ObjectRecord,indexed::Error>)
        requires base==loc.offset,io::interval(media,loc.offset,size,data),
        ensures match result {
            Ok(r)=>crate::hosted_record_roundtrip::same_fields(r,source),
            Err(e)=>source.contents().3.len()>0 && e matches indexed::Error::Record(record::Error::Decode(record::DecodeError::Record(record::BodyError::Allocation))),
        },
    {
        let _length=data.len();
        let result=indexed::read(data,base,loc,id,indexed::Format{magic:frame::ARENA_MAGIC,version:frame::FRAME_VERSION,limit,scheme},hash,identify);
        proof {
            let bytes=data@;
            let body=bytes.skip(52);
            assert(bytes==frame::header_bytes(frame::ARENA_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum)+raw);
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(body =~= raw);
            crate::hosted_record_roundtrip::canonical_shape(raw,source,scheme,id);
            assert(bytes.subrange(0,52+loc.payload_len as int) =~= bytes);
            assert(bytes.take(8) =~= frame::ARENA_MAGIC@);
            assert(bytes.subrange(8,10) =~= seq![frame::FRAME_VERSION as u8,(frame::FRAME_VERSION >> 8) as u8]);
            assert(bytes.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(loc.payload_len));
            assert(bytes.subrange(20,52) =~= loc.checksum@);
            let written=choose|b:&[u8]| b@==raw && #[trigger] hash.ensures((frame::ARENA_MAGIC,raw.len() as u64,b),loc.checksum);
            assert forall|b:&[u8],d:[u8;32]| b@==raw && #[trigger] hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),d) implies d==loc.checksum by {
                assert(written@==b@);
            }
            if let Ok((ref r,_))=result {crate::hosted_record_roundtrip::unique_record(raw,scheme,*r,source);}
            if let Err(indexed::Error::Record(record::Error::Identity))=result {
                let (r,d)=choose|r:ObjectRecord,d:[u8;32]| d@!=id.digest() && record::record_at(raw,40,scheme,r) &&
                    #[trigger] identify.ensures((&r,),d);
                crate::hosted_record_roundtrip::unique_record(raw,scheme,r,source);
                assert(false);
            }
        }
        match result {Ok((r,_))=>Ok(r),Err(e)=>Err(e)}
    };
    io::with_span(media,loc.offset,size,consume)
}


/// Authentic locations released by replay, together with the backing's flush
/// decision. Target and image witnesses disappear from executable code.
pub(super) struct ArenaReceipt {
    pub(super) index:BTreeMap<ObjectId,crate::ArenaLocation>,
    pub(super) flush:crate::frontier::JournalFlush<()>,
    pub(super) target:Ghost<(int,Seq<u8>)>,
    pub(super) image:Ghost<Seq<u8>>,
}

impl ArenaReceipt {
    pub(super) open spec fn covers<H:Fn([u8;8],u64,&[u8])->[u8;32]>(&self,records:Map<ObjectId,ObjectRecord>,
        scheme:root_wire::Scheme,limit:u64,hash:H) -> bool {
        &&& btree_map_inv(&self.index) && self.index@.dom()==records.dom()
        &&& forall|k:ObjectId| #[trigger] self.index@.contains_key(k) ==> {
            let loc=self.index@[k];let src=records[k];let raw=crate::recovered_record::encoding(scheme,k,src);
            &&& ObjectRecord::labels_ordered(src.contents().3) && loc.payload_len<=limit
            &&& arena_entry(loc,raw,self.image@,0)
            &&& crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,raw,loc.checksum)
        }
    }
}

/// Rebuild the table solely by consuming the reopened media and the recovered
/// index. A failed positional read identifies the exact key and location.
#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
fn read_index<M:crate::positional_read::Media,H,I>(media:&M,index:&BTreeMap<ObjectId,crate::ArenaLocation>,
    scheme:root_wire::Scheme,limit:u64,hash:H,identify:I,Ghost(records):Ghost<Map<ObjectId,ObjectRecord>>)
    -> (out:Result<BTreeMap<ObjectId,ObjectRecord>,(ObjectId,ReadError<M::Error>)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&ObjectRecord)->[u8;32]+Copy,
    requires btree_map_inv(index),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        scheme.algorithm@!=seq![0u8,0u8],scheme.construction@!=seq![0u8,0u8],
        media.image().len()<=u64::MAX,index@.dom()==records.dom(),
        forall|k:ObjectId| #[trigger] index@.contains_key(k) ==> {
            let loc=index@[k];let src=records[k];let raw=crate::recovered_record::encoding(scheme,k,src);
            &&& ObjectRecord::labels_ordered(src.contents().3) && loc.payload_len<=limit
            &&& arena_entry(loc,raw,media.image(),0)
            &&& crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,raw,loc.checksum)
        },
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
        forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,a),d) &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,b),e) ==> d==e,
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|k:ObjectId,r:&ObjectRecord,d:[u8;32]| #[trigger] records.contains_key(k) &&
            crate::hosted_record_roundtrip::same_fields(*r,records[k]) &&
            #[trigger] identify.ensures((r,),d) ==> d@==k.digest(),
    ensures out matches Ok(table) ==> btree_map_inv(&table) && table@.dom()==records.dom() &&
            forall|k:ObjectId| #[trigger] table@.contains_key(k) ==> crate::hosted_record_roundtrip::same_fields(table@[k],records[k]),
        out matches Err((k,e)) ==> index@.contains_key(k) && read_failure(media,index@[k],records[k],e),
{
    use vstd::std_specs::iter::IteratorSpec;
    let mut it=index.iter();
    let ghost all=it.remaining();
    let ghost mut n:int=0;
    let mut table=BTreeMap::new();
    loop
        invariant 0<=n<=all.len(),all.len()==index.len(),it.remaining()==all.skip(n),all.unref().to_set()==index@.kv_pairs(),
            btree_map_inv(&table),table@.dom().subset_of(records.dom()),
            forall|j:int| 0<=j<n ==> table@.contains_key(*#[trigger] all[j].0),
            forall|k:ObjectId| #[trigger] table@.contains_key(k) ==> crate::hosted_record_roundtrip::same_fields(table@[k],records[k]),
        decreases index.len()-n,
    {
        let Some((id,loc))=it.next() else {
            assert(n==all.len());
            assert forall|k:ObjectId| #[trigger] records.contains_key(k) implies table@.contains_key(k) by {
                let pair=(k,index@[k]);
                assert(all.unref().to_set().contains(pair));
                let j=all.unref().index_of(pair);
                assert(all.unref()[j]==pair && *all[j].0==k);
            }
            assert(table@.dom() =~= records.dom());
            return Ok(table);
        };
        assert(all.unref()[n]==(*id,*loc));
        assert(index@.kv_pairs().contains((*id,*loc)));
        let record=match read_fresh(media,*loc,*id,scheme,limit,hash,identify,Ghost(records[*id])) {
            Ok(r)=>r,Err(e)=>return Err((*id,e)),
        };
        table.insert(*id,record);
        proof {n=n+1;}
    }
}


enum ColdRead<M:crate::positional_read::Media> {
    AwaitingContainer,
    Read(M,ObjectId,ReadError<M::Error>),
    Refused(M,crate::journal_closure::Failure,Ghost<BTreeMap<ObjectId,ObjectRecord>>),
    Loaded(M,BTreeMap<ObjectId,ObjectRecord>,std::collections::BTreeSet<ObjectId>),
}

spec fn restored(table:&BTreeMap<ObjectId,ObjectRecord>,records:Map<ObjectId,ObjectRecord>) -> bool {
    &&& btree_map_inv(table) && table@.dom()==records.dom()
    &&& forall|k:ObjectId| #[trigger] table@.contains_key(k) ==> crate::hosted_record_roundtrip::same_fields(table@[k],records[k])
}

spec fn authorized<P:Ord>(history:&BTreeMap<P,(RootState,u64)>,table:&BTreeMap<ObjectId,ObjectRecord>,known:Set<ObjectId>) -> bool {
    (forall|p:P| #[trigger] history@.contains_key(p) ==> exists|s:Set<ObjectId>| #[trigger] crate::journal_closure::admitted(table,history@[p].0.commit,s) && s.subset_of(known)) &&
                (forall|k:ObjectId| #[trigger] known.contains(k) ==> exists|p:P,s:Set<ObjectId>| history@.contains_key(p) &&
                    #[trigger] crate::journal_closure::admitted(table,history@[p].0.commit,s) && s.contains(k))
}

/// Reopen the same synchronized native arena, discard the table built during
/// WAL replay, and validate the supplied recovered journal against fresh reads.
/// A region receipt cannot take this path before container persistence.
#[verifier::spinoff_prover]
fn reopen_native<A:crate::arena_frame::ReplayArena,M:crate::positional_read::Media,P:Ord,H,I,O>(
    receipt:&ArenaReceipt,arena:&A,open:O,target:Ghost<spec_fn(M)->(int,Seq<u8>)>,
    history:&BTreeMap<P,(RootState,u64)>,scheme:root_wire::Scheme,limit:u64,hash:H,identify:I,
    Ghost(records):Ghost<Map<ObjectId,ObjectRecord>>) -> (out:ColdRead<M>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&ObjectRecord)->[u8;32]+Copy,O:FnOnce(&A)->M,
    requires receipt.covers(records,scheme,limit,hash),arena.target()==receipt.target@,
        receipt.flush is StableFile ==> arena.stable()==receipt.image@ && arena.stable().len()<=u64::MAX && open.requires((arena,)),
        forall|m:M| #[trigger] open.ensures((arena,),m) ==> m.image()==arena.stable() && (target@)(m)==arena.target(),
        btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        scheme.algorithm@!=seq![0u8,0u8],scheme.construction@!=seq![0u8,0u8],
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
        forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,a),d) &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,b),e) ==> d==e,
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|k:ObjectId,r:&ObjectRecord,d:[u8;32]| #[trigger] records.contains_key(k) &&
            crate::hosted_record_roundtrip::same_fields(*r,records[k]) && #[trigger] identify.ensures((r,),d) ==> d@==k.digest(),
    ensures (out is AwaitingContainer)==(receipt.flush is AwaitingContainer),
        match out {
            ColdRead::AwaitingContainer=>true,
            ColdRead::Read(m,k,e)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ &&
                receipt.index@.contains_key(k) && read_failure(&m,receipt.index@[k],records[k],e),
            ColdRead::Refused(m,e,table)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ && restored(&table@,records) &&
                exists|p:P| history@.contains_key(p) && #[trigger] crate::journal_closure::refused(&table@,history@[p].0.commit,history@[p].1,e),
            ColdRead::Loaded(m,table,known)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ && restored(&table,records) &&
                authorized(history,&table,known@),
        },
{
    if let crate::frontier::JournalFlush::AwaitingContainer(())=receipt.flush {return ColdRead::AwaitingContainer;}
    let media=open(arena);
    let table=match read_index(&media,&receipt.index,scheme,limit,hash,identify,Ghost(records)) {
        Ok(table)=>table,Err((k,e))=>return ColdRead::Read(media,k,e),
    };
    assert(restored(&table,records));
    assert((target@)(media)==receipt.target@ && media.image()==receipt.image@);
    match crate::journal_closure::validate(history,&table) {
        Ok(known)=>{assert(authorized(history,&table,known@));return ColdRead::Loaded(media,table,known);},
        Err(e)=>{
            assert(exists|p:P| history@.contains_key(p) && #[trigger] crate::journal_closure::refused(&table,history@[p].0.commit,history@[p].1,e));
            return ColdRead::Refused(media,e,Ghost(table));
        },
    }
}

}
