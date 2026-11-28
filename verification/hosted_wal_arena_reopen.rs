//! Reopen synchronized replay frames and revalidate the recovered journal roots.
use super::*;
use crate::hosted_cold_journal as journal;
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
    pub(super) start:Ghost<u64>,
    pub(super) order:Ghost<Seq<ObjectId>>,
}

impl ArenaReceipt {
    pub(super) open spec fn covers<H:Fn([u8;8],u64,&[u8])->[u8;32]>(&self,records:Map<ObjectId,ObjectRecord>,
        scheme:root_wire::Scheme,limit:u64,hash:H) -> bool {
        &&& super::recovered_arena::layout(self.index@,self.order@,self.start@,self.image@.len())
        &&& btree_map_inv(&self.index) && self.index@.dom()==records.dom()
        &&& forall|k:ObjectId| #[trigger] self.index@.contains_key(k) ==> {
            let loc=self.index@[k];let src=records[k];let raw=crate::recovered_record::encoding(scheme,k,src);
            &&& ObjectRecord::labels_ordered(src.contents().3) && loc.payload_len<=limit
            &&& arena_entry(loc,raw,self.image@,0)
            &&& crate::arena_frame::hashed(hash,crate::arena_frame::ARENA_MAGIC,raw,loc.checksum)
        }
    }
}

enum RebuildError<E> {
    Frame(u64,crate::frame_repair::FrameError<E>),
    Index(u64,crate::recovered_record::IndexError),
}

spec fn io_at<R:crate::frame_repair::FrameReader>(image:Seq<u8>,target:(int,Seq<u8>),loc:crate::ArenaLocation,e:R::Error) -> bool {
    (exists|r:R| r.image()==image && r.target()==target && r.position()==loc.offset &&
        #[trigger] r.failed(loc.offset as int,52,e)) ||
    (exists|r:R| r.image()==image && r.target()==target && r.position()==loc.offset as int+52 &&
        #[trigger] r.failed(loc.offset as int+52,loc.payload_len,e))
}

spec fn rebuild_failure<R:crate::frame_repair::FrameReader>(receipt:&ArenaReceipt,records:Map<ObjectId,ObjectRecord>,e:RebuildError<R::Error>) -> bool {
    match e {
            RebuildError::Frame(at,crate::frame_repair::FrameError::Io(e))=>exists|k:ObjectId|
                #[trigger] receipt.index@.contains_key(k) && receipt.index@[k].offset==at &&
                    io_at::<R>(receipt.image@,receipt.target@,receipt.index@[k],e),
            RebuildError::Index(at,e)=>e matches crate::recovered_record::IndexError::Record(crate::recovered_record::Error::Decode(
                crate::verified_record::DecodeError::Record(crate::verified_record::BodyError::Allocation))) &&
                exists|k:ObjectId| #[trigger] records.contains_key(k) && receipt.index@[k].offset==at && records[k].contents().3.len()>0,
            _=>false,
    }
}

/// Rebuild the index by advancing the actual file cursor to the measured end.
/// A nonzero start scans the newly synchronized suffix only.
#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
fn rebuild<R:crate::frame_repair::FrameReader,H,I>(reader:&mut R,start:u64,end:u64,
    scheme:root_wire::Scheme,limit:u64,hash:H,identify:I,Ghost(receipt):Ghost<ArenaReceipt>,
    Ghost(records):Ghost<Map<ObjectId,ObjectRecord>>)
    -> (out:Result<BTreeMap<ObjectId,crate::ArenaLocation>,RebuildError<R::Error>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&ObjectRecord)->[u8;32]+Copy,
    requires receipt.covers(records,scheme,limit,hash),old(reader).image()==receipt.image@,
        old(reader).target()==receipt.target@,old(reader).position()==start,start==receipt.start@,
        end==receipt.image@.len(),start<=end,scheme.algorithm@!=seq![0u8,0u8],scheme.construction@!=seq![0u8,0u8],
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
        forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,a),d) &&
            #[trigger] hash.ensures((crate::arena_frame::ARENA_MAGIC,n,b),e) ==> d==e,
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|k:ObjectId,r:&ObjectRecord,d:[u8;32]| #[trigger] records.contains_key(k) &&
            crate::hosted_record_roundtrip::same_fields(*r,records[k]) && #[trigger] identify.ensures((r,),d) ==> d@==k.digest(),
    ensures final(reader).image()==receipt.image@,final(reader).target()==receipt.target@,
        match out {
            Ok(index)=>btree_map_inv(&index) && index@==receipt.index@ && final(reader).position()==end,
            Err(e)=>rebuild_failure::<R>(&receipt,records,e),
        },
{
    use crate::arena_frame as frame;
    use super::recovered_arena::boundary;
    let ghost order=receipt.order@;
    let mut index=BTreeMap::new();
    let mut at=start;
    let ghost mut j:int=0;
    while at<end
        invariant 0<=j<=order.len(),at<=end,reader.position()==at,reader.image()==receipt.image@,reader.target()==receipt.target@,
            at==boundary(receipt.index@,order,j,start),btree_map_inv(&index),
            index@.dom()==order.take(j).to_set(),
            forall|k:ObjectId| #[trigger] index@.contains_key(k) ==> index@[k]==receipt.index@[k],
        decreases end-at,
    {
        assert(j<order.len());
        let ghost id=order[j];
        let ghost loc=receipt.index@[id];
        let ghost src=records[id];
        let ghost raw=crate::recovered_record::encoding(scheme,id,src);
        assert(order.contains(id));
        assert(receipt.index@.contains_key(id));
        assert(loc.offset==at);
        let ghost before=*reader;
        let f=match crate::hosted_acknowledged_root::scan_written(reader,at,end,limit,frame::ARENA_MAGIC,hash,Ghost(loc),Ghost(raw)) {
            Ok(f)=>f,Err(e)=>{
                proof {if let crate::frame_repair::FrameError::Io(io)=&e {
                    if before.failed(at as int,52,*io) {assert(before.position()==loc.offset);}
                    assert(io_at::<R>(receipt.image@,receipt.target@,loc,*io));
                }}
                return Err(RebuildError::Frame(at,e));
            }
        };
        proof {
            if order.take(j).contains(id) {
                let n=order.take(j).index_of(id);
                assert(order[n]==order[j]);
            }
            assert(!index@.contains_key(id));
        }
        let checksum=|n:u64,b:&[u8]| -> (d:[u8;32])
            ensures hash.ensures((frame::ARENA_MAGIC,n,b),d),
            {hash(frame::ARENA_MAGIC,n,b)};
        let body=f.body.as_slice();
        let new=match crate::hosted_record_roundtrip::index_fresh(&mut index,at,body,scheme,identify,checksum,Ghost(src),Ghost(id)) {
            Ok(new)=>new,Err(e)=>return Err(RebuildError::Index(at,e)),
        };
        proof {
            let written=choose|b:&[u8]| b@==raw && #[trigger] hash.ensures((frame::ARENA_MAGIC,loc.payload_len,b),loc.checksum);
            assert(new.checksum==loc.checksum);
            assert(new==loc);
            assert(order.take(j+1) =~= order.take(j).push(id));
            let prefix=order.take(j);
            assert forall|k:ObjectId| #[trigger] prefix.push(id).to_set().contains(k) == prefix.to_set().insert(id).contains(k) by {
                if prefix.push(id).contains(k) {
                    let n=prefix.push(id).index_of(k);
                    if n<j {assert(prefix[n]==k);}
                }
                if prefix.contains(k) {
                    let n=prefix.index_of(k);
                    assert(prefix.push(id)[n]==k);
                }
                assert(prefix.push(id)[j]==id);
            }
            assert(order.take(j+1).to_set() =~= prefix.to_set().insert(id));
            j=j+1;
        }
        at=f.end;
    }
    proof {
        if j<order.len() {
            let k=order[j];
            assert(order.contains(k));
            assert(receipt.index@.contains_key(k));
            assert(receipt.index@[k].offset==at);
        }
        assert(j==order.len());
        assert(order.take(j) =~= order);
        assert(index@ =~= receipt.index@);
    }
    Ok(index)
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


enum ColdRead<M:crate::positional_read::Media,E,JE> {
    Journal(u64,journal::Failure<JE>),
    Scan(RebuildError<E>),
    AwaitingContainer,
    Read(M,ObjectId,ReadError<M::Error>),
    Refused(M,crate::journal_closure::Failure,Ghost<BTreeMap<ObjectId,ObjectRecord>>),
    Loaded(M,BTreeMap<ObjectId,ObjectRecord>,std::collections::BTreeSet<ObjectId>),
}

spec fn restored(table:&BTreeMap<ObjectId,ObjectRecord>,records:Map<ObjectId,ObjectRecord>) -> bool {
    &&& btree_map_inv(table) && table@.dom()==records.dom()
    &&& forall|k:ObjectId| #[trigger] table@.contains_key(k) ==> crate::hosted_record_roundtrip::same_fields(table@[k],records[k])
}

spec fn authorized<P:Ord>(history:Map<P,(RootState,u64)>,table:&BTreeMap<ObjectId,ObjectRecord>,known:Set<ObjectId>) -> bool {
    (forall|p:P| #[trigger] history.contains_key(p) ==> exists|s:Set<ObjectId>| #[trigger] crate::journal_closure::admitted(table,history[p].0.commit,s) && s.subset_of(known)) &&
                (forall|k:ObjectId| #[trigger] known.contains(k) ==> exists|p:P,s:Set<ObjectId>| history.contains_key(p) &&
                    #[trigger] crate::journal_closure::admitted(table,history[p].0.commit,s) && s.contains(k))
}

spec fn refused_history<P:Ord>(history:Map<P,(RootState,u64)>,table:&BTreeMap<ObjectId,ObjectRecord>,e:crate::journal_closure::Failure) -> bool {
    exists|p:P| history.contains_key(p) && #[trigger] crate::journal_closure::refused(table,history[p].0.commit,history[p].1,e)
}

/// Reopen the same synchronized native arena, discard the table built during
/// WAL replay, scan the independent root journal, and validate both recovered maps.
/// A region receipt cannot take this path before container persistence.
#[verifier::spinoff_prover]
fn reopen_native<A:crate::arena_frame::ReplayArena,M:crate::positional_read::Media,R:crate::frame_repair::FrameReader,P:Ord,H,I,O,J:crate::frontier::JournalContainer,Q:crate::frame_repair::FrameReader,OJ,D,C>(
    Ghost(receipt):Ghost<ArenaReceipt>,flush:crate::frontier::JournalFlush<()>,arena:&A,open:O,target:Ghost<spec_fn(M)->(int,Seq<u8>)>,
    journal_file:&J,open_journal:OJ,decode:D,recode:C,Ghost(rows):Ghost<Seq<journal::Row<P>>>,scheme:root_wire::Scheme,limit:u64,hash:H,identify:I,
    Ghost(records):Ghost<Map<ObjectId,ObjectRecord>>) -> (out:ColdRead<M,R::Error,Q::Error>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&ObjectRecord)->[u8;32]+Copy,O:FnOnce(&A)->(R,M,u64,u64),
        OJ:FnOnce(&J)->(Q,u64),D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires flush==receipt.flush,receipt.covers(records,scheme,limit,hash),arena.target()==receipt.target@,
        receipt.flush is StableFile ==> arena.stable()==receipt.image@ && arena.stable().len()<=u64::MAX && open.requires((arena,)),
        forall|opened:(R,M,u64,u64)| #[trigger] open.ensures((arena,),opened) ==> {
            let (reader,media,start,end)=opened;
            &&& media.image()==arena.stable() && (target@)(media)==arena.target()
            &&& reader.image()==media.image() && reader.target()==arena.target()
            &&& reader.position()==start && start==receipt.start@ && start<=end==media.image().len()
        },
        (journal_file.container_id(),journal_file.region_id())!=arena.target(),
        flush is StableFile ==> open_journal.requires((journal_file,)),
        forall|opened:(Q,u64)| #[trigger] open_journal.ensures((journal_file,),opened) ==> {
            let (r,end)=opened;
            &&& r.image()==journal_file.durable_image() && end==r.image().len() && r.position()==0
            &&& r.target()==(journal_file.container_id(),journal_file.region_id())
        },
        journal::readable(rows,journal_file.durable_image(),journal_file.durable_image().len() as u64,scheme,limit,hash,decode,recode),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
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
            ColdRead::Journal(at,e)=>journal::failed::<Q,P>(rows,journal_file.durable_image(),(journal_file.container_id(),journal_file.region_id()),at,e),
            ColdRead::Scan(e)=>rebuild_failure::<R>(&receipt,records,e),
            ColdRead::Read(m,k,e)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ &&
                receipt.index@.contains_key(k) && read_failure(&m,receipt.index@[k],records[k],e),
            ColdRead::Refused(m,e,table)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ && restored(&table@,records) &&
                journal::consecutive(rows,rows.len()) && refused_history(journal::prefix(rows,rows.len()),&table@,e),
            ColdRead::Loaded(m,table,known)=> (target@)(m)==receipt.target@ && m.image()==receipt.image@ && restored(&table,records) &&
                journal::consecutive(rows,rows.len()) && authorized(journal::prefix(rows,rows.len()),&table,known@),
        },
{
    if let crate::frontier::JournalFlush::AwaitingContainer(())=flush {return ColdRead::AwaitingContainer;}
    let (mut reader,media,start,end)=open(arena);
    let index=match rebuild(&mut reader,start,end,scheme,limit,hash,identify,Ghost(receipt),Ghost(records)) {
        Ok(index)=>index,Err(e)=>return ColdRead::Scan(e),
    };
    let table=match read_index(&media,&index,scheme,limit,hash,identify,Ghost(records)) {
        Ok(table)=>table,Err((k,e))=>return ColdRead::Read(media,k,e),
    };
    assert(restored(&table,records));
    assert((target@)(media)==receipt.target@ && media.image()==receipt.image@);
    let (mut root_reader,journal_end)=open_journal(journal_file);
    let history=match journal::recover(&mut root_reader,journal_end,scheme,limit,hash,decode,recode,Ghost(rows)) {
        Ok(history)=>history,Err((at,e))=>return ColdRead::Journal(at,e),
    };
    match crate::journal_closure::validate(&history,&table) {
        Ok(known)=>{assert(authorized(history@,&table,known@));return ColdRead::Loaded(media,table,known);},
        Err(e)=>{
            assert(exists|p:P| history@.contains_key(p) && #[trigger] crate::journal_closure::refused(&table,history@[p].0.commit,history@[p].1,e));
            let ghost witness=choose|p:P| history@.contains_key(p) && #[trigger] crate::journal_closure::refused(&table,history@[p].0.commit,history@[p].1,e);
            let snapshot=Ghost(table);
            assert(crate::journal_closure::refused(&snapshot@,history@[witness].0.commit,history@[witness].1,e));
            assert(refused_history(history@,&snapshot@,e));
            assert(restored(&snapshot@,records));
            return ColdRead::Refused(media,e,snapshot);
        },
    }
}

}
