//! Bind ordered engine-prepared object declarations to their selected WAL storage encoding.
use super::*;
use crate::wal_object_storage as storage;
#[path = "hosted_wal_recovered_arena.rs"]
mod recovered_arena;
use recovered_arena::{append_fresh_arena,arena_contains,arena_entry,same_extent};
verus! {

enum Payload<'a> { Plain(&'a [u8]), Lz4(Vec<u8>) }
enum Error { Identity(usize), Order(usize), Limit(usize), Envelope(usize) }

impl Payload<'_> {
    spec fn bytes(&self) -> Seq<u8> {
        match self {Self::Plain(b)=>b@,Self::Lz4(b)=>b@}
    }

    fn descriptor(&self) -> (d:Stored<'_>)
        ensures d.body@==self.bytes(),d.encoding.flag()==if self is Plain {0u8} else {1u8},
    {
        match self {
            Self::Plain(b)=>Stored{encoding:ObjectEncoding::Plain,body:b},
            Self::Lz4(b)=>Stored{encoding:ObjectEncoding::Lz4,body:b.as_slice()},
        }
    }
}

spec fn ordered(rows:Seq<(ObjectId,Vec<u8>)>,count:nat) -> bool {
    forall|j:int,k:int| 0<=j<k<count ==> #[trigger] ObjectId::digest_before(rows[j].0.digest(),rows[k].0.digest())
}

spec fn packed(canonical:Seq<u8>,compression:spec_fn(Seq<u8>)->Seq<u8>,payload:Payload) -> bool {
    if compression(canonical).len()+8<canonical.len() {
        payload is Lz4 && payload.bytes()==vstd::bytes::spec_u64_to_le_bytes(canonical.len() as u64)+compression(canonical)
    } else {payload is Plain && payload.bytes()==canonical}
}

spec fn admitted(rows:Seq<(ObjectId,Vec<u8>)>,scheme:root_wire::Scheme,limit:u64,c:spec_fn(Seq<u8>)->Seq<u8>,p:Seq<Payload>,i:int) -> bool {
    &&& crate::verified_record::declared(rows[i].1@,scheme,rows[i].0)
    &&& rows[i].1.len()<=limit
    &&& packed(rows[i].1@,c,p[i])
}

fn pack_rows<'a,C:Fn(&[u8])->Vec<u8>>(rows:&'a [(ObjectId,Vec<u8>)],scheme:root_wire::Scheme,limit:u64,
    encode:C,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>)
    -> (out:Result<Vec<Payload<'a>>,Error>)
    requires forall|r:&[u8]| #[trigger] encode.requires((r,)),
        forall|r:&[u8],v:Vec<u8>| #[trigger] encode.ensures((r,),v) ==> v@==(compression@)(r@),
    ensures out matches Ok(p) ==> p.len()==rows.len() && ordered(rows@,rows.len() as nat) &&
        forall|i:int| 0<=i<p.len() ==> #[trigger] admitted(rows@,scheme,limit,compression@,p@,i),
        out matches Err(Error::Identity(i)) ==> i<rows.len() && !crate::verified_record::declared(rows@[i as int].1@,scheme,rows@[i as int].0),
        out matches Err(Error::Limit(i)) ==> i<rows.len() && rows@[i as int].1.len()>limit,
        out matches Err(Error::Order(i)) ==> 0<i<rows.len() && !ObjectId::digest_before(rows@[i as int-1].0.digest(),rows@[i as int].0.digest()),
        out matches Err(Error::Envelope(i)) ==> i<rows.len() && (compression@)(rows@[i as int].1@).len()+8>usize::MAX,
{
    let mut out=Vec::with_capacity(rows.len());
    let mut i=0usize;
    while i<rows.len()
        invariant i<=rows.len(),out.len()==i,ordered(rows@,i as nat),
            forall|r:&[u8]| #[trigger] encode.requires((r,)),
            forall|r:&[u8],v:Vec<u8>| #[trigger] encode.ensures((r,),v) ==> v@==(compression@)(r@),
            forall|j:int| 0<=j<i ==> #[trigger] admitted(rows@,scheme,limit,compression@,out@,j),
        decreases rows.len()-i,
    {
        let (id,body)=&rows[i];
        if !crate::verified_record::declares(body,scheme,*id) {return Err(Error::Identity(i));}
        if body.len() as u64>limit {return Err(Error::Limit(i));}
        let prior=if i==0 {None} else {Some(rows[i-1].0)};
        if !id.follows(prior) {return Err(Error::Order(i));}
        proof {
            assert forall|j:int,k:int| 0<=j<k<=i implies #[trigger] ObjectId::digest_before(rows@[j].0.digest(),rows@[k].0.digest()) by {
                if k==i && j<i-1 {
                    assert(ObjectId::digest_before(rows@[j].0.digest(),rows@[i as int-1].0.digest()));
                    assert(ObjectId::digest_before(rows@[i as int-1].0.digest(),id.digest()));
                    ObjectId::digest_order_transitive(rows@[j].0.digest(),rows@[i as int-1].0.digest(),id.digest());
                }
            }
        }
        let raw=body.as_slice();
        let compressed=encode(raw);
        let n=match storage::allocation(raw.len(),compressed.len()) {Ok(v)=>v,Err(())=>return Err(Error::Envelope(i))};
        let payload=if let Some(size)=n {
            let mut envelope=Vec::with_capacity(size);
            storage::pack(&mut envelope,raw.len() as u64,&compressed);
            Payload::Lz4(envelope)
        } else {Payload::Plain(raw)};
        assert(packed(body@,compression@,payload));
        let ghost previous=out@;
        out.push(payload);
        assert forall|j:int| 0<=j<=i implies #[trigger] admitted(rows@,scheme,limit,compression@,out@,j) by {
            if j<i {assert(admitted(rows@,scheme,limit,compression@,previous,j));}
        }
        i+=1;
    }
    Ok(out)
}

fn descriptors<'a>(payloads:&'a [Payload]) -> (rows:Vec<Stored<'a>>)
    ensures rows.len()==payloads.len(),forall|i:int| 0<=i<rows.len() ==> {
        let r=#[trigger] rows@[i];
        &&& r.body@==payloads@[i].bytes()
        &&& r.encoding.flag()==if payloads@[i] is Plain {0u8} else {1u8}
    },
{
    let mut rows:Vec<Stored>=Vec::with_capacity(payloads.len());
    let mut i=0usize;
    while i<payloads.len()
        invariant i<=payloads.len(),i==rows.len(),forall|j:int| 0<=j<i ==> {
            let r=#[trigger] rows@[j];
            &&& r.body@==payloads@[j].bytes()
            &&& r.encoding.flag()==if payloads@[j] is Plain {0u8} else {1u8}
        },
        decreases payloads.len()-i,
    {
        rows.push(payloads[i].descriptor());
        i+=1;
    }
    rows
}

spec fn raw_extent(rows:Seq<(ObjectId,Vec<u8>)>,count:nat) -> nat
    decreases count,
{
    if count==0 {0} else {raw_extent(rows,(count-1) as nat)+72nat+rows[count-1].1.len() as nat}
}

proof fn fits(rows:Seq<(ObjectId,Vec<u8>)>,stored:Seq<Stored>,n:nat)
    requires n<=rows.len()==stored.len(),forall|i:int| 0<=i<n ==> (#[trigger] stored[i]).body.len()<=rows[i].1.len(),
    ensures extent(stored,n)<=raw_extent(rows,n),
    decreases n,
{
    if n>0 {fits(rows,stored,(n-1) as nat);}
}

spec fn storage_bytes(raw:Seq<u8>,c:spec_fn(Seq<u8>)->Seq<u8>) -> Seq<u8> {
    if c(raw).len()+8<raw.len() {vstd::bytes::spec_u64_to_le_bytes(raw.len() as u64)+c(raw)} else {raw}
}

spec fn bound(o:Captured,id:ObjectId,raw:Seq<u8>,scheme:root_wire::Scheme,limit:u64,
    c:spec_fn(Seq<u8>)->Seq<u8>,image:Seq<u8>) -> bool {
    &&& crate::verified_record::declared(raw,scheme,id) && raw.len()<=limit
    &&& o.body@==storage_bytes(raw,c)
    &&& o.flags==(if c(raw).len()+8<raw.len() {1u8} else {0u8})
    &&& image.subrange(o.start as int+72,o.start as int+72+o.body.len())==o.body@
}

#[verifier::spinoff_prover]
#[verifier::rlimit(30)]
fn submit<M:crate::positional_read::Media,S:crate::group_frontier::BufferedWal,H,F,Open,C:Fn(&[u8])->Vec<u8>>(
    sequence:u64,begin:&[u8],rows:&[(ObjectId,Vec<u8>)],root:&[u8],scheme:root_wire::Scheme,limit:u64,
    encode:C,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>,sink:S,base:u64,chunk_size:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>) -> (out:Result<Released<M>,Error>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,Open:FnOnce(&S)->M,
    requires sequence!=0,sink.at_end(),sink.buffered_image().len()==base,
        288+begin.len()+raw_extent(rows@,rows.len() as nat)+root.len()<=usize::MAX,
        base as int+288+begin.len()+raw_extent(rows@,rows.len() as nat)+root.len()<=u64::MAX,
        forall|r:&[u8]| #[trigger] encode.requires((r,)),
        forall|r:&[u8],v:Vec<u8>| #[trigger] encode.ensures((r,),v) ==> v@==(compression@)(r@),
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
            forall|p:&[u8]| #[trigger] finish.requires((p,)),
            forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
    ensures out matches Ok(r) ==> {
        &&& (target@)(r.media)==sink.wal_target() && r.media.image().take(base as int)==sink.buffered_image()
        &&& ordered(rows@,rows.len() as nat) && r.objects.len()==rows.len() && r.roots.len()==1
        &&& r.marker.marker().counts.sequence==sequence && r.marker.marker().counts.objects==rows.len() && r.marker.marker().counts.roots==1
        &&& r.roots@[0].body@==root@ && r.media.image().subrange(r.roots@[0].start as int+72,r.roots@[0].start as int+72+root.len())==root@
        &&& forall|i:int| 0<=i<rows.len() ==> #[trigger] bound(r.objects@[i],rows@[i].0,rows@[i].1@,scheme,limit,compression@,r.media.image())
    },
    out matches Err(Error::Identity(i)) ==> i<rows.len() && !crate::verified_record::declared(rows@[i as int].1@,scheme,rows@[i as int].0),
    out matches Err(Error::Limit(i)) ==> i<rows.len() && rows@[i as int].1.len()>limit,
    out matches Err(Error::Order(i)) ==> 0<i<rows.len() && !ObjectId::digest_before(rows@[i as int-1].0.digest(),rows@[i as int].0.digest()),
    out matches Err(Error::Envelope(i)) ==> i<rows.len() && (compression@)(rows@[i as int].1@).len()+8>usize::MAX,
{
    let packed_rows=pack_rows(rows,scheme,limit,encode,compression)?;
    let stored=descriptors(&packed_rows);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert forall|i:int| 0<=i<rows.len() implies (#[trigger] stored@[i]).body.len()<=rows@[i].1.len() by {
            assert(admitted(rows@,scheme,limit,compression@,packed_rows@,i));
        }
        fits(rows@,stored@,rows.len() as nat);
    }
    let r=write_group(sequence,begin,&stored,root,sink,base,chunk_size,hash,checksum,finish,digest,reopen,target);
    proof {
        assert forall|i:int| 0<=i<rows.len() implies #[trigger] bound(r.objects@[i],rows@[i].0,rows@[i].1@,scheme,limit,compression@,r.media.image()) by {
            assert(r.objects@[i].body@==stored@[i].body@);
            assert(admitted(rows@,scheme,limit,compression@,packed_rows@,i));
            assert(stored@[i].body@==packed_rows@[i].bytes());
        }
    }
    Ok(r)
}

fn fits_wal(begin:usize,root:usize,rows:&[(ObjectId,Vec<u8>)],base:u64) -> (fits:bool)
    ensures fits==(288+begin+root+raw_extent(rows@,rows.len() as nat)<=usize::MAX &&
        base as int+288+begin+root+raw_extent(rows@,rows.len() as nat)<=u64::MAX),
{
    let Some(start)=begin.checked_add(288) else {return false;};
    let Some(mut size)=start.checked_add(root) else {return false;};
    let mut i=0usize;
    while i<rows.len()
        invariant i<=rows.len(),size as int==288+begin+root+raw_extent(rows@,i as nat),
        decreases rows.len()-i,
    {
        proof {raw_extent_le(rows@,(i+1) as nat,rows.len() as nat);}
        let Some(head)=size.checked_add(72) else {return false;};
        let Some(next)=head.checked_add(rows[i].1.len()) else {return false;};
        size=next;
        i+=1;
    }
    base.checked_add(size as u64).is_some()
}

proof fn raw_extent_le(rows:Seq<(ObjectId,Vec<u8>)>,i:nat,n:nat)
    requires i<=n<=rows.len(),ensures raw_extent(rows,i)<=raw_extent(rows,n),
    decreases n-i,
{
    if i<n {raw_extent_le(rows,i,(n-1) as nat);}
}

spec fn refused(rows:Seq<(ObjectId,Vec<u8>)>,scheme:root_wire::Scheme,limit:u64,c:spec_fn(Seq<u8>)->Seq<u8>,error:Error) -> bool {
    match error {
        Error::Identity(i)=>i<rows.len() && !crate::verified_record::declared(rows[i as int].1@,scheme,rows[i as int].0),
        Error::Limit(i)=>i<rows.len() && rows[i as int].1.len()>limit,
        Error::Order(i)=>0<i<rows.len() && !ObjectId::digest_before(rows[i as int-1].0.digest(),rows[i as int].0.digest()),
        Error::Envelope(i)=>i<rows.len() && c(rows[i as int].1@).len()+8>usize::MAX,
    }
}

enum GraphError { Closure(crate::closure_walk::Failure<ObjectId,ObjectId>), Capacity, Batch(Error) }

struct Publication<M> {
    wal_target:Ghost<(int,Seq<u8>)>, group:Released<M>, journal:crate::journal_transition::Record, rows:Ghost<Seq<(ObjectId,Vec<u8>)>>,
}

/// Journal all fresh declarations with the root chosen by the publication CAS.
/// Additional retained dependencies in the walk may already live on disk.
#[verifier::spinoff_prover]
#[verifier::rlimit(30)]
fn publish_fresh<M:crate::positional_read::Media,S:crate::group_frontier::BufferedWal,H,F,Open,C:Fn(&[u8])->Vec<u8>>(
    graph:&crate::hosted_kv_root_publication::Graph<Vec<u8>>,table:&BTreeMap<ObjectId,ObjectRecord>,version:crate::ObjectFormatVersion,
    owner:Owner,expected:Option<RootState>,scheme:root_wire::Scheme,sequence:u64,begin:&[u8],limit:u64,
    encode:C,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>,sink:S,base:u64,chunk_size:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>) -> (out:Result<Publication<M>,GraphError>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,Open:FnOnce(&S)->M,
    requires sequence!=0,sink.at_end(),sink.buffered_image().len()==base,graph.selected.binding().0@==owner.bytes(),
        graph.links(graph.selected.binding().0,expected,graph.records@[graph.component],version),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<ObjectRecord>(),
        btree_map_inv(table),btree_map_inv(&graph.records),
        forall|id:ObjectId| #[trigger] graph.records@.contains_key(id) ==> table@.contains_key(id) && table@[id]==graph.records@[id],
        forall|r:&[u8]| #[trigger] encode.requires((r,)),
        forall|r:&[u8],v:Vec<u8>| #[trigger] encode.ensures((r,),v) ==> v@==(compression@)(r@),
            forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
            forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
            forall|p:&[u8]| #[trigger] finish.requires((p,)),
            forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
    ensures out matches Ok(p) ==> {
        let r=p.group;
        let replacement=graph.selected.binding().2;
        &&& (target@)(r.media)==sink.wal_target() && r.media.image().take(base as int)==sink.buffered_image()
        &&& p.wal_target@==sink.wal_target() && ordered(p.rows@,p.rows@.len())
        &&& p.journal.principal@==owner.bytes() && p.journal.expected==expected && p.journal.replacement==replacement
        &&& r.marker.marker().counts.sequence==sequence && r.marker.marker().counts.objects==graph.records.len() && r.marker.marker().counts.roots==1
        &&& r.roots.len()==1 && r.roots@[0].body@==crate::journal_transition::wire(owner.bytes(),scheme,expected,replacement)
        &&& r.media.image().subrange(r.roots@[0].start as int+72,r.roots@[0].start as int+72+r.roots@[0].body.len())==r.roots@[0].body@
        &&& r.objects.len()==graph.records.len()
        &&& crate::hosted_kv_root_publication::canonical_rows(graph,p.rows@,scheme)
        &&& forall|i:int| 0<=i<p.rows@.len() ==> #[trigger] bound(r.objects@[i],p.rows@[i].0,p.rows@[i].1@,scheme,limit,compression@,r.media.image())
    },
    out matches Err(GraphError::Closure(crate::closure_walk::Failure::Source(k,e))) ==> k==e && !table@.contains_key(k),
    out matches Err(GraphError::Closure(crate::closure_walk::Failure::Cycle(k))) ==> crate::closure_walk::reaches(
        table@.map_values(|r:ObjectRecord| crate::closure_walk::children(r.contents().3)),Set::empty(),k,k),
    !(out matches Err(GraphError::Closure(crate::closure_walk::Failure::Root(_)))),
    out matches Err(GraphError::Capacity) ==> exists|rs:Seq<(ObjectId,Vec<u8>)>| #[trigger] crate::hosted_kv_root_publication::canonical_rows(graph,rs,scheme) && {
        let root=crate::journal_transition::wire(owner.bytes(),scheme,expected,graph.selected.binding().2);
        let size=288+begin.len()+root.len()+raw_extent(rs,rs.len());
        size>usize::MAX || base as int+size>u64::MAX
    },
    !(out matches Err(GraphError::Batch(Error::Identity(_)))),
    out matches Err(GraphError::Batch(e)) ==> exists|rs:Seq<(ObjectId,Vec<u8>)>| #[trigger] crate::hosted_kv_root_publication::canonical_rows(graph,rs,scheme) &&
        refused(rs,scheme,limit,compression@,e),
{
    let rows=match crate::hosted_kv_root_publication::fresh_rows(graph,table,version,scheme) {Ok(r)=>r,Err(e)=>return Err(GraphError::Closure(e))};
    let name=owner.encode();
    let replacement=graph.selected.replacement();
    let root=crate::journal_transition::encode(&name,scheme,expected,replacement).unwrap();
    if !fits_wal(begin.len(),root.len(),&rows,base) {
        assert(crate::hosted_kv_root_publication::canonical_rows(graph,rows@,scheme));
        return Err(GraphError::Capacity);
    }
    let ghost wal_target=sink.wal_target();
    let r=match submit(sequence,begin,&rows,&root,scheme,limit,encode,compression,sink,base,chunk_size,hash,checksum,finish,digest,reopen,target) {
        Ok(r)=>r, Err(e)=>{
            proof {match e {Error::Identity(i)=>{
                    let (k,raw)=rows@[i as int];
                    assert(raw@==crate::recovered_record::encoding(scheme,k,graph.records@[k]));
                    assert(raw@.subrange(0,2) =~= scheme.algorithm@);
                    assert(raw@.subrange(2,4) =~= scheme.construction@);
                    assert(raw@.subrange(4,8) =~= seq![32u8,0,0,0]);
                    assert(raw@.subrange(8,40) =~= k.digest());
                    assert(false);
                },Error::Limit(_)=>{},Error::Order(_)=>{},Error::Envelope(_)=>{}}
                assert(refused(rows@,scheme,limit,compression@,e));
                assert(crate::hosted_kv_root_publication::canonical_rows(graph,rows@,scheme));}
            return Err(GraphError::Batch(e));
        },
    };
    let journal=crate::hosted_acknowledged_root::parse_written(&r.roots[0].body,&name,scheme,expected,replacement);
    Ok(Publication{wal_target:Ghost(wal_target),group:r,journal,rows:Ghost(rows@)})
}

enum RecoveryError<E,A> { Arena(crate::arena_frame::BatchError<A>), Compression(usize,E), References(usize), Closure(crate::closure_walk::Failure<ObjectId,ObjectId>) }

spec fn codec_failure<E,D:Fn(&[u8],usize)->Result<Vec<u8>,E>>(block:Seq<u8>,size:usize,decode:D,error:E) -> bool {
    exists|b:&[u8]| b@==block && #[trigger] decode.ensures((b,size),Err(error))
}

proof fn same_children(a:Seq<crate::ObjectReference>,b:Seq<crate::ObjectReference>)
    requires a.len()==b.len(),forall|i:int| 0<=i<a.len() ==> #[trigger] a[i].fields()==b[i].fields(),
    ensures crate::closure_walk::children(a)==crate::closure_walk::children(b),
    decreases a.len(),
{
    if a.len()>0 {
        assert(a[0].fields()==b[0].fields());
        assert forall|i:int| 0<=i<a.skip(1).len() implies #[trigger] a.skip(1)[i].fields()==b.skip(1)[i].fields() by {
            assert(a.skip(1)[i]==a[i+1] && b.skip(1)[i]==b[i+1]);
        }
        same_children(a.skip(1),b.skip(1));
    }
}

/// Reconstruct the freshly declared part of the object table from the bodies
/// captured during stable WAL readback. Name each entry from its decoded fields.
#[verifier::spinoff_prover]
#[verifier::rlimit(35)]
#[verifier::loop_isolation(false)]
fn recover_closure<M:crate::positional_read::Media,E,D,H,A:crate::arena_frame::BatchFile,F:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    p:&Publication<M>,Ghost(graph):Ghost<&crate::hosted_kv_root_publication::Graph<Vec<u8>>>,
    version:crate::ObjectFormatVersion,scheme:root_wire::Scheme,limit:u64,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>,
    decode:D,hash:H,arena:&mut A,checksum:F)
    -> (out:Result<(BTreeMap<ObjectId,ObjectRecord>,BTreeMap<ObjectId,crate::ArenaLocation>),RecoveryError<E,A::Error>>)
    where D:Fn(&[u8],usize)->Result<Vec<u8>,E>,H:Fn(&ObjectRecord)->[u8;32]+Copy,
    requires old(arena).image().len()<=u64::MAX,old(arena).target()!=p.wal_target@,
        ordered(p.rows@,p.rows@.len()),
        forall|n:u64,b:&[u8]| #[trigger] checksum.requires((crate::arena_frame::ARENA_MAGIC,n,b)),
        p.journal.replacement==graph.selected.binding().2,
        graph.links(graph.selected.binding().0,graph.selected.binding().1,graph.records@[graph.component],version),
        crate::hosted_kv_root_publication::canonical_rows(graph,p.rows@,scheme),
        p.group.objects.len()==p.rows@.len(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        scheme.algorithm@!=seq![0u8,0u8],scheme.construction@!=seq![0u8,0u8],
        forall|i:int| 0<=i<p.rows@.len() ==> #[trigger] bound(p.group.objects@[i],p.rows@[i].0,p.rows@[i].1@,scheme,limit,compression@,p.group.media.image()),
        forall|id:ObjectId| #[trigger] graph.records@.contains_key(id) ==> ObjectRecord::labels_ordered(graph.records@[id].contents().3),
        forall|r:&ObjectRecord| #[trigger] hash.requires((r,)),
        forall|k:ObjectId,r:&ObjectRecord,d:[u8;32]| #[trigger] graph.records@.contains_key(k) &&
            crate::hosted_record_roundtrip::same_fields(*r,graph.records@[k]) && #[trigger] hash.ensures((r,),d) ==> d@==k.digest(),
        forall|b:&[u8],n:usize| #[trigger] decode.requires((b,n)),
        forall|i:int,b:&[u8],v:Vec<u8>| 0<=i<p.rows@.len() && b@==(compression@)(p.rows@[i].1@) &&
            #[trigger] decode.ensures((b,p.rows@[i].1.len()),Ok(v)) ==> v@==p.rows@[i].1@,
    ensures final(arena).target()==old(arena).target(),
        out matches Ok((t,index)) ==> index@.dom()==t@.dom() &&
        (forall|i:int| 0<=i<p.rows@.len() ==> #[trigger] arena_entry(index@[p.rows@[i].0],p.rows@[i].1@,final(arena).image(),old(arena).image().len())) &&
        final(arena).image().take(old(arena).image().len() as int)==old(arena).image() &&
        crate::closure_walk::closed(p.journal.replacement.commit,Set::empty(),
            crate::hosted_kv_root_publication::owning_edges(t@),t@.dom()) &&
        (exists|rank:Map<ObjectId,nat>| rank.dom()==t@.dom() && #[trigger] crate::closure_walk::ranked(
            crate::hosted_kv_root_publication::owning_edges(t@),Set::empty(),rank)) &&
        t@.dom()==graph.records@.dom() &&
        forall|k:ObjectId| #[trigger] t@.contains_key(k) ==> crate::hosted_record_roundtrip::same_fields(t@[k],graph.records@[k]),
        ((out matches Err(RecoveryError::References(_))) || (out matches Err(RecoveryError::Compression(_,_)))) ==> final(arena).image()==old(arena).image(),
        out matches Err(RecoveryError::Closure(_)) ==> final(arena).image().take(old(arena).image().len() as int)==old(arena).image() &&
            forall|i:int| 0<=i<p.rows@.len() ==> #[trigger] arena_contains(p.rows@[i].1@,final(arena).image(),old(arena).image().len()),
        out matches Err(RecoveryError::Arena(crate::arena_frame::BatchError::Write(e))) ==> A::write_failed(old(arena).target(),e),
        out matches Err(RecoveryError::Arena(crate::arena_frame::BatchError::Seek(e))) ==> old(arena).seek_failed(e) && final(arena).image()==old(arena).image(),
        out matches Err(RecoveryError::Arena(crate::arena_frame::BatchError::Overflow)) ==> final(arena).image()==old(arena).image() &&
            (raw_extent(p.rows@,p.rows@.len())>isize::MAX || old(arena).image().len()+raw_extent(p.rows@,p.rows@.len())>u64::MAX),
        out matches Err(RecoveryError::Closure(crate::closure_walk::Failure::Source(k,e))) ==> k==e && !graph.records@.contains_key(k),
        out matches Err(RecoveryError::Closure(crate::closure_walk::Failure::Cycle(k))) ==> crate::closure_walk::reaches(
            graph.records@.map_values(|r:ObjectRecord| crate::closure_walk::children(r.contents().3)),Set::empty(),k,k),
        !(out matches Err(RecoveryError::Closure(crate::closure_walk::Failure::Root(_)))),
        out matches Err(RecoveryError::References(i)) ==> i<p.rows@.len() && graph.records@[p.rows@[i as int].0].contents().3.len()>0,
        out matches Err(RecoveryError::Compression(i,e)) ==> i<p.rows@.len() && p.group.objects@[i as int].flags==1 &&
            codec_failure((compression@)(p.rows@[i as int].1@),p.rows@[i as int].1.len(),decode,e),
{
    let mut table=BTreeMap::new();
    let mut payloads:Vec<(ObjectId,Vec<u8>)>=Vec::new();
    let mut i=0;
    while i<p.group.objects.len()
        invariant i<=p.rows@.len(),btree_map_inv(&table),payloads.len()==i,
            forall|j:int| 0<=j<i ==> (#[trigger] payloads@[j]).0==p.rows@[j].0 && payloads@[j].1@==p.rows@[j].1@,
            forall|k:ObjectId| #[trigger] table@.contains_key(k) ==> graph.records@.contains_key(k) &&
                crate::hosted_record_roundtrip::same_fields(table@[k],graph.records@[k]),
            forall|j:int| 0<=j<i ==> table@.contains_key(#[trigger] p.rows@[j].0),
        decreases p.rows@.len()-i,
    {
        let ghost id=p.rows@[i as int].0;
        let ghost witness=p.rows@[i as int].1;
        let ghost source=&graph.records@[id];
        let capture=&p.group.objects[i];
        assert(bound(*capture,id,witness@,scheme,limit,compression@,p.group.media.image()));
        let expanded;
        let bytes=if capture.flags==0 {capture.body.as_slice()} else {
            proof {
                vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
                assert(capture.flags==1);
                assert(capture.body@==vstd::bytes::spec_u64_to_le_bytes(witness.len() as u64)+(compression@)(witness@));
                assert(capture.body.len()>=8);
            }
            let (size,block)=storage::split(&capture.body).unwrap();
            proof {
                vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
                assert(capture.body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(witness.len() as u64));
                assert(capture.body@.skip(8) =~= (compression@)(witness@));
            }
            expanded=match decode(block,size as usize) {
                Ok(v)=>v, Err(e)=>{
                    assert(decode.ensures((block,witness.len()),Err(e)));
                    assert(exists|b:&[u8]| b@==(compression@)(witness@) && #[trigger] decode.ensures((b,witness.len()),Err(e)));
                    assert(p.group.objects@[i as int].flags==1);
                    assert(exists|b:&[u8]| b@==(compression@)(p.rows@[i as int].1@) && #[trigger] decode.ensures((b,p.rows@[i as int].1.len()),Err(e)));
                    assert(codec_failure((compression@)(witness@),witness.len(),decode,e));
                    return Err(RecoveryError::Compression(i,e))
                },
            };
            expanded.as_slice()
        };
        proof {crate::hosted_record_roundtrip::canonical_shape(bytes@,*source,scheme,id);}
        let (key,record)=match crate::hosted_record_roundtrip::scan_written(bytes,Ghost(source),scheme,Ghost(id),hash) {
            Ok(row)=>row,Err(_)=>return Err(RecoveryError::References(i)),
        };
        table.insert(key,record);
        let mut payload=Vec::new();
        payload.extend_from_slice(bytes);
        payloads.push((key,payload));
        i+=1;
    }
    assert(table@.dom() =~= graph.records@.dom());
    proof {
        assert forall|j:int,k:int| 0<=j<k<payloads.len() implies (#[trigger] payloads@[j].0)!=(#[trigger] payloads@[k].0) by {
            assert(ObjectId::digest_before(p.rows@[j].0.digest(),p.rows@[k].0.digest()));
        }
    }
    proof {same_extent(payloads@,p.rows@,p.rows@.len());}
    let index=match append_fresh_arena(arena,&payloads,checksum) {Ok(index)=>index,Err(e)=>return Err(RecoveryError::Arena(e))};
    proof {
        assert forall|k:ObjectId| #[trigger] index@.contains_key(k) == table@.contains_key(k) by {
            if index@.contains_key(k) {
                let j=choose|i:int| 0<=i<payloads.len() && #[trigger] payloads@[i].0==k;
                assert(p.rows@[j].0==k);
            }
            if table@.contains_key(k) {
                assert(graph.records@.contains_key(k));
                let j=choose|i:int| 0<=i<p.rows@.len() && #[trigger] p.rows@[i].0==k;
                assert(payloads@[j].0==k);
            }
        }
        assert(index@.dom() =~= table@.dom());
        assert forall|i:int| 0<=i<p.rows@.len() implies #[trigger] arena_contains(p.rows@[i].1@,arena.image(),old(arena).image().len()) by {
            let row=payloads@[i];
            assert(arena_entry(index@[row.0],row.1@,arena.image(),old(arena).image().len()));
        }
    }
    let root=p.journal.replacement.commit;
    let ghost edges=table@.map_values(|r:ObjectRecord| crate::closure_walk::children(r.contents().3));
    proof {
        assert forall|k:ObjectId| #[trigger] table@.contains_key(k) implies
            crate::closure_walk::children(table@[k].contents().3)==crate::closure_walk::children(graph.records@[k].contents().3) by {
            same_children(table@[k].contents().3,graph.records@[k].contents().3);
        }
        assert(edges =~= graph.records@.map_values(|r:ObjectRecord| crate::closure_walk::children(r.contents().3)));
    }
    let rows=match crate::hosted_kv_root_publication::materialize::<Vec<u8>>(Ghost(graph),&table,root,version) {
        Ok(rows)=>rows,Err(e)=>return Err(RecoveryError::Closure(e)),
    };
    proof {
        let ids=crate::closure_load::row_ids(rows@).to_set();
        assert(ids =~= table@.dom());
    }
    Ok((table,index))
}
}
