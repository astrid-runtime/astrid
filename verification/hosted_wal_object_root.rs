//! Bind a committed Object and Root descriptor to one writer-produced WAL stream.
use super::*;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},laws_eq::obeys_concrete_eq,std_specs::btree::btree_map_inv};
verus! {

pub(super) struct ObjectRoot<M> {
    media:M,
    marker:CheckedMarker, object:Vec<u8>, root:Vec<u8>, object_start:u64, root_start:u64, flag:u8,
}

impl<M:crate::positional_read::Media> ObjectRoot<M> {
    /// Absolute descriptor offsets refer to the stored object and root payloads
    /// in the reopened file, including a nonempty pre-existing WAL prefix.
    closed spec fn stored(&self,base:u64,object_at:int,root_at:int) -> bool {
        let bytes=self.media.image();
        &&& base<=object_at && object_at+72+self.object.len()==root_at
        &&& root_at+72+self.root.len()+144==bytes.len()
        &&& bytes.subrange(object_at+72,root_at)==self.object@
        &&& bytes.subrange(root_at+72,root_at+72+self.root.len())==self.root@
    }
}

/// Transfer the framed group and scan the transferred bytes. The native object
/// writer may select plain or compressed storage before this measured write.
#[verifier::spinoff_prover]
#[verifier::rlimit(40)]
fn release<M:crate::positional_read::Media,H,F,T>(sequence:u64,begin:&[u8],object:&[u8],encoding:ObjectEncoding,root:&[u8],
    chunk_size:usize,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,
    digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,transfer:T,base:u64,prior:Ghost<Seq<u8>>,
    media_id:Ghost<spec_fn(M)->(int,Seq<u8>)>,wal_id:Ghost<(int,Seq<u8>)>) -> (out:Option<ObjectRoot<M>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
        T:FnOnce(Vec<u8>,[usize;3])->Option<(M,Vec<u8>)>,
    requires prior@.len()==base, sequence!=0,begin.len() as int+object.len()+root.len()+360<=usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
        forall|v:Vec<u8>,ends:[usize;3]| ends@[0]<=ends@[1]<=ends@[2]<=v.len() &&
            v.len()==begin.len()+object.len()+root.len()+360 ==> #[trigger] transfer.requires((v,ends)),
        forall|v:Vec<u8>,ends:[usize;3],m:M,r:Vec<u8>| #[trigger] transfer.ensures((v,ends),Some((m,r))) ==> r@==v@ && m.image()==prior@+v@ && (media_id@)(m)==wal_id@,
    ensures out.is_none() ==> exists|v:Vec<u8>,ends:[usize;3]| ends@[0]<=ends@[1]<=ends@[2]<=v.len() &&
            v.len()==begin.len()+object.len()+root.len()+360 && #[trigger] transfer.ensures((v,ends),None),
        out matches Some(r) ==> {
            let m=r.marker.marker();
            &&& (media_id@)(r.media)==wal_id@ && r.media.image().take(base as int)==prior@
            &&& r.stored(base,base as int+r.object_start,base as int+r.root_start)
            &&& r.object@==object@ && r.root@==root@ && r.flag==encoding.flag()
            &&& r.object_start as int==72+begin.len() && r.root_start as int==r.object_start as int+72+object.len()
            &&& m.counts.sequence==sequence && m.counts.logical==3 && m.counts.objects==1 && m.counts.roots==1
            &&& m.counts.bytes as int==60+begin.len()+object.len()+root.len()
            &&& m.digest==(digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
                wal_measurement::digest_header(WalRecordKind::Object,encoding.flag(),sequence,1,object.len() as u64)+object@+
                wal_measurement::digest_header(WalRecordKind::Root,0,sequence,2,root.len() as u64)+root@)
        },
{
    let (mut stream,c1,mut data)=write_data(Measured::begin(sequence,begin).ok()?,hash,checksum)?;
    let first=Record{next:stream.len(),kind:WalRecordKind::Begin,flags:0,sequence,ordinal:0,body:begin};
    let ghost first_frame=stream@;
    let flag=encoding.wire_flag();
    let (body,c2,object_digest)=write_data(Measured::append(c1,DataKind::Object(encoding),object).ok()?,hash,checksum)?;
    stream.extend_from_slice(&body);
    data.extend_from_slice(&object_digest);
    let second=Record{next:stream.len(),kind:WalRecordKind::Object,flags:flag,sequence,ordinal:1,body:object};
    let (journal,c3,root_digest)=write_data(Measured::append(c2,DataKind::Root,root).ok()?,hash,checksum)?;
    stream.extend_from_slice(&journal);
    data.extend_from_slice(&root_digest);
    let third=Record{next:stream.len(),kind:WalRecordKind::Root,flags:0,sequence,ordinal:2,body:root};
    let text=data.as_slice();
    let sum=finish(text);
    let marker=commit_wire::Marker{counts:c3,digest:sum};
    let frame=marker.frame(vec![0u8;52],hash)?;
    stream.extend_from_slice(&frame);
    let commit_bytes=marker.encode();
    let commit=Record{next:stream.len(),kind:WalRecordKind::Commit,flags:0,sequence,ordinal:3,body:&commit_bytes};
    let ghost rows=seq![first,second,third];
    let ghost layout=Layout{rows,states:seq![c1,c2,c3],commit};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let (p,q)=choose|p:&[u8],q:[u8;32]| p@==marker.payload() && #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            frame@==(physical::Envelope{version:1,size:p.len() as u64,checksum:q}).wire()+p@;
        assert(hash.ensures((physical::MAGIC,p.len() as u64,p),q));
        assert(frame@==frame_bytes(marker.payload(),1,checksum@));
        assert(stream@ =~= first_frame+body@+journal@+frame@);
        assert(stream@.take(first.next as int) =~= first_frame);
        assert(stream@.subrange(first.next as int,second.next as int) =~= body@);
        assert(stream@.subrange(second.next as int,third.next as int) =~= journal@);
        assert(stream@.subrange(third.next as int,commit.next as int) =~= frame@);
        reveal(at_record);
        assert(at_record(stream@,0,first,u64::MAX,checksum@));
        assert(at_record(stream@,first.next as int,second,u64::MAX,checksum@));
        assert(at_record(stream@,second.next as int,third,u64::MAX,checksum@));
        assert(at_record(stream@,third.next as int,commit,u64::MAX,checksum@));
        reveal_with_fuel(transcript,4);
        assert(rows.drop_last() =~= seq![first,second]);
        assert(seq![first,second].drop_last() =~= seq![first]);
        assert(seq![first].drop_last() =~= Seq::<Record>::empty());
        assert(data@ =~= transcript(rows));
        assert(finish.ensures((text,),sum));
        reveal(complete);
        assert forall|i:int| 0<i<rows.len() implies at_record(stream@,rows[i-1].next as int,
            #[trigger] rows[i],u64::MAX,checksum@) && step(rows[i],layout.states[i-1],layout.states[i]) by {
            if i==1 {} else {assert(i==2);}
        }
        assert(complete(layout,stream@,0,u64::MAX,checksum@,digest@));
    }
    let (media,stream)=transfer(stream,[first.next,second.next,third.next])?;
    let found=scan_transaction(&stream,0,u64::MAX,chunk_size,hash,checksum,finish,digest,Ghost(Some(layout)))?;
    proof {
        reveal_with_fuel(selected,4);
        assert(found.batch.contents().objects =~= seq![second]);
        assert(found.batch.contents().roots =~= seq![third]);
        assert(found.marker.marker()==marker && found.end==stream.len());
        assert(data@ =~= chunk(first)+chunk(second)+chunk(third));
        let expected=wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
            wal_measurement::digest_header(WalRecordKind::Object,flag,sequence,1,object.len() as u64)+object@+
            wal_measurement::digest_header(WalRecordKind::Root,0,sequence,2,root.len() as u64)+root@;
        assert(data@ =~= expected);
        assert(found.marker.marker().digest==(digest@)(expected));
    }
    let o=found.batch.objects()[0];let r=found.batch.roots()[0];
    let mut recovered=Vec::new();recovered.extend_from_slice(o.body);
    let mut bound=Vec::new();bound.extend_from_slice(r.body);
    proof {
        assert(media.image().take(base as int) =~= prior@);
        reveal(at_record);
        assert(stream@.subrange(first.next as int+72,second.next as int) =~= object@);
        assert(stream@.subrange(second.next as int+72,third.next as int) =~= root@);
        assert(media.image().subrange(base as int+first.next+72,base as int+second.next) =~= object@);
        assert(media.image().subrange(base as int+second.next+72,base as int+third.next) =~= root@);
    }
    let released=ObjectRoot{media,marker:found.marker,object:recovered,root:bound,flag:o.flags,
        object_start:(o.next-(72+o.body.len())) as u64,root_start:(r.next-(72+r.body.len())) as u64};
    proof {
        assert(released.object_start==first.next && released.root_start==second.next);
        assert(base as int+third.next+144==released.media.image().len());
        assert(released.object@==object@ && released.root@==root@);
        let object_at=base as int+released.object_start;
        let root_at=base as int+released.root_start;
        let image=released.media.image();
        assert(base<=object_at && object_at+72+released.object.len()==root_at);
        assert(root_at+72+released.root.len()+144==image.len());
        assert(image.subrange(object_at+72,root_at)==released.object@);
        assert(image.subrange(root_at+72,root_at+72+released.root.len())==released.root@);
        assert(released.stored(base,base as int+released.object_start,base as int+released.root_start));
    }
    Some(released)
}

fn acknowledged_object_root<S:crate::group_frontier::BufferedWal,M:crate::positional_read::Media,Open:FnOnce(&S)->M,H,F>(
    sequence:u64,begin:&[u8],object:&[u8],encoding:ObjectEncoding,root:&[u8],chunk:usize,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,sink:S,base:u64,reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
    -> (out:Option<ObjectRoot<M>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires sequence!=0,begin.len() as int+object.len()+root.len()+360<=usize::MAX,
        sink.at_end(),sink.buffered_image().len()==base,base as int+begin.len()+object.len()+root.len()+360<=u64::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
        forall|s:&S| #[trigger] reopen.requires((s,)),
        forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
            forall|at:u64,e:M::Error| base<=at<base as int+begin.len()+object.len()+root.len()+360 ==> !#[trigger] m.io_error(at,e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
    ensures out matches Some(r) && {
            let m=r.marker.marker();
            &&& (target@)(r.media)==sink.wal_target() && r.media.image().take(base as int)==sink.buffered_image()
            &&& r.stored(base,r.object_start as int,r.root_start as int)
            &&& r.object@==object@ && r.root@==root@ && r.flag==encoding.flag()
            &&& r.object_start as int==base as int+72+begin.len() && r.root_start as int==r.object_start as int+72+object.len()
            &&& m.counts.sequence==sequence && m.counts.logical==3 && m.counts.objects==1 && m.counts.roots==1
            &&& m.counts.bytes as int==60+begin.len()+object.len()+root.len()
            &&& m.digest==(digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
                wal_measurement::digest_header(WalRecordKind::Object,encoding.flag(),sequence,1,object.len() as u64)+object@+
                wal_measurement::digest_header(WalRecordKind::Root,0,sequence,2,root.len() as u64)+root@)
        },
{
    let ghost before=sink.buffered_image();
    let ghost original_target=sink.wal_target();
    let transfer=move |submitted:Vec<u8>,ends:[usize;3]| -> (out:Option<(M,Vec<u8>)>)
        requires ends@[0]<=ends@[1]<=ends@[2]<=submitted.len(),submitted.len()==begin.len()+object.len()+root.len()+360,
            sink.at_end(),sink.buffered_image()==before,before.len()==base,sink.wal_target()==original_target,
            base as int+submitted.len()<=u64::MAX,
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at<base as int+submitted.len() ==> !#[trigger] m.io_error(at,e),
        ensures out matches Some((media,read)) && read@==submitted@ && media.image()==before+submitted@ &&
            (target@)(media)==original_target,
    {
        let mut sink=sink;
        let [first,second,third]=ends;
        sink.append_record(&submitted[..first]).ok()?;
        sink.append_record(&submitted[first..second]).ok()?;
        sink.append_record(&submitted[second..third]).ok()?;
        sink.append_record(&submitted[third..]).ok()?;
        assert(sink.buffered_image() =~= before+submitted@);
        sync_and_read(sink,&submitted,base,reopen,target,Ghost(before))
    };
    let mut r=release(sequence,begin,object,encoding,root,chunk,hash,checksum,finish,digest,transfer,base,Ghost(before),target,Ghost(original_target))?;
    r.object_start=base.checked_add(r.object_start)?;
    r.root_start=base.checked_add(r.root_start)?;
    Some(r)
}

enum CodecError<E> { Envelope, Decoder(E) }

spec fn decoder_failure<E,D:FnOnce(&[u8],usize)->Result<Vec<u8>,E>>(compressed:Seq<u8>,size:usize,decode:D,e:E) -> bool {
    &&& compressed.len()+8<size
    &&& exists|block:&[u8]| block@==compressed && #[trigger] decode.ensures((block,size),Err(e))
}

/// Reopen the complete WAL group before unpacking its object. Only the LZ4
/// block primitive is supplied by the caller. Its envelope and length are checked here.
fn canonical_group<Encoder,Decoder,E,S:crate::group_frontier::BufferedWal,M:crate::positional_read::Media,Open:FnOnce(&S)->M,H,F>(
    sequence:u64,begin:&[u8],object:&[u8],encode:Encoder,decode:Decoder,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>,root:&[u8],chunk:usize,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,sink:S,base:u64,reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
    -> (out:Result<(ObjectRoot<M>,Vec<u8>),CodecError<E>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
        Encoder:FnOnce(&[u8])->Vec<u8>,Decoder:FnOnce(&[u8],usize)->Result<Vec<u8>,E>,
    requires sequence!=0,begin.len() as int+object.len()+root.len()+360<=usize::MAX,
        sink.at_end(),sink.buffered_image().len()==base,base as int+begin.len()+object.len()+root.len()+360<=u64::MAX,
        encode.requires((object,)),
        forall|v:Vec<u8>| #[trigger] encode.ensures((object,),v) ==> v@==(compression@)(object@),
        forall|b:&[u8],n:usize| #[trigger] decode.requires((b,n)),
        forall|b:&[u8],v:Vec<u8>| b@==(compression@)(object@) &&
            #[trigger] decode.ensures((b,object.len()),Ok(v)) ==> v@==object@,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
        forall|s:&S| #[trigger] reopen.requires((s,)),
        forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
            forall|at:u64,e:M::Error| base<=at<base as int+begin.len()+object.len()+root.len()+360 ==> !#[trigger] m.io_error(at,e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
    ensures out matches Ok((r,canonical)) ==> {
        &&& (target@)(r.media)==sink.wal_target() && r.media.image().take(base as int)==sink.buffered_image() && r.stored(base,r.object_start as int,r.root_start as int)
        &&& canonical@==object@ && r.root@==root@ && r.object_start as int==base as int+72+begin.len()
        &&& r.root_start as int==r.object_start as int+72+r.object.len()
        &&& if (compression@)(object@).len()+8<object.len() {
            r.flag==1 && r.object@==vstd::bytes::spec_u64_to_le_bytes(object.len() as u64)+(compression@)(object@)
        } else {r.flag==0 && r.object@==object@}
        &&& r.marker.marker().counts.sequence==sequence && r.marker.marker().counts.logical==3 &&
            r.marker.marker().counts.objects==1 && r.marker.marker().counts.roots==1
        &&& r.marker.marker().digest==(digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
            wal_measurement::digest_header(WalRecordKind::Object,r.flag,sequence,1,r.object.len() as u64)+r.object@+
            wal_measurement::digest_header(WalRecordKind::Root,0,sequence,2,root.len() as u64)+root@)
    }, out matches Err(CodecError::Envelope) ==> (compression@)(object@).len()+8>usize::MAX,
        out matches Err(CodecError::Decoder(e)) ==> decoder_failure((compression@)(object@),object.len(),decode,e),
{
    use crate::wal_object_storage as storage;
    let compressed=encode(object);
    let selection=match storage::allocation(object.len(),compressed.len()) {Ok(v)=>v,Err(())=>return Err(CodecError::Envelope)};
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    let mut envelope=Vec::new();
    let (encoding,stored)=if let Some(_)=selection {
        storage::pack(&mut envelope,object.len() as u64,&compressed);
        (ObjectEncoding::Lz4,envelope.as_slice())
    } else {(ObjectEncoding::Plain,object)};
    assert(stored.len()<=object.len());
    let r=acknowledged_object_root(sequence,begin,stored,encoding,root,chunk,hash,checksum,finish,digest,
        sink,base,reopen,target).unwrap();
    let canonical=if r.flag==0 {
        let mut copy=Vec::new();copy.extend_from_slice(&r.object);copy
    } else {
        let (size,block)=storage::split(&r.object).unwrap();
        proof {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(r.object@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(object.len() as u64));
            assert(r.object@.skip(8) =~= compressed@);
        }
        match decode(block,size as usize) {
            Ok(bytes)=>bytes,
            Err(e)=>{
                assert(decode.ensures((block,object.len()),Err(e)));
                assert((compression@)(object@).len()+8<object.len());
                assert(block@==(compression@)(object@));
                assert(exists|b:&[u8]| b@==(compression@)(object@) && #[trigger] decode.ensures((b,object.len()),Err(e)));
                assert(decoder_failure((compression@)(object@),object.len(),decode,e));
                return Err(CodecError::Decoder(e))
            },
        }
    };
    Ok((r,canonical))
}

struct MarkerFold<M> {
    group:ObjectRoot<M>,id:ObjectId,location:crate::ArenaLocation,graph:crate::hosted_kv_root_publication::Graph<Vec<u8>>,journal:crate::journal_transition::Record,
}
enum FoldError<IO,E> { Publication(crate::hosted_kv_root_publication::Error), Capacity, Codec(CodecError<E>), Arena(crate::arena_frame::BatchError<IO>) }

/// Fold the stored object released by the acknowledged group. Return the root
/// decoded from its companion descriptor for subsequent closure and CAS checks.
fn fold_token_group<A:crate::arena_frame::BatchFile,Identify,Encoder,Decoder,E,S:crate::group_frontier::BufferedWal,M:crate::positional_read::Media,Open:FnOnce(&S)->M,H,F>(
    sequence:u64,begin:&[u8],arena:&mut A,scheme:root_wire::Scheme,owner:Owner,expected:Option<RootState>,
    state_refs:Vec<crate::ObjectReference>,commit_refs:Vec<crate::ObjectReference>,
    pending:&std::collections::BTreeMap<Vec<u8>,RootState>,published:&std::collections::BTreeMap<Vec<u8>,RootState>,
    kind:crate::token_authority::Marker,token:[u8;16],previous:Option<ObjectId>,depth:u64,used:u64,totals:crate::checkpoint_totals::NodeTotals,
    identify:Identify,encode:Encoder,decode:Decoder,compression:Ghost<spec_fn(Seq<u8>)->Seq<u8>>,chunk:usize,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,sink:S,base:u64,reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
    -> (out:Result<MarkerFold<M>,FoldError<A::Error,E>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
        Identify:Fn(&ObjectRecord)->ObjectId+Copy,Encoder:FnOnce(&[u8])->Vec<u8>,Decoder:FnOnce(&[u8],usize)->Result<Vec<u8>,E>,
    requires obeys_cmp::<crate::ObjectReference>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        obeys_concrete_eq::<ObjectRecord>(),obeys_cmp::<Vec<u8>>(),obeys_cmp_concrete_eq::<Vec<u8>>(),
        btree_map_inv(pending),btree_map_inv(published),sequence!=0,depth<u64::MAX,used as int+65<=u64::MAX,
        sink.at_end(),sink.buffered_image().len()==base,old(arena).image().len()<=u64::MAX,
        old(arena).target()!=sink.wal_target(),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
        forall|object:&[u8]| #[trigger] encode.requires((object,)),
        forall|object:&[u8],v:Vec<u8>| #[trigger] encode.ensures((object,),v) ==> v@==(compression@)(object@),
        forall|b:&[u8],n:usize| #[trigger] decode.requires((b,n)),
        forall|b:&[u8],v:Vec<u8>,original:&[u8]| b@==#[trigger] (compression@)(original@) &&
            #[trigger] decode.ensures((b,original.len()),Ok(v)) ==> v@==original@,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
        forall|s:&S| #[trigger] reopen.requires((s,)),
        forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
            forall|at:u64,e:M::Error| base<=at ==> !#[trigger] m.io_error(at,e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
    ensures final(arena).target()==old(arena).target(),
        out matches Err(e) && !(e is Arena) ==> final(arena).image()==old(arena).image(),
        out matches Ok(fold) ==> {
            let at=fold.location.offset as int+crate::arena_frame::WIDTH;
            let ticket=fold.group;
            let g=fold.graph;
            let principal=g.selected.binding().0;
            let replacement=g.selected.binding().2;
            let record=g.records@[fold.id];
            let payload=final(arena).image().subrange(at,at+fold.location.payload_len);
            &&& (target@)(ticket.media)==sink.wal_target() && ticket.media.image().take(base as int)==sink.buffered_image()
            &&& ticket.stored(base,ticket.object_start as int,ticket.root_start as int)
            &&& if (compression@)(payload).len()+8<payload.len() {
                ticket.flag==1 && ticket.object@==vstd::bytes::spec_u64_to_le_bytes(payload.len() as u64)+(compression@)(payload)
            } else {ticket.flag==0 && ticket.object@==payload}
            &&& final(arena).image().take(old(arena).image().len() as int)==old(arena).image()
            &&& fold.location.offset>=old(arena).image().len() && at+fold.location.payload_len<=final(arena).image().len()
            &&& final(arena).image().subrange(at+8,at+40)==fold.id.digest()
            &&& principal@==owner.bytes() && g.component==fold.id
            &&& (exists|v:crate::ObjectFormatVersion| v.number()==4 && #[trigger] g.links(principal,expected,record,v))
            &&& (if pending@.contains_key(principal) {Some(pending@[principal])} else {published@.get(principal)})==expected
            &&& forall|id:ObjectId| g.records@.contains_key(id) ==> #[trigger] identify.ensures((&g.records@[id],),id)
            &&& record.contents().2==crate::hosted_journal_history::component_bytes(final(arena).image(),fold.location)
            &&& forall|text:Seq<u8>| #[trigger] crate::marker_key::spells(token@,text) ==>
                crate::hosted_delta_mutation::marker_bytes(record.contents().2,
                    crate::hosted_token_recovery::ns_bytes(kind)+seq![0u8]+text)
            &&& fold.journal.principal@==owner.bytes() && fold.journal.expected==expected && fold.journal.replacement==replacement
            &&& ticket.object_start as int==base as int+72+begin.len() && ticket.root_start as int==ticket.object_start as int+72+ticket.object.len()
            &&& ticket.marker.marker().counts.sequence==sequence && ticket.marker.marker().counts.objects==1 &&
                ticket.marker.marker().counts.roots==1 && ticket.marker.marker().counts.logical==3
            &&& ticket.root@==crate::journal_transition::wire(owner.bytes(),scheme,expected,replacement)
            &&& ticket.marker.marker().digest==(digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
                wal_measurement::digest_header(WalRecordKind::Object,ticket.flag,sequence,1,ticket.object.len() as u64)+ticket.object@+
                wal_measurement::digest_header(WalRecordKind::Root,0,sequence,2,ticket.root.len() as u64)+ticket.root@)
        },
{
    use crate::hosted_token_recovery::marker_append;
    use vstd::string::StringSliceAdditionalSpecFns;
    let (namespace,text)=kind.address(crate::marker_key::encode(&token));
    let ns=namespace.as_bytes();
    let key=crate::encoding::composite(ns,&text);
    proof {
        reveal_strlit("caps:used");reveal_strlit("caps:revoked");
        vstd::string::is_ascii_spec_bytes("caps:used");vstd::string::is_ascii_spec_bytes("caps:revoked");
        assert(ns@==crate::hosted_token_recovery::ns_bytes(kind));
    }
    let (record,_)=crate::hosted_delta_mutation::written_marker(key,previous,depth,used,totals);
    let graph=match crate::hosted_kv_root_publication::prepare(owner.encode(),expected,record,state_refs,commit_refs,
        crate::ObjectFormatVersion::new(4).unwrap(),identify,pending,published) {
        Ok(g)=>g,Err(e)=>return Err(FoldError::Publication(e)),
    };
    let replacement=graph.selected.replacement();
    let id=graph.component;
    let record=graph.records.get(&id).unwrap();
    let canonical=crate::verified_record::encode(scheme,id,record).unwrap();
    let name=owner.encode();
    let wire=crate::journal_transition::encode(&name,scheme,expected,replacement).unwrap();
    let Some(first)=begin.len().checked_add(360) else {return Err(FoldError::Capacity)};
    let Some(next)=first.checked_add(canonical.len()) else {return Err(FoldError::Capacity)};
    let Some(extent)=next.checked_add(wire.len()) else {return Err(FoldError::Capacity)};
    if base.checked_add(extent as u64).is_none() {return Err(FoldError::Capacity);}
    let (group,recovered)=match canonical_group(sequence,begin,&canonical,encode,decode,compression,&wire,chunk,
        hash,checksum,finish,digest,sink,base,reopen,target) {Ok(pair)=>pair,Err(e)=>return Err(FoldError::Codec(e))};
    let journal=crate::hosted_acknowledged_root::parse_written(&group.root,&name,scheme,expected,replacement);
    let location=match marker_append::append_payload(arena,recovered,vec![Vec::new()],0,hash) {Ok(loc)=>loc,Err(e)=>return Err(FoldError::Arena(e))};
    proof {
        marker_append::encoded_fields(arena.image(),location,canonical@,scheme,id,*record);
        assert forall|spelling:Seq<u8>| #[trigger] crate::marker_key::spells(token@,spelling) implies
            crate::hosted_delta_mutation::marker_bytes(record.contents().2,crate::hosted_token_recovery::ns_bytes(kind)+seq![0u8]+spelling)
            by {crate::marker_key::unique_text(token@,text@,spelling);}
    }
    Ok(MarkerFold{group,id,location,graph,journal})
}
}
