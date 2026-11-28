//! Construct a complete layout from the real Begin, Root and Commit encoders.
use super::*;
use crate::{ObjectId,ObjectRecord,RootState,root_declaration,transaction_records};
use std::collections::BTreeMap;
use crate::wal_root_history::{self as table,Decision};
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};
use crate::{owner_codec::{self,Owner},root_wire,root_transition::{self,Version,Replay}};
use vstd::prelude::*;

verus! {

/// An unsealed content transaction must recheck every supplied row before the
/// durable preparation can select a generation under the transaction's owner.
fn admit_content<P:Ord,H:Fn(&ObjectRecord)->ObjectId>(pending:&BTreeMap<P,RootState>,published:&BTreeMap<P,RootState>,
    owner:P,expected:Option<RootState>,commit:ObjectId,rows:Vec<(ObjectId,ObjectRecord)>,identify:H)
    -> (out:Result<Result<RootState,root_transition::SelectionError>,(ObjectId,ObjectId)>)
    requires obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),btree_map_inv(pending),btree_map_inv(published),
        forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures ({
        let actual = if pending@.contains_key(owner) {Some(pending@[owner])}
            else if published@.contains_key(owner) {Some(published@[owner])} else {None};
        match out {
            Err((bad,computed)) => exists|i:int| 0 <= i < rows.len() && rows@[i].0 == bad &&
                #[trigger] identify.ensures((&rows@[i].1,),computed) && computed.digest() != bad.digest() &&
                forall|j:int| 0 <= j < i ==> #[trigger] transaction_records::authentic(rows@[j],identify),
            Ok(selected) => {
                &&& forall|j:int| 0 <= j < rows.len() ==> #[trigger] transaction_records::authentic(rows@[j],identify)
                &&& match selected {
                    Err(root_transition::SelectionError::Conflict {expected:e,actual:a}) => e == expected && a == actual && a != e,
                    Err(root_transition::SelectionError::Overflow) => expected == actual && (actual matches Some(r) && r.generation.value() == u64::MAX),
                    Ok(r) => r.commit == commit && actual == expected && match actual {
                        None => r.generation.value() == 0, Some(old) => r.generation.value() == old.generation.value()+1,
                    },
                }
            },
        }
    }),
{
    let declaration = root_declaration::Declaration::<P,u8>::untrusted(owner,expected,commit,rows);
    let (update,kind) = declaration.admit(&0,|a:&u8,b:&u8| *a == *b,identify)?;
    assert(kind is Rechecked);
    match root_transition::select_update(pending,published,update) {
        Ok((selected,batch)) => {
            assert(batch == rows);
            assert(selected.binding().0 == owner && selected.binding().1 == expected);
            Ok(Ok(selected.replacement()))
        },
        Err(e) => Ok(Err(e)),
    }
}

/// Model the native engine identity relation by equality on opaque authority
/// names. Only a matching session may transfer its private checkpoint.
fn admit_sealed<P,C,H:Fn(&ObjectRecord)->ObjectId>(update:root_declaration::Update<P>,
    issuer:u64,receiver:u64,checkpoint:&mut Option<C>,identify:H)
    -> (out:Result<(root_declaration::Update<P>,Option<C>),(ObjectId,ObjectId)>)
    requires forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures match out {
        Ok((accepted,hint)) => accepted == update && (if issuer == receiver {
            hint == *old(checkpoint) && final(checkpoint).is_none()
        } else {
            hint.is_none() && *final(checkpoint) == *old(checkpoint) &&
                forall|i:int| 0 <= i < update.records.len() ==> #[trigger] transaction_records::authentic(update.records@[i],identify)
        }),
        Err((bad,computed)) => issuer != receiver && *final(checkpoint) == *old(checkpoint) &&
            exists|i:int| 0 <= i < update.records.len() && update.records@[i].0 == bad &&
                #[trigger] identify.ensures((&update.records@[i].1,),computed) && computed.digest() != bad.digest() &&
                forall|j:int| 0 <= j < i ==> #[trigger] transaction_records::authentic(update.records@[j],identify),
    },
{
    let declaration = root_declaration::Declaration::sealed(update,issuer);
    let same = |a:&u64,b:&u64| -> (equal:bool) ensures equal == (*a == *b) { *a == *b };
    declaration.admit_with_checkpoint(&receiver,same,identify,checkpoint)
}

/// The same identity session may consume exactly the hint constructed from
/// the sealed declaration's own principal and commit. A peer never gets it.
fn checkpoint_recipient<H:Fn(&ObjectRecord)->ObjectId>(update:root_declaration::Update<u64>,issuer:u64,
    receiver:u64,root:RootState,hash:H)
    -> (out:(Result<(root_declaration::Update<u64>,Option<(u64,ObjectId)>),(ObjectId,ObjectId)>,Option<(u64,RootState)>))
    requires forall|r:&ObjectRecord| #[trigger] hash.requires((r,)),
    ensures issuer == receiver ==> out.0.is_ok(),
        out.0 matches Ok((accepted,hint)) ==> accepted == update &&
            hint == if issuer == receiver {Some((update.principal,update.commit))} else {None},
        out.1 == if root.commit == update.commit {Some((update.principal,root))} else {None},
{
    let declaration = root_declaration::Declaration::sealed(update,issuer);
    let target = declaration.checkpoint_target();
    let mut slot = None;
    declaration.attach_checkpoint(&mut slot,|owner:&u64,id:ObjectId| -> (v:(u64,ObjectId))
        ensures v == (*owner,id), {(*owner,id)});
    let same = |a:&u64,b:&u64| -> (v:bool) ensures v == (*a == *b) {*a == *b};
    let result = declaration.admit_with_checkpoint(&receiver,same,hash,&mut slot);
    let fallback = target.publish(root,|owner:u64,r:RootState| -> (v:(u64,RootState))
        ensures v == (owner,r), {(owner,r)});
    (result,fallback)
}

fn untrusted_hint<C>(owner:u64,commit:ObjectId,slot:&mut Option<C>,make:impl FnOnce(&u64,ObjectId)->C)
    ensures *final(slot) == *old(slot),
{
    let raw = root_declaration::Declaration::<u64,u64>::untrusted(owner,None,commit,Vec::new());
    raw.attach_checkpoint(slot,make);
}

/// The journal callback receives the root retained across closure validation.
fn journal_selected<P,E,T,F,W>(selected:root_transition::SelectedRoot<P>,encoder:F,write:W)
    -> (out:Result<(root_transition::PreparedRoot<P,RootState>,T),E>)
    where F:FnOnce(&P,Option<RootState>,RootState)->Result<Vec<u8>,E>,
        W:FnOnce(&P,Option<RootState>,RootState,&Vec<u8>)->T,
    requires encoder.requires((&selected.binding().0,selected.binding().1,selected.binding().2)),
        forall|bytes:&Vec<u8>| #[trigger] write.requires((&selected.binding().0,selected.binding().1,selected.binding().2,bytes)),
    ensures match out {
        Ok((prepared,t)) => {
            let (p,e,r,bytes) = prepared.binding();
            &&& (p,e,r) == selected.binding()
            &&& encoder.ensures((&p,e,r),Ok(bytes))
            &&& write.ensures((&p,e,r,&bytes),t)
        },
        Err(error) => encoder.ensures((&selected.binding().0,selected.binding().1,selected.binding().2),Err(error)),
    },
{
    let prepared = selected.encode(encoder)?;
    let t = prepared.write_wal(write);
    Ok((prepared,t))
}

/// Between two preparations under the group writer lock, the same owner sees
/// its staged version and every other owner still sees its prior effective root.
fn subsequent_prepare<P:Ord+Clone>(pending:&mut BTreeMap<P,crate::RootState>,published:&BTreeMap<P,crate::RootState>,
    accepted:&root_transition::PreparedRoot<P,crate::RootState>,owner:&P,expected:Option<crate::RootState>)
    -> (out:root_transition::Advance)
    requires obeys_cmp::<P>(), obeys_cmp_concrete_eq::<P>(), vstd::pervasive::obeys_clone_eq::<P>(),
        btree_map_inv(old(pending)), btree_map_inv(published),
    ensures ({
        let before = old(pending)@;
        let (p,_,r,_) = accepted.binding();
        let observed = if *owner == p { Some(r) } else if before.contains_key(*owner) { Some(before[*owner]) }
            else if published@.contains_key(*owner) { Some(published@[*owner]) } else { None };
        &&& (out is Conflict) == (observed != expected)
        &&& (out is Overflow) == (observed == expected
            && (observed matches Some(v) && v.generation.value() == u64::MAX))
        &&& out matches root_transition::Advance::Next(n) ==> match observed {
            None => n == 0, Some(v) => n as int == v.generation.value() as int + 1,
        }
    }),
{
    accepted.stage(pending);
    root_transition::admit_current(pending,published,owner,expected).1
}

spec fn frame_bytes(payload:Seq<u8>,version:u8,checksum:spec_fn(Seq<u8>)->[u8;32]) -> Seq<u8> {
    (physical::Envelope {version,size:payload.len() as u64,checksum:checksum(payload)}).wire() + payload
}

fn write_data<H>(record:Measured,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<(Vec<u8>,Counts,Vec<u8>)>) where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
    ensures out matches Some((frame,c,d)) && {
        let (k,f,o,counts,b) = record.parts();
        &&& c == counts
        &&& frame@ == frame_bytes(record.payload(),if f==0 {1} else {2},checksum@)
        &&& d@ == wal_measurement::digest_header(k,f,c.sequence,o,b.len() as u64) + b@
    },
{
    let collect = |header:&[u8],body:&[u8]| -> (bytes:Vec<u8>) ensures bytes@ == header@ + body@ {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(header); bytes.extend_from_slice(body);
        assert(bytes@ =~= header@ + body@);
        bytes
    };
    let (frame,c,d) = record.write(vec![0u8;52],hash,collect)?;
    proof {
        let (p,q) = choose|p:&[u8],q:[u8;32]| p@ == record.payload() && #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            frame@ == (physical::Envelope {version:if record.parts().1==0 {1} else {2},size:p.len() as u64,checksum:q}).wire() + p@;
        assert(hash.ensures((physical::MAGIC,p.len() as u64,p),q));
        let (k,f,o,counts,b) = record.parts();
        let h = choose|h:&[u8]| h@ == wal_measurement::digest_header(k,f,counts.sequence,o,b.len() as u64)
            && #[trigger] collect.ensures((h,b),d);
        assert(collect.ensures((h,b),d));
    }
    Some((frame,c,d))
}

/// Any nonzero transaction sequence and representable Begin and Root bodies
/// provide a concrete writer-produced layout. Require success in the reader
/// and recover the exact stored Root bytes in its released batch.
#[verifier::rlimit(25)]
fn begin_root<H,F,T:FnOnce(Vec<u8>,usize,usize)->Option<Vec<u8>>>(sequence:u64,begin_body:&[u8],root_body:&[u8],chunk_size:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,transfer:T)
    -> (out:Option<(CheckedMarker,Vec<u8>,u64)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires sequence != 0, begin_body.len() as int + root_body.len() + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        forall|v:Vec<u8>,i:usize,j:usize| i<=j<=v.len() && v.len()==begin_body.len()+root_body.len()+288 ==> #[trigger] transfer.requires((v,i,j)),
        forall|v:Vec<u8>,i:usize,j:usize,r:Vec<u8>| #[trigger] transfer.ensures((v,i,j),Some(r)) ==> r@==v@,
    ensures out.is_none() ==> exists|v:Vec<u8>,i:usize,j:usize| i<=j<=v.len() && v.len()==begin_body.len()+root_body.len()+288 &&
            #[trigger] transfer.ensures((v,i,j),None),
        out matches Some((checked,recovered,start)) ==> {
        let m = checked.marker();
        &&& recovered@ == root_body@
        &&& start as int == 72 + begin_body.len()
        &&& m.counts.sequence == sequence && m.counts.logical == 2 && m.counts.objects == 0 && m.counts.roots == 1
        &&& m.counts.bytes as int == 40 + begin_body.len() + root_body.len()
        &&& m.digest == (digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin_body.len() as u64) + begin_body@
            + wal_measurement::digest_header(WalRecordKind::Root,0,sequence,1,root_body.len() as u64) + root_body@)
    },
{
    let first = Measured::begin(sequence,begin_body).ok()?;
    let (mut stream,c1,mut data) = write_data(first,hash,checksum)?;
    let begin = Record {next:stream.len(),kind:WalRecordKind::Begin,flags:0,sequence,ordinal:0,body:begin_body};
    let ghost first_frame = stream@;
    let second = Measured::append(c1,DataKind::Root,root_body).ok()?;
    let (second_frame,c2,tail) = write_data(second,hash,checksum)?;
    stream.extend_from_slice(&second_frame);
    let root = Record {next:stream.len(),kind:WalRecordKind::Root,flags:0,sequence,ordinal:1,body:root_body};
    data.extend_from_slice(&tail);
    let transcript_bytes = data.as_slice();
    let sum = finish(transcript_bytes);
    let marker = commit_wire::Marker {counts:c2,digest:sum};
    let encoded = marker.frame(vec![0u8;52],hash)?;
    let raw_body = marker.encode();
    stream.extend_from_slice(&encoded);
    let commit = Record {next:stream.len(),kind:WalRecordKind::Commit,flags:0,sequence,ordinal:2,body:&raw_body};
    let ghost rows = seq![begin,root];
    let ghost w = Layout {rows,states:seq![c1,c2],commit};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let (p,q) = choose|p:&[u8],q:[u8;32]| p@ == marker.payload() && #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            encoded@ == (physical::Envelope {version:1,size:p.len() as u64,checksum:q}).wire() + p@;
        assert(hash.ensures((physical::MAGIC,p.len() as u64,p),q));
        assert(encoded@ == frame_bytes(marker.payload(),1,checksum@));
        assert(stream@ =~= first_frame + second_frame@ + encoded@);
        assert(stream@.take(begin.next as int) =~= first_frame);
        assert(stream@.subrange(begin.next as int,root.next as int) =~= second_frame@);
        assert(stream@.subrange(root.next as int,commit.next as int) =~= encoded@);
        reveal(at_record);
        assert(at_record(stream@,0,begin,u64::MAX,checksum@));
        assert(at_record(stream@,begin.next as int,root,u64::MAX,checksum@));
        assert(at_record(stream@,root.next as int,commit,u64::MAX,checksum@));
        reveal_with_fuel(transcript,3);
        assert(rows.drop_last() =~= seq![begin]);
        assert(seq![begin].drop_last() =~= Seq::<Record>::empty());
        assert(data@ =~= transcript(rows));
        assert(finish.ensures((transcript_bytes,),sum));
        reveal(complete);
        assert(complete(w,stream@,0,u64::MAX,checksum@,digest@));
    }
    let stream = transfer(stream,begin.next,root.next)?;
    let scan = scan_transaction(&stream,0,u64::MAX,chunk_size,hash,checksum,finish,digest,Ghost(Some(w)))?;
    proof {
        reveal_with_fuel(selected,3);
        assert(scan.batch.contents().roots =~= seq![root]);
        assert(scan.batch.contents().objects.len() == 0);
        assert(scan.end == stream.len());
        assert(scan.marker.marker() == marker);
        assert(data@ =~= chunk(begin) + chunk(root));
        let expected = wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin_body.len() as u64) + begin_body@
            + wal_measurement::digest_header(WalRecordKind::Root,0,sequence,1,root_body.len() as u64) + root_body@;
        assert(data@ =~= expected);
        assert(scan.marker.marker().digest == (digest@)(expected));
    }
    let mut recovered = Vec::new();
    recovered.extend_from_slice(scan.batch.roots()[0].body);
    let released = scan.batch.roots()[0];
    let start = released.next - (72 + released.body.len());
    Some((scan.marker,recovered,start as u64))
}

/// Submit the writer's three framed records, publish the buffered WAL, and reread the
/// submitted interval from the stable image of the same target.
fn durable_begin_root<S:crate::group_frontier::BufferedWal,M:crate::positional_read::Media,Open:FnOnce(&S)->M,H,F>(
    sequence:u64,begin:&[u8],root:&[u8],chunk:usize,hash:H,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,sink:S,base:u64,reopen:Open,target:Ghost<spec_fn(M)->(int,Seq<u8>)>)
    -> (out:Option<(CheckedMarker,Vec<u8>,u64)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires sequence!=0,begin.len() as int+root.len()+288<=usize::MAX,
        sink.at_end(),sink.buffered_image().len()==base,base as int+begin.len()+root.len()+288<=u64::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v==(checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v==(digest@)(p@),
        forall|s:&S| #[trigger] reopen.requires((s,)),
        forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
            forall|at:u64,e:M::Error| base<=at<base as int+begin.len()+root.len()+288 ==> !#[trigger] m.io_error(at,e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.append_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.drain_error(e),
        forall|s:S,e:S::Error| s.wal_target()==sink.wal_target() ==> !#[trigger] s.sync_error(e),
    ensures out matches Some((marker,body,start)) && body@==root@ && start as int==base as int+72+begin.len() &&
        marker.marker().counts.sequence==sequence && marker.marker().counts.logical==2 && marker.marker().counts.roots==1 &&
        marker.marker().digest==(digest@)(wal_measurement::digest_header(WalRecordKind::Begin,0,sequence,0,begin.len() as u64)+begin@+
            wal_measurement::digest_header(WalRecordKind::Root,0,sequence,1,root.len() as u64)+root@),
{
    let ghost before=sink.buffered_image();
    let ghost original_target=sink.wal_target();
    let transfer=move |submitted:Vec<u8>,first:usize,second:usize| -> (out:Option<Vec<u8>>)
        requires first<=second<=submitted.len(),submitted.len()==begin.len()+root.len()+288,
            sink.at_end(),sink.buffered_image()==before,before.len()==base,sink.wal_target()==original_target,
            base as int+submitted.len()<=u64::MAX,
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.append_error(e),
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.drain_error(e),
            forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.sync_error(e),
            forall|s:&S| #[trigger] reopen.requires((s,)),
            forall|s:&S,m:M| #[trigger] reopen.ensures((s,),m) ==> m.image()==s.stable_image() && (target@)(m)==s.wal_target() &&
                forall|at:u64,e:M::Error| base<=at<base as int+submitted.len() ==> !#[trigger] m.io_error(at,e),
        ensures out matches Some(read) && read@==submitted@,
    {
        let mut sink=sink;
        sink.append_record(&submitted[..first]).ok()?;
        sink.append_record(&submitted[first..second]).ok()?;
        sink.append_record(&submitted[second..]).ok()?;
        assert(sink.buffered_image() =~= before+submitted@);
        let sync=move || -> (out:Result<S,S::Error>)
            requires sink.buffered_image()==before+submitted@,sink.wal_target()==original_target,
                forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.drain_error(e),
                forall|s:S,e:S::Error| s.wal_target()==original_target ==> !#[trigger] s.sync_error(e),
            ensures out matches Ok(s) && s.stable_image()==before+submitted@ && s.wal_target()==original_target,
        {
            let mut buffered=sink;
            crate::group_frontier::publish_buffer(&mut buffered)?;
            Ok(buffered)
        };
        let mut pending=1u64;
        let mut poisoned=false;
        let (acknowledged,stable)=crate::group_frontier::sync_pending(false,&mut pending,&mut poisoned,sync).ok()?;
        assert(acknowledged==1 && pending==0 && !poisoned);
        let media=reopen(&stable);
        assert((target@)(media)==original_target);
        assert(media.image().subrange(base as int,base as int+submitted.len()) =~= submitted@);
        let mut observed=vec![0u8;submitted.len()];
        crate::positional_read::exact(&media,base,&mut observed).ok()?;
        Some(observed)
    };
    let (marker,body,relative)=begin_root(sequence,begin,root,chunk,hash,checksum,finish,digest,transfer)?;
    Some((marker,body,base.checked_add(relative)?))
}

spec fn version(r:root_wire::Root) -> Version {
    Version {generation:vstd::bytes::spec_u64_from_le_bytes(r.generation@),commit:r.commit}
}

fn decode_version(r:root_wire::Root) -> (v:Version)
    ensures v == version(r),
{
    Version {generation:u64::from_le_bytes(r.generation),commit:r.commit}
}

fn wire_version(v:Version) -> (r:root_wire::Root)
    ensures r.generation@ == vstd::bytes::spec_u64_to_le_bytes(v.generation), r.commit == v.commit,
{
    root_wire::Root {generation:commit_wire::little_endian(v.generation),commit:v.commit}
}

/// Consult the history of the owner decoded from the released record, then
/// classify the replay against the full versions that the writer serialized.
/// The maximum body is 138 bytes (8-byte length, 33-byte owner, 1-byte
/// expected tag and two 48-byte roots). The three frames add 288 bytes.
fn recover_root<H,F,K:Ord+Copy,L>(sequence:u64,begin:&[u8],owner:Owner,scheme:root_wire::Scheme,
    prior:Option<root_wire::Root>,next:root_wire::Root,chunk:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    key_of:L,key_spec:Ghost<spec_fn(Seq<u8>)->K>,history:&mut BTreeMap<K,(Version,u64)>)
    -> (out:Option<Replay>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,L:FnOnce(Owner)->K,
    requires sequence != 0, begin.len() as int + 138 + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        forall|o:Owner| #[trigger] key_of.requires((o,)),
        forall|o:Owner,k:K| #[trigger] key_of.ensures((o,),k) ==> k == (key_spec@)(o.bytes()),
        forall|a:Owner,b:Owner| #[trigger] (key_spec@)(a.bytes()) == #[trigger] (key_spec@)(b.bytes()) ==> a.bytes() == b.bytes(),
        obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(old(history)),
    ensures ({
        let k = (key_spec@)(owner.bytes());
        let actual = if old(history)@.contains_key(k) {Some(old(history)@[k].0)} else {None};
        let expected = match prior {Some(r) => Some(version(r)),None => None};
        let replacement = version(next);
        let valid = match expected {None => replacement.generation == 0,
            Some(e) => replacement.generation as int == e.generation as int + 1};
        &&& btree_map_inv(final(history))
        &&& final(history)@ == if out matches Some(Replay::Apply) {
            old(history)@.insert(k,(replacement,(72 + begin.len()) as u64))
        } else { old(history)@ }
        &&& forall|other:Owner| other.bytes() != owner.bytes() ==> {
            let other_key = #[trigger] (key_spec@)(other.bytes());
            &&& final(history)@.contains_key(other_key) == old(history)@.contains_key(other_key)
            &&& old(history)@.contains_key(other_key) ==> final(history)@[other_key] == old(history)@[other_key]
        }
        &&& out.is_some() == valid
        &&& out matches Some(d) ==> {
            &&& (d is AlreadyPublished) == root_transition::matches_root(actual,Some(replacement))
            &&& (d is Apply) == (!root_transition::matches_root(actual,Some(replacement)) && root_transition::matches_root(actual,expected))
            &&& (d is Conflict) == (!root_transition::matches_root(actual,Some(replacement)) && !root_transition::matches_root(actual,expected))
        }
    }),
{
    let key = owner.encode();
    let wire = root_wire::encode(&key,scheme,prior,next)?;
    assert(wire.len() <= 138) by {
        match prior {Some(r) => {assert(r.wire(scheme).len() == 48);},None => {}}
        assert(next.wire(scheme).len() == 48);
        assert(key.len() <= 33);
        assert(vstd::bytes::spec_u64_to_le_bytes(key.len() as u64).len() == 8) by {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        }
    }
    let (_,body,offset) = begin_root(sequence,begin,&wire,chunk,hash,checksum,finish,digest,
        |v:Vec<u8>,_:usize,_:usize| -> (out:Option<Vec<u8>>) ensures out==Some(v), {Some(v)})?;
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(key.len() as u64));
    let (saved,mut cursor) = root_wire::read_owner(&body).ok()?;
    assert(saved@ =~= key@);
    let recovered = owner_codec::decode(saved)?;
    let ghost start = cursor as int;
    assert(body@.skip(start) =~= root_wire::prior(prior,scheme) + next.wire(scheme));
    assert(root_wire::tail(body@,start,scheme,prior,next));
    let (e,r) = root_wire::read_tail(&body,&mut cursor,scheme).ok()?;
    proof { root_wire::unique_tail(body@,start,scheme,e,r,prior,next); }
    proof {
        assert(r.commit =~= next.commit);
        assert(r.generation =~= next.generation);
        if let Some(x) = e {
            let y = prior.unwrap();
            assert(x.commit =~= y.commit);
            assert(x.generation =~= y.generation);
        }
        assert(r == next && e == prior);
    }
    let expected = match e {Some(v) => Some(decode_version(v)), None => None};
    let replacement = decode_version(r);
    if !root_transition::valid_generation(expected,replacement.generation) {return None;}
    let owner_key = key_of(recovered);
    let identity = |v:Version| -> (r:Version) ensures r == v { v };
    assert forall|v:Version,r:Version| #[trigger] identity.ensures((v,),r) implies r == table::version(identity,v) by {
        assert(exists|t:Version| identity.ensures((v,),t));
    }
    let ghost before = history@;
    let ghost actual = if before.contains_key(owner_key) {Some(before[owner_key].0)} else {None};
    let encode = |_:&K,expected:Option<Version>,replacement:Version| -> (journal:Result<Vec<u8>,()>)
        requires expected == (match prior {Some(r) => Some(version(r)),None => None}), replacement == version(next),
        ensures journal matches Ok(bytes) && bytes@ == body@,
    {
        let prev = match expected {Some(v) => Some(wire_version(v)),None => None};
        let wire_next = wire_version(replacement);
        proof {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(wire_next.generation =~= next.generation);
            if let Some(p) = prev { assert(p.generation =~= prior.unwrap().generation); }
            assert(prev == prior && wire_next == next);
            assert(body@ =~= vstd::bytes::spec_u64_to_le_bytes(saved.len() as u64) + saved@ +
                root_wire::prior(prior,scheme) + next.wire(scheme));
        }
        root_wire::encode(saved,scheme,prev,wire_next).ok_or(())
    };
    let decision = table::fold(history,owner_key,expected,replacement,offset,identity,encode).ok()?;
    assert(table::optional_version(identity,actual) == actual);
    assert(table::optional_version(identity,expected) == expected);
    assert(table::version(identity,replacement) == replacement);
    assert(owner_key == (key_spec@)(owner.bytes()));
    assert(expected == match prior {Some(r) => Some(version(r)),None => None});
    match decision {
        Decision::AlreadyPublished => Some(Replay::AlreadyPublished),
        Decision::Conflict(_) => Some(Replay::Conflict),
        Decision::Applied(journal) => {
            assert(journal@ == body@);
            // A repeated recovery must preserve the first offset even if the
            // journal encoder would now fail and the observed offset differs.
            let unavailable = |_:&K,_:Option<Version>,_:Version| -> (res:Result<(),()>) ensures res.is_err() {Err(())};
            let again = table::fold(history,owner_key,expected,replacement,0,identity,unavailable);
            assert(again matches Ok(Decision::AlreadyPublished));
            Some(Replay::Apply)
        },
    }
}

/// Two independent root transactions may carry the same UID bytes under
/// different owner tags. Applying the second preserves the first entry.
fn recover_principal_and_fleet<H,F,K:Ord+Copy,L>(sequence:u64,begin:&[u8],uid:[u8;32],
    scheme:root_wire::Scheme,first:[u8;32],second:[u8;32],chunk:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    key_of:L,key_spec:Ghost<spec_fn(Seq<u8>)->K>,history:&mut BTreeMap<K,(Version,u64)>)
    -> (replayed:bool)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,L:Fn(Owner)->K+Copy,
    requires sequence != 0, begin.len() as int + 138 + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        forall|o:Owner| #[trigger] key_of.requires((o,)),
        forall|o:Owner,k:K| #[trigger] key_of.ensures((o,),k) ==> k == (key_spec@)(o.bytes()),
        forall|a:Owner,b:Owner| #[trigger] (key_spec@)(a.bytes()) == #[trigger] (key_spec@)(b.bytes()) ==> a.bytes() == b.bytes(),
        obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(old(history)),
        sequence < u64::MAX,
        !old(history)@.contains_key((key_spec@)(Owner::Principal(uid).bytes())),
        !old(history)@.contains_key((key_spec@)(Owner::Fleet(uid).bytes())),
    ensures replayed && final(history)@ == old(history)@
        .insert((key_spec@)(Owner::Principal(uid).bytes()),(Version {generation:0,commit:first},(72+begin.len()) as u64))
        .insert((key_spec@)(Owner::Fleet(uid).bytes()),(Version {generation:0,commit:second},(72+begin.len()) as u64)),
{
    let principal = Owner::Principal(uid);
    let fleet = Owner::Fleet(uid);
    let zero = commit_wire::little_endian(0);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(principal.bytes()[0] != fleet.bytes()[0]);
        assert((key_spec@)(principal.bytes()) != (key_spec@)(fleet.bytes()));
    }
    let p = root_wire::Root {generation:zero,commit:first};
    let f = root_wire::Root {generation:zero,commit:second};
    let applied = recover_root(sequence,begin,principal,scheme,None,p,chunk,hash,checksum,finish,digest,key_of,key_spec,history);
    if !matches!(applied,Some(Replay::Apply)) {return false;}
    let applied = recover_root(sequence+1,begin,fleet,scheme,None,f,chunk,hash,checksum,finish,digest,key_of,key_spec,history);
    matches!(applied,Some(Replay::Apply))
}

}
