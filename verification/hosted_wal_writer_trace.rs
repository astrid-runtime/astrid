//! Construct a complete layout from the real Begin, Root and Commit encoders.
use super::*;
use crate::{owner_codec::{self,Owner},root_wire,root_transition::{self,Version,Replay}};
use vstd::prelude::*;

verus! {

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
fn begin_root<H,F>(sequence:u64,begin_body:&[u8],root_body:&[u8],chunk_size:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<(CheckedMarker,Vec<u8>)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires sequence != 0, begin_body.len() as int + root_body.len() + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
    ensures out matches Some((checked,recovered)) && {
        let m = checked.marker();
        &&& recovered@ == root_body@
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
    Some((scan.marker,recovered))
}

spec fn version(r:root_wire::Root) -> Version {
    Version {generation:vstd::bytes::spec_u64_from_le_bytes(r.generation@),commit:r.commit}
}

fn decode_version(r:root_wire::Root) -> (v:Version)
    ensures v == version(r),
{
    Version {generation:u64::from_le_bytes(r.generation),commit:r.commit}
}

/// Consult the history of the owner decoded from the released record, then
/// classify the replay against the full versions that the writer serialized.
/// The maximum body is 138 bytes (8-byte length, 33-byte owner, 1-byte
/// expected tag and two 48-byte roots). The three frames add 288 bytes.
fn recover_root<H,F,L>(sequence:u64,begin:&[u8],owner:Owner,scheme:root_wire::Scheme,
    prior:Option<root_wire::Root>,next:root_wire::Root,chunk:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>,
    lookup:L,history:Ghost<spec_fn(Seq<u8>)->Option<Version>>)
    -> (out:Option<Replay>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,L:FnOnce(Owner)->Option<Version>,
    requires sequence != 0, begin.len() as int + 138 + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
        forall|o:Owner| #[trigger] lookup.requires((o,)),
        forall|o:Owner,v:Option<Version>| #[trigger] lookup.ensures((o,),v) ==> v == (history@)(o.bytes()),
    ensures ({
        let actual = (history@)(owner.bytes());
        let expected = match prior {Some(r) => Some(version(r)),None => None};
        let replacement = version(next);
        let valid = match expected {None => replacement.generation == 0,
            Some(e) => replacement.generation as int == e.generation as int + 1};
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
    let (_,body) = begin_root(sequence,begin,&wire,chunk,hash,checksum,finish,digest)?;
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
    let expected = match e {Some(v) => Some(decode_version(v)), None => None};
    let replacement = decode_version(r);
    if !root_transition::valid_generation(expected,replacement.generation) {return None;}
    let actual = lookup(recovered);
    Some(root_transition::replay(actual,expected,replacement))
}

}
