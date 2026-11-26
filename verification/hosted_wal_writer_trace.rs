//! Construct a complete layout from the real Begin, Root and Commit encoders.
use super::*;
use std::collections::BTreeMap;
use crate::wal_root_history::{self as table,Decision};
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};
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
#[verifier::rlimit(25)]
fn begin_root<H,F>(sequence:u64,begin_body:&[u8],root_body:&[u8],chunk_size:usize,hash:H,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>,finish:F,digest:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<(CheckedMarker,Vec<u8>,u64)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,F:Fn(&[u8])->[u8;32]+Copy,
    requires sequence != 0, begin_body.len() as int + root_body.len() + 288 <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        forall|p:&[u8]| #[trigger] finish.requires((p,)),
        forall|p:&[u8],v:[u8;32]| #[trigger] finish.ensures((p,),v) ==> v == (digest@)(p@),
    ensures out matches Some((checked,recovered,start)) && {
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
    let (_,body,offset) = begin_root(sequence,begin,&wire,chunk,hash,checksum,finish,digest)?;
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
