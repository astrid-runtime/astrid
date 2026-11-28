//! Decode one complete root-journal payload and retain the diagnostic cursor.
use super::{
    RootState, arena_frame as frame, journal_snapshot as snapshot,
    journal_transition as transition, root_wire,
};
use vstd::prelude::*;

verus! {
pub(super) enum Record { Transition(transition::Record), Snapshot(Vec<(Vec<u8>,RootState)>) }
pub(super) enum Error { Header(snapshot::HeaderError), Transition(transition::DecodeError), Snapshot(snapshot::CompleteError) }

#[cfg(verus_keep_ghost)]
use super::journal_history as history;

pub(super) open spec fn snapshot_header(bytes:Seq<u8>,count:usize) -> bool {
    bytes.len()>=17 && bytes.take(17)==snapshot::header(count as u64)
}

pub(super) open spec fn tag(bytes:Seq<u8>) -> u64 {
    if bytes.len()>=8 {vstd::bytes::spec_u64_from_le_bytes(bytes.take(8))} else {0u64}
}

#[verifier::spinoff_prover]
pub(super) fn decode(bytes:&[u8],cursor:&mut usize,scheme:root_wire::Scheme) -> (out:Result<Record,Error>)
    requires *old(cursor)==0,
    ensures
        out matches Ok(Record::Transition(r)) ==> bytes.len()>=8 && tag(bytes@)!=snapshot::SENTINEL &&
            *final(cursor)==bytes.len() && 8+tag(bytes@) as int<=bytes.len() && r.principal@==bytes@.subrange(8,8+tag(bytes@) as int) &&
            exists|e:Option<root_wire::Root>,n:root_wire::Root| #[trigger] root_wire::tail(bytes@,8+tag(bytes@) as int,scheme,e,n) &&
                history::represents(n,r.replacement) && match (e,r.expected) {(None,None)=>true,(Some(a),Some(b))=>history::represents(a,b),_=>false},
        forall|e:Option<root_wire::Root>,n:root_wire::Root| bytes.len()>=8 && tag(bytes@)!=snapshot::SENTINEL && tag(bytes@)<=usize::MAX &&
            #[trigger] root_wire::tail(bytes@,8+tag(bytes@) as int,scheme,e,n) ==> (out matches Ok(Record::Transition(_))),
        out matches Ok(Record::Snapshot(rows)) ==> snapshot_header(bytes@,rows.len()) && *final(cursor)==bytes.len() &&
            snapshot::ordered(rows@) && exists|ends:Seq<usize>| ends[0]==17 && ends[rows.len() as int]==bytes.len() &&
                #[trigger] snapshot::spans(bytes@,rows@,ends,scheme),
        forall|expected:snapshot::WireRows,ends:Seq<usize>,count:usize|
            snapshot_header(bytes@,count) && #[trigger] snapshot::layout(bytes@,17,count,scheme,expected,ends) ==>
                match out {
                    Ok(Record::Snapshot(rows))=>rows.len()==count && snapshot::matches_rows(rows@,expected),
                    Err(Error::Snapshot(snapshot::CompleteError::Capacity))=>count>0,
                    Err(Error::Snapshot(snapshot::CompleteError::End(e)))=>*final(cursor)==ends[count as int] &&
                        exists|v:Seq<(Vec<u8>,RootState)>| v.len()==count && #[trigger] snapshot::matches_rows(v,expected) &&
                            match e {snapshot::EndError::Order=>!snapshot::ordered(v),snapshot::EndError::Trailing=>snapshot::ordered(v) && *final(cursor)!=bytes.len()},
                    _=>false,
                },

{
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert forall|c:usize| #[trigger] snapshot_header(bytes@,c) implies
            vstd::bytes::spec_u64_from_le_bytes(bytes@.take(8))==snapshot::SENTINEL &&
            bytes@[8]==snapshot::RECORD && vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(9,17))==c by {
            let h=bytes@.take(17);
            assert(h==snapshot::header(c as u64));
            assert(h[8]==bytes@[8]);
            assert(h.subrange(9,17) =~= vstd::bytes::spec_u64_to_le_bytes(c as u64));
            assert(bytes@.subrange(9,17) =~= h.subrange(9,17));
            assert(bytes@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(snapshot::SENTINEL));
            assert(bytes@.subrange(9,17) =~= vstd::bytes::spec_u64_to_le_bytes(c as u64));
        }
    }
    match snapshot::read_header(bytes,cursor) {
        Ok(snapshot::JournalHeader::Transition(n))=>match transition::decode(bytes,cursor,n,scheme) {
            Ok(r)=>Ok(Record::Transition(r)),Err(e)=>Err(Error::Transition(e)),
        },
        Ok(snapshot::JournalHeader::Snapshot(n))=>match snapshot::read_complete(bytes,cursor,n,scheme) {
            Ok(v)=>Ok(Record::Snapshot(v)),Err(e)=>Err(Error::Snapshot(e)),
        },
        Err(e)=>Err(Error::Header(e)),
    }
}

pub(super) enum WriteError<E> { Order, Size(u64), Frame(frame::SingleError<E>) }

/// Encode and append exactly the sorted principal rows selected for compaction.
pub(super) fn append_snapshot<S:frame::BatchFile,H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    file:&mut S,roots:&[(Vec<u8>,RootState)],scheme:root_wire::Scheme,limit:u64,hash:H)
    -> (out:Result<frame::ArenaLocation,WriteError<S::Error>>)
    requires forall|b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,b.len() as u64,b)),
    ensures final(file).target()==old(file).target(),{
        let bytes=snapshot::prefix(roots@,roots.len() as nat,scheme);
        match out {
            Ok(loc)=>snapshot::ordered(roots@) && snapshot::serialized(bytes,roots@,scheme) &&
                loc.offset==old(file).image().len() && loc.payload_len==bytes.len()<=limit &&
                frame::hashed(hash,frame::ROOT_MAGIC,bytes,loc.checksum) && final(file).image()==old(file).image()+
                    frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum)+bytes,
            Err(WriteError::Order)=>!snapshot::ordered(roots@) && final(file).image()==old(file).image(),
            Err(WriteError::Size(n))=>snapshot::ordered(roots@) && n==bytes.len() && n>limit && final(file).image()==old(file).image(),
            Err(WriteError::Frame(e))=>snapshot::ordered(roots@) && match e {
                frame::SingleError::Length=>bytes.len()>u64::MAX && final(file).image()==old(file).image(),
                frame::SingleError::Seek(e)=>bytes.len()<=limit && old(file).seek_failed(e) && final(file).image()==old(file).image(),
                frame::SingleError::Header(e)|frame::SingleError::Payload(e)=>bytes.len()<=limit && S::write_failed(old(file).target(),e),
            },
        }
    },
{
    let Some(bytes)=snapshot::encode_ordered(roots,scheme) else {return Err(WriteError::Order)};
    let Ok(size)=u64::try_from(bytes.len()) else {return Err(WriteError::Frame(frame::SingleError::Length));};
    if size>limit {return Err(WriteError::Size(size));}
    let body=bytes.as_slice();
    match frame::append_one(file,frame::ROOT_MAGIC,frame::FRAME_VERSION,body,hash) {
        Ok(loc)=>{assert(frame::hashed(hash,frame::ROOT_MAGIC,body@,loc.checksum));Ok(loc)},
        Err(e)=>Err(WriteError::Frame(e)),
    }
}
}
