//! Physical WAL framing under a fixed checksum function and stable stream bytes.
use crate::{wal_physical_wire as physical, wal_record_wire as logical};
use vstd::prelude::*;

verus! {

/// Recover a single physical payload from a cursor in the supplied stream.
/// The kernel state machine separately decides what to do with rejected frames.
fn read_at<'a,F>(stream:&'a [u8], at:usize, limit:u64, hash:F,
    Ghost(checksum):Ghost<spec_fn(Seq<u8>) -> [u8;32]>)
    -> (out:Option<(usize,&'a [u8],physical::Envelope)>)
    where F: FnOnce([u8;8],u64,&[u8]) -> [u8;32],
    requires forall|m:[u8;8],len:u64,data:&[u8]| #[trigger] hash.requires((m,len,data)),
        forall|data:&[u8],sum:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,data.len() as u64,data),sum)
            ==> sum == checksum(data@),
    ensures
        ({
            let start = at as int + physical::WIDTH;
            if start > stream.len() { out.is_none() } else {
            let h = stream@.subrange(at as int,start);
            let size = vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20));
            let end = start + size;
            if end > stream.len() {out.is_none()} else {
            let payload = stream@.subrange(start,end);
            &&& out.is_some() == (start <= stream.len() && physical::supported(h) && end <= stream.len()
                && size <= limit && checksum(payload)@ == h.skip(20))
            &&& out matches Some((next,body,envelope)) ==> next == end && body@ == payload &&
                envelope.wire() == h && envelope.checksum == checksum(payload)
            }}
        }),
{
    let start = at.checked_add(physical::WIDTH)?;
    if start > stream.len() {return None;}
    let mut raw = [0u8;52];
    raw.copy_from_slice(&stream[at..start]);
    let header = physical::decode(&raw)?;
    let end = match physical::extent(start as u64,header.size,stream.len() as u64,limit) {
        physical::Extent::Complete(end) => end as usize, _ => return None,
    };
    let payload = &stream[start..end];
    assert(payload.len() as u64 == header.size);
    if !header.validates(payload,hash) {
        proof {
            let sum = choose|sum:[u8;32]| sum@ != header.checksum@ && #[trigger] hash.ensures((physical::MAGIC,header.size,payload),sum);
            assert(hash.ensures((physical::MAGIC,payload.len() as u64,payload),sum));
            assert(sum == checksum(payload@));
            assert(sum@ != header.checksum@);
        }
        return None;
    }
    assert(hash.ensures((physical::MAGIC,payload.len() as u64,payload),header.checksum));
    Some((end,payload,header))
}

/// A sealed logical frame is readable at its actual offset between arbitrary
/// neighboring bytes. No bytes in either neighbor enter the selected payload.
fn round_trip<F>(prefix:&[u8], suffix:&[u8], record:logical::Header, body:&[u8], hash:F,
    Ghost(checksum):Ghost<spec_fn(Seq<u8>) -> [u8;32]>)
    -> (out:Option<(usize,Vec<u8>,bool)>)
    where F: Fn([u8;8],u64,&[u8]) -> [u8;32] + Copy,
    requires prefix.len() as int + suffix.len() + physical::WIDTH + logical::HEADER_LEN + body.len() <= usize::MAX,
        forall|m:[u8;8],n:u64,data:&[u8]| #[trigger] hash.requires((m,n,data)),
        forall|data:&[u8],sum:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,data.len() as u64,data),sum)
            ==> sum == checksum(data@),
    ensures out matches Some((next,bytes,features)) && next as int == prefix.len() + physical::WIDTH + logical::HEADER_LEN + body.len()
        && bytes@ == body@ && features == ((1 <= record.kind <= 4 && record.flags == 0) || (record.kind == 2 && record.flags == 1)),
{
    let mut frame = vec![0u8;52];
    record.append(&mut frame,body);
    let ghost sum = checksum(record.bytes() + body@);
    let ghost original = frame@;
    assert(original.skip(52) =~= record.bytes() + body@);
    let sealed = physical::seal(&mut frame,record.flags,hash);
    assert(sealed);
    let ghost image = frame@;
    let mut stream = Vec::new();
    stream.extend_from_slice(prefix);
    stream.extend_from_slice(&frame);
    stream.extend_from_slice(suffix);
    let ghost start = prefix.len() as int + 52;
    let ghost h = stream@.subrange(prefix.len() as int,start);
    let ghost data = record.bytes() + body@;
    let ghost expected = physical::Envelope {version:if record.flags == 0 {1} else {2},size:data.len() as u64,checksum:sum};
    proof {
        let (payload,observed) = choose|p:&[u8],q:[u8;32]| p@ == original.skip(52) &&
            #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            image == (physical::Envelope {version:if record.flags == 0 {1} else {2},size:p.len() as u64,checksum:q}).wire() + p@;
        assert(hash.ensures((physical::MAGIC,payload.len() as u64,payload),observed));
        assert(observed == checksum(payload@));
    }
    assert(frame@ =~= expected.wire() + data);
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(expected.wire().len() == 52);
    assert(stream@ =~= prefix@ + frame@ + suffix@);
    assert(h =~= expected.wire());
    assert(h.take(8) =~= physical::MAGIC@);
    assert(physical::supported(h));
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(h.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(expected.size));
    assert(h.skip(20) =~= sum@);
    assert(stream@.subrange(start,start+data.len()) =~= data);
    let result = read_at(&stream,prefix.len(),u64::MAX,hash,Ghost(checksum));
    let (next,payload,envelope) = result?;
    assert(next as int == prefix.len() + frame.len());
    assert(payload@ =~= data);
    let (h,decoded) = logical::split(payload)?;
    assert(h.bytes() =~= record.bytes());
    assert(decoded@ =~= body@);
    let valid = match logical::WalRecordKind::from_tag(h.kind) {
        Some(kind) => envelope.accepts(kind,h.flags), None => false,
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(decoded);
    Some((next,bytes,valid))
}

}

verus! {

/// Recovery treats a complete but oversized frame as evidence that truncation
/// would discard later data. Only bounded candidates require a checksum.
spec fn candidate(stream:Seq<u8>, at:u64, limit:u64, checksum:spec_fn(Seq<u8>)->[u8;32]) -> bool {
    let start = at as int + physical::WIDTH;
    if start > stream.len() { false } else {
        let h = stream.subrange(at as int,start);
        let size = vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20));
        let end = start + size;
        physical::supported(h) && end <= stream.len() &&
            (size > limit || checksum(stream.subrange(start,end))@ == h.skip(20))
    }
}

fn candidate_at<F>(stream:&[u8],at:u64,limit:u64,hash:F,Ghost(checksum):Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (found:bool) where F:FnOnce([u8;8],u64,&[u8])->[u8;32],
    requires at < stream.len(), forall|m:[u8;8],n:u64,data:&[u8]| #[trigger] hash.requires((m,n,data)),
        forall|data:&[u8],sum:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,data.len() as u64,data),sum)
            ==> sum == checksum(data@),
    ensures found == candidate(stream@,at,limit,checksum),
{
    let Some(start) = (at as usize).checked_add(physical::WIDTH) else {return false;};
    if start > stream.len() {return false;}
    let mut raw = [0u8;52];
    raw.copy_from_slice(&stream[at as usize..start]);
    let Some(envelope) = physical::decode(&raw) else {return false;};
    if matches!(physical::extent(start as u64,envelope.size,stream.len() as u64,limit), physical::Extent::Oversized) {
        return true;
    }
    read_at(stream,at as usize,limit,hash,Ghost(checksum)).is_some()
}

fn first_interior<F>(stream:&[u8], start:u64, limit:u64, hash:F, checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (found:Option<u64>) where F:Fn([u8;8],u64,&[u8])->[u8;32] + Copy,
    requires forall|m:[u8;8],n:u64,data:&[u8]| #[trigger] hash.requires((m,n,data)),
        forall|data:&[u8],sum:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,data.len() as u64,data),sum)
            ==> sum == (checksum@)(data@),
    ensures found matches Some(hit) ==> start <= hit < stream.len() && candidate(stream@,hit,limit,checksum@) &&
            forall|j:u64| start <= j < hit ==> !#[trigger] candidate(stream@,j,limit,checksum@),
        found.is_none() ==> forall|j:u64| start <= j < stream.len() ==> !#[trigger] candidate(stream@,j,limit,checksum@),
{
    use crate::wal_interior::{self, Probe};
    let probe = |_:(),pos:u64| -> (v:((),Result<Probe,()>))
        requires pos < stream.len(),
        ensures v.1 == if candidate(stream@,pos,limit,checksum@) {Ok(Probe::Found)} else {Ok(Probe::Miss)},
    {
        let found = candidate_at(stream,pos,limit,hash,checksum);
        ((),Ok(if found {Probe::Found} else {Probe::Miss}))
    };
    let (_,out) = wal_interior::search((),start,stream.len() as u64,probe);
    match out {
        Ok(Some(hit)) => {
            assert(wal_interior::observed(probe,hit,Ok(Probe::Found)));
            assert forall|j:u64| start <= j < hit implies !#[trigger] candidate(stream@,j,limit,checksum@) by {
                assert(wal_interior::observed(probe,j,Ok(Probe::Miss)));
            }
            Some(hit)
        },
        Ok(None) => {
            assert forall|j:u64| start <= j < stream.len() implies !#[trigger] candidate(stream@,j,limit,checksum@) by {
                assert(wal_interior::observed(probe,j,Ok(Probe::Miss)));
            }
            None
        },
        Err(_) => { assert(false); None },
    }
}

}

verus! {

/// A damaged frame is truncatable only when no later physical candidate is
/// present. An active transaction resumes at its Begin even after many frames.
fn damaged_boundary<F>(stream:&[u8], cursor:u64, active_begin:Option<u64>, limit:u64, hash:F,
    checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>) -> (out:Result<u64,u64>)
    where F:Fn([u8;8],u64,&[u8])->[u8;32] + Copy,
    requires cursor < stream.len(),
        forall|m:[u8;8],n:u64,data:&[u8]| #[trigger] hash.requires((m,n,data)),
        forall|data:&[u8],sum:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,data.len() as u64,data),sum)
            ==> sum == (checksum@)(data@),
    ensures out.is_ok() == (forall|j:u64| cursor < j < stream.len() ==> !#[trigger] candidate(stream@,j,limit,checksum@)),
        out matches Ok(resume) ==> resume == active_begin.unwrap_or(cursor),
        out matches Err(hit) ==> cursor < hit < stream.len() && candidate(stream@,hit,limit,checksum@)
            && forall|j:u64| cursor < j < hit ==> !#[trigger] candidate(stream@,j,limit,checksum@),
{
    if let Some(hit) = first_interior(stream,cursor.saturating_add(1),limit,hash,checksum) {
        return Err(hit);
    }
    match crate::wal_interior::boundary(active_begin,cursor,true) {
        crate::wal_interior::Boundary::Tail(resume) => Ok(resume),
        crate::wal_interior::Boundary::End(_) => { assert(false); Err(cursor) },
    }
}

}
