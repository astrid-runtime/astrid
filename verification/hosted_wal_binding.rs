//! The measured writer emits a physical payload and a digest input for one
//! record. Recover the payload using the physical and logical decoders.
use crate::{commit_wire::Counts, hosted_wal_physical_model::read_at, wal_measured_record::{DataKind,Measured,ObjectEncoding},
    wal_measurement, wal_physical_wire as physical, wal_record_wire as logical};
use vstd::prelude::*;

verus! {

spec fn follows(record:Measured, prior:Option<Counts>) -> bool {
    let (kind,flags,ord,c,body) = record.parts();
    let bytes = logical::HEADER_LEN as int + body.len();
    match prior {
        None => kind is Begin && flags == 0 && ord == 0 && c.logical == 1 &&
            c.objects == 0 && c.roots == 0 && c.bytes == bytes,
        Some(p) => {
            &&& c.sequence == p.sequence && ord == p.logical && c.logical as int == p.logical as int + 1
            &&& c.bytes as int == p.bytes as int + bytes
            &&& match kind {
                logical::WalRecordKind::Object => flags <= 1 && c.objects as int == p.objects as int + 1 && c.roots == p.roots,
                logical::WalRecordKind::Root => flags == 0 && c.roots as int == p.roots as int + 1 && c.objects == p.objects,
                _ => false,
            }
        },
    }
}

fn write_and_read<F>(record:Measured, prior:Option<Counts>, prefix:&[u8], suffix:&[u8], limit:u64, hash:F,checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<(Vec<u8>,Vec<u8>,Counts)>)
    where F:Fn([u8;8],u64,&[u8])->[u8;32] + Copy,
    requires follows(record,prior), prefix.len() as int + suffix.len() + record.parts().4.len() + physical::WIDTH + logical::HEADER_LEN <= usize::MAX,
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
    ensures out.is_some() == (record.parts().4.len() as int + logical::HEADER_LEN <= limit),
        out matches Some((body,digest,c)) ==> {
        let (kind,flags,ordinal,counts,stored) = record.parts();
        &&& body@ == stored@ && c == counts
        &&& digest@ == wal_measurement::digest_header(kind,flags,counts.sequence,ordinal,body.len() as u64) + body@
    },
{
    let collect = |header:&[u8],body:&[u8]| -> (bytes:Vec<u8>)
        ensures bytes@ == header@ + body@,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(body);
        assert(bytes@ =~= header@ + body@);
        bytes
    };
    let (frame,c,digest) = record.write(vec![0u8;52],hash,collect)?;
    let ghost payload = record.payload();
    let ghost sum = (checksum@)(payload);
    let ghost envelope = physical::Envelope {version:if record.parts().1 == 0 {1} else {2},size:payload.len() as u64,checksum:sum};
    proof {
        let (p,q) = choose|p:&[u8],q:[u8;32]| p@ == payload && #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),q) &&
            frame@ == (physical::Envelope {version:if record.parts().1 == 0 {1} else {2},size:p.len() as u64,checksum:q}).wire() + payload;
        assert(hash.ensures((physical::MAGIC,p.len() as u64,p),q));
        assert(q == (checksum@)(p@));
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let (kind,flags,ordinal,counts,stored) = record.parts();
        let h = choose|h:&[u8]| h@ == wal_measurement::digest_header(kind,flags,counts.sequence,ordinal,stored.len() as u64)
            && #[trigger] collect.ensures((h,stored),digest);
        assert(collect.ensures((h,stored),digest));
    }
    assert(frame@ =~= envelope.wire() + payload);
    assert(envelope.wire().len() == 52);
    let mut stream = Vec::new();
    stream.extend_from_slice(prefix);
    stream.extend_from_slice(&frame);
    stream.extend_from_slice(suffix);
    let ghost start = prefix.len() as int + physical::WIDTH;
    let ghost h = stream@.subrange(prefix.len() as int,start);
    assert(stream@ =~= prefix@ + frame@ + suffix@);
    assert(h =~= envelope.wire());
    assert(h.take(8) =~= physical::MAGIC@);
    assert(h.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(envelope.size));
    assert(h.skip(20) =~= sum@);
    assert(stream@.subrange(start,start + payload.len()) =~= payload);
    let (end,bytes,physical) = read_at(&stream,prefix.len(),limit,hash,checksum,usize::MAX)?;
    assert(end as int == prefix.len() + frame.len());
    assert(bytes@ =~= payload);
    let (decoded,body) = logical::split(bytes)?;
    let ghost (_,_,ordinal,counts,stored) = record.parts();
    assert(decoded.sequence@ =~= vstd::bytes::spec_u64_to_le_bytes(counts.sequence));
    assert(decoded.ordinal@ =~= vstd::bytes::spec_u64_to_le_bytes(ordinal));
    let sequence = u64::from_le_bytes(decoded.sequence);
    let expected_ordinal = match prior {Some(c) => c.logical,None => 0};
    let body = logical::body_at_position(body,sequence,u64::from_le_bytes(decoded.ordinal),c.sequence,expected_ordinal).ok()?;
    assert(body@ =~= stored@);
    let kind = logical::WalRecordKind::from_tag(decoded.kind)?;
    assert(kind == record.parts().0);
    assert(decoded.flags == record.parts().1);
    if !physical.accepts(kind,decoded.flags) {return None;}
    let read = match (prior,kind) {
        (None,logical::WalRecordKind::Begin) => Measured::begin(sequence,body).ok()?,
        (Some(before),logical::WalRecordKind::Object) => Measured::append(before,DataKind::Object(ObjectEncoding::from_flag(decoded.flags)?),body).ok()?,
        (Some(before),logical::WalRecordKind::Root) => Measured::append(before,DataKind::Root,body).ok()?,
        _ => return None,
    };
    assert(read.parts() == record.parts());
    let (recount,read_digest) = read.observe(collect);
    proof {
        let (kind,flags,ord,counts,stored) = read.parts();
        let h = choose|h:&[u8]| h@ == wal_measurement::digest_header(kind,flags,counts.sequence,ord,stored.len() as u64)
            && #[trigger] collect.ensures((h,stored),read_digest);
        assert(collect.ensures((h,stored),read_digest));
        assert(read_digest@ =~= digest@);
        assert(recount == c);
    }
    let mut recovered = Vec::new();
    recovered.extend_from_slice(body);
    Some((recovered,read_digest,recount))
}

}

verus! {

/// Start with only the public inputs to the production constructors. This
/// discharges the invariant required by the writer-to-reader theorem.
pub(super) fn stored_record<H>(prior:Option<(Counts,DataKind)>, begin_sequence:u64, body:&[u8], prefix:&[u8], suffix:&[u8], limit:u64, hash:H, checksum:Ghost<spec_fn(Seq<u8>)->[u8;32]>)
    -> (out:Option<(Vec<u8>,Vec<u8>,Counts)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32] + Copy,
    requires forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|p:&[u8],v:[u8;32]| #[trigger] hash.ensures((physical::MAGIC,p.len() as u64,p),v) ==> v == (checksum@)(p@),
        prefix.len() as int + suffix.len() + body.len() + physical::WIDTH + logical::HEADER_LEN <= usize::MAX,
    ensures ({
        let bytes = logical::HEADER_LEN as int + body.len();
        let (kind,flags,seq,ordinal,objects,roots,total) = match prior {
            None => (logical::WalRecordKind::Begin,0u8,begin_sequence,0u64,0int,0int,bytes),
            Some((p,DataKind::Object(f))) => (logical::WalRecordKind::Object,f.flag(),p.sequence,p.logical,p.objects as int+1,p.roots as int,p.bytes as int+bytes),
            Some((p,DataKind::Root)) => (logical::WalRecordKind::Root,0u8,p.sequence,p.logical,p.objects as int,p.roots as int+1,p.bytes as int+bytes),
        };
        &&& out.is_some() == (bytes <= limit && ordinal < u64::MAX && objects <= u64::MAX && roots <= u64::MAX && total <= u64::MAX)
        &&& out matches Some((recovered,transcript,c)) ==> recovered@ == body@ &&
            transcript@ == wal_measurement::digest_header(kind,flags,seq,ordinal,body.len() as u64) + body@ &&
            c.sequence == seq && c.logical as int == ordinal as int + 1 && c.objects == objects &&
            c.roots == roots && c.bytes == total
    }),
{
    let (record,prior) = match prior {
        Some((before,kind)) => (Measured::append(before,kind,body).ok()?,Some(before)),
        None => (Measured::begin(begin_sequence,body).ok()?,None),
    };
    assert(follows(record,prior));
    write_and_read(record,prior,prefix,suffix,limit,hash,checksum)
}

}
