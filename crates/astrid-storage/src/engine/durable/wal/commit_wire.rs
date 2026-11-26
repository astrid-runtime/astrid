//! ASTWAL2 Commit body. All counts and the sequence are little-endian u64s.
use super::{physical_wire, record_wire};
use vstd::prelude::*;

verus! {

pub(super) const LENGTH: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Counts {
    pub(super) sequence: u64,
    pub(super) logical: u64,
    pub(super) objects: u64,
    pub(super) roots: u64,
    pub(super) bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Marker {
    pub(super) counts: Counts,
    pub(super) digest: [u8;32],
}

pub(super) enum Mismatch { Sequence, Logical, Objects, Roots, Bytes, Digest }

impl Counts {
    pub(super) fn validate(&self, observed: &Self) -> (result: Result<(),Mismatch>)
        ensures result.is_ok() == (*self == *observed), !(result matches Err(Mismatch::Digest)),
    {
        if self.sequence != observed.sequence { return Err(Mismatch::Sequence); }
        if self.logical != observed.logical { return Err(Mismatch::Logical); }
        if self.objects != observed.objects { return Err(Mismatch::Objects); }
        if self.roots != observed.roots { return Err(Mismatch::Roots); }
        if self.bytes != observed.bytes { return Err(Mismatch::Bytes); }
        Ok(())
    }
}

pub(super) fn little_endian(value: u64) -> (bytes: [u8;8])
    ensures bytes@ == vstd::bytes::spec_u64_to_le_bytes(value),
{
    proof { vstd::bytes::spec_u64_to_le_bytes_to_open(value); }
    let bytes = [
        (value & 255) as u8, ((value >> 8) & 255) as u8,
        ((value >> 16) & 255) as u8, ((value >> 24) & 255) as u8,
        ((value >> 32) & 255) as u8, ((value >> 40) & 255) as u8,
        ((value >> 48) & 255) as u8, ((value >> 56) & 255) as u8,
    ];
    assert(bytes@ =~= vstd::bytes::spec_u64_to_le_bytes_open(value));
    bytes
}

impl Marker {
    pub(super) open spec fn wire(&self) -> Seq<u8> {
        vstd::bytes::spec_u64_to_le_bytes(self.counts.sequence)
        + vstd::bytes::spec_u64_to_le_bytes(self.counts.logical)
        + vstd::bytes::spec_u64_to_le_bytes(self.counts.objects)
        + vstd::bytes::spec_u64_to_le_bytes(self.counts.roots)
        + vstd::bytes::spec_u64_to_le_bytes(self.counts.bytes)
        + self.digest@
    }

    pub(super) fn encode(&self) -> (body: [u8;72])
        ensures body@ == self.wire(),
    {
        let mut body = [0;72];
        body[..8].copy_from_slice(&little_endian(self.counts.sequence));
        body[8..16].copy_from_slice(&little_endian(self.counts.logical));
        body[16..24].copy_from_slice(&little_endian(self.counts.objects));
        body[24..32].copy_from_slice(&little_endian(self.counts.roots));
        body[32..40].copy_from_slice(&little_endian(self.counts.bytes));
        body[40..].copy_from_slice(&self.digest);
        assert(body@ =~= self.wire());
        body
    }

    pub(super) open spec fn payload(&self) -> Seq<u8> {
        seq![4u8,0u8,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(self.counts.sequence)
            + vstd::bytes::spec_u64_to_le_bytes(self.counts.logical) + self.wire()
    }

    /// Both the logical header and the marker body come from this transaction.
    pub(super) fn frame<H>(&self, mut frame:Vec<u8>, hash:H) -> (out:Option<Vec<u8>>)
        where H:FnOnce([u8;8],u64,&[u8])->[u8;32],
        requires forall|p:&[u8],n:u64| #[trigger] hash.requires((physical_wire::MAGIC,n,p)),
        ensures out.is_some() == (frame.len() == physical_wire::WIDTH),
            out matches Some(bytes) ==> exists|p:&[u8],sum:[u8;32]| p@ == self.payload() &&
                #[trigger] hash.ensures((physical_wire::MAGIC,p.len() as u64,p),sum) &&
                bytes@ == (physical_wire::Envelope {version:1,size:p.len() as u64,checksum:sum}).wire() + p@,
    {
        if frame.len() != physical_wire::WIDTH { return None; }
        let header = record_wire::Header { kind:record_wire::WalRecordKind::Commit.tag(), flags:0, reserved:[0;2],
            sequence:little_endian(self.counts.sequence), ordinal:little_endian(self.counts.logical) };
        header.append(&mut frame,&self.encode());
        assert(frame@.skip(52) =~= self.payload());
        if !physical_wire::seal(frame.as_mut_slice(),0,hash) { return None; }
        Some(frame)
    }

    pub(super) fn digest_matches(&self, observed: &[u8;32]) -> (matches: bool)
        ensures matches == (self.digest@ == observed@),
    {
        if self.digest.as_slice() != observed.as_slice() { return false; }
        assert(self.digest@ =~= observed@);
        true
    }
}

/// Scanner evidence carried by the Commit event. Construction requires the
/// observed counters and the full digest of the scanner's logical records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CheckedMarker(Marker);

impl CheckedMarker {
    pub(super) closed spec fn marker(&self) -> Marker { self.0 }
    pub(super) fn counts(&self) -> (c: &Counts) ensures *c == self.marker().counts { &self.0.counts }
}

impl Marker {
    pub(super) fn confirm<F>(self, observed: &Counts, finish_digest: F)
        -> (out: Result<CheckedMarker,Mismatch>) where F: FnOnce() -> [u8;32],
        requires finish_digest.requires(()),
        ensures
            out matches Ok(checked) ==> checked.marker() == self && self.counts == *observed
                && finish_digest.ensures((),self.digest),
            out matches Err(Mismatch::Digest) ==> self.counts == *observed && exists|d:[u8;32]|
                #[trigger] finish_digest.ensures((),d) && d@ != self.digest@,
            out.is_err() && !(out matches Err(Mismatch::Digest)) ==> self.counts != *observed,
    {
        self.counts.validate(observed)?;
        let digest = finish_digest();
        if !self.digest_matches(&digest) { return Err(Mismatch::Digest); }
        assert(digest == self.digest);
        Ok(CheckedMarker(self))
    }
}

fn word(body: &[u8], at: usize) -> (number: u64)
    requires at as int + 8 <= body.len(),
    ensures number == vstd::bytes::spec_u64_from_le_bytes(body@.subrange(at as int,at as int + 8)),
{
    let mut bytes = [0;8];
    bytes.copy_from_slice(&body[at..at.saturating_add(8)]);
    u64::from_le_bytes(bytes)
}

pub(super) fn decode(body: &[u8]) -> (marker: Option<Marker>)
    ensures marker.is_some() == (body.len() == LENGTH),
        marker matches Some(m) ==> m.wire() == body@,
{
    if body.len() != LENGTH { return None; }
    let counts = Counts { sequence: word(body,0), logical: word(body,8), objects: word(body,16),
        roots: word(body,24), bytes: word(body,32) };
    let mut digest = [0;32];
    digest.copy_from_slice(&body[40..]);
    let marker = Marker { counts, digest };
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(marker.wire() =~= body@);
    Some(marker)
}

}
