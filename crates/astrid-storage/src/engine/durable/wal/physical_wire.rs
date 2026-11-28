//! ASTWAL2 physical envelope and bounded payload extent.
use super::{commit_wire, record_wire::WalRecordKind};
use vstd::prelude::*;

verus! {

pub(super) const WIDTH: usize = 52;
pub(super) const MAGIC: [u8;8] = [b'A', b'S', b'T', b'W', b'A', b'L', b'2', 0];

/// Offset at which the payload of this physical frame starts.
pub(super) fn payload_start(offset:u64) -> (out:Option<u64>)
    ensures out.is_some() == (offset as int + WIDTH <= u64::MAX),
        out matches Some(start) ==> start as int == offset as int + WIDTH,
{
    offset.checked_add(WIDTH as u64)
}

#[derive(Clone,Copy)]
pub(super) struct Envelope {
    pub(super) version: u8,
    pub(super) size: u64,
    pub(super) checksum: [u8;32],
}

impl Envelope {
    pub(super) open spec fn wire(self) -> Seq<u8> {
        MAGIC@ + seq![self.version,0u8,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(self.size) + self.checksum@
    }

    fn encode(self) -> (header:[u8;52])
        ensures header@ == self.wire(),
    {
        let mut header = [0;52];
        header[..8].copy_from_slice(&MAGIC);
        header[8] = self.version;
        header[12..20].copy_from_slice(&commit_wire::little_endian(self.size));
        header[20..].copy_from_slice(&self.checksum);
        assert(header@ =~= self.wire());
        header
    }

    pub(super) fn accepts(self, kind:WalRecordKind, flags:u8) -> (ok:bool)
        ensures ok == ((self.version == 1 && flags == 0) ||
            (self.version == 2 && kind is Object && flags == 1)),
    {
        match self.version { 1 => flags == 0, 2 => matches!(kind,WalRecordKind::Object) && flags == 1, _ => false }
    }

    pub(super) fn validates<F>(self, payload:&[u8], hash:F) -> (ok:bool)
        where F: FnOnce([u8;8],u64,&[u8]) -> [u8;32],
        requires hash.requires((MAGIC,self.size,payload)),
        ensures ok ==> payload.len() == self.size && hash.ensures((MAGIC,self.size,payload),self.checksum),
            !ok && payload.len() == self.size ==> exists|sum:[u8;32]| sum@ != self.checksum@ &&
                #[trigger] hash.ensures((MAGIC,self.size,payload),sum),
    {
        if payload.len() as u64 != self.size {return false;}
        let sum = hash(MAGIC,self.size,payload);
        if sum.as_slice() != self.checksum.as_slice() { return false; }
        assert(sum@ =~= self.checksum@);
        assert(sum == self.checksum);
        assert(hash.ensures((MAGIC,self.size,payload),sum));
        true
    }
}

pub(super) open spec fn supported(header:Seq<u8>) -> bool {
    header.take(8) == MAGIC@ && (header[8] == 1 || header[8] == 2)
        && header[9] == 0 && header[10] == 0 && header[11] == 0
}

pub(super) fn decode(header:&[u8;52]) -> (out:Option<Envelope>)
    ensures out.is_some() == supported(header@),
        out matches Some(e) ==> e.wire() == header@ && e.version == header@[8] &&
            e.size == vstd::bytes::spec_u64_from_le_bytes(header@.subrange(12,20)) && e.checksum@ == header@.skip(20),
{
    assert(header@.take(8) =~= header@.subrange(0,8));
    let magic = MAGIC;
    if header[..8] != magic[..] || !(header[8] == 1 || header[8] == 2)
        || header[9] != 0 || header[10] != 0 || header[11] != 0 { return None; }
    assert(header@.take(8) =~= MAGIC@);
    let mut size = [0;8];
    size.copy_from_slice(&header[12..20]);
    let mut checksum = [0;32];
    checksum.copy_from_slice(&header[20..]);
    let e = Envelope { version:header[8],size:u64::from_le_bytes(size),checksum };
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(e.wire() =~= header@);
    Some(e)
}

pub(super) fn seal<F>(frame:&mut [u8], flags:u8, hash:F) -> (ok:bool)
    where F: FnOnce([u8;8],u64,&[u8]) -> [u8;32],
    requires forall|data:&[u8],size:u64| #[trigger] hash.requires((MAGIC,size,data)),
    ensures ok == (old(frame).len() >= WIDTH),
        !ok ==> final(frame)@ == old(frame)@,
        ok ==> exists|data:&[u8], sum:[u8;32]| data@ == old(frame)@.skip(WIDTH as int) &&
            #[trigger] hash.ensures((MAGIC,data.len() as u64,data),sum) &&
            final(frame)@ == (Envelope { version:if flags == 0 {1} else {2},size:data.len() as u64,checksum:sum }).wire() + data@,
{
    if frame.len() < WIDTH {return false;}
    let data = &frame[WIDTH..];
    let ghost original = frame@;
    let size = data.len() as u64;
    assert(hash.requires((MAGIC,size,data)));
    let sum = hash(MAGIC,size,data);
    assert(hash.ensures((MAGIC,size,data),sum));
    assert(hash.ensures((MAGIC,data.len() as u64,data),sum));
    assert(data@ =~= original.skip(WIDTH as int));
    let header = Envelope { version:if flags == 0 {1} else {2},size,checksum:sum }.encode();
    frame[..WIDTH].copy_from_slice(&header);
    assert(frame@ =~= header@ + original.skip(WIDTH as int));
    true
}

pub(super) enum Extent { Overflow, Incomplete, Oversized, Complete(u64) }

pub(super) fn extent(start:u64, size:u64, file:u64, limit:u64) -> (out:Extent)
    ensures
        (out is Overflow) == (start as int + size > u64::MAX),
        (out is Incomplete) == (file < start as int + size <= u64::MAX),
        (out is Oversized) == (start as int + size <= file && size > limit),
        (out is Complete) == (start as int + size <= file && size <= limit),
        out matches Extent::Complete(end) ==> end as int == start as int + size,
{
    let Some(end) = start.checked_add(size) else {return Extent::Overflow;};
    if end > file {Extent::Incomplete} else if size > limit {Extent::Oversized} else {Extent::Complete(end)}
}

}
