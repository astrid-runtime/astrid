//! One stored record supplies the count transition, physical frame and digest.
use super::{
    commit_wire::{Counts, little_endian},
    measurement::{self, Entry, Overflow},
    physical_wire,
    record_wire::{Header, WalRecordKind},
};
use vstd::prelude::*;

verus! {

#[derive(Clone,Copy)]
pub(super) enum DataKind { Object(u8), Root }

pub(super) struct Measured<'a> {
    kind: WalRecordKind,
    flags: u8,
    ordinal: u64,
    counts: Counts,
    body: &'a [u8],
}

impl<'a> Measured<'a> {
    pub(super) closed spec fn parts(self) -> (WalRecordKind,u8,u64,Counts,&'a [u8]) {
        (self.kind,self.flags,self.ordinal,self.counts,self.body)
    }

    pub(super) fn begin(sequence:u64,body:&'a [u8]) -> (result:Result<Self,Overflow>)
        ensures result.is_ok() == (super::record_wire::HEADER_LEN as int + body.len() <= u64::MAX),
            result matches Ok(r) ==> r.parts() == (WalRecordKind::Begin,0u8,0u64,
                Counts {sequence,logical:1,objects:0,roots:0,bytes:(super::record_wire::HEADER_LEN as int + body.len()) as u64},body),
    {
        let counts = measurement::begin(sequence,body).ok_or(Overflow::Bytes)?;
        Ok(Self {kind:WalRecordKind::Begin,flags:0,ordinal:0,counts,body})
    }

    pub(super) fn append(before:Counts,entry:DataKind,body:&'a [u8]) -> (result:Result<Self,Overflow>)
        ensures result.is_ok() == (before.logical < u64::MAX &&
            before.bytes as int + super::record_wire::HEADER_LEN as int + body.len() <= u64::MAX &&
            (if entry is Object {before.objects < u64::MAX} else {before.roots < u64::MAX})),
            result matches Ok(r) ==> ({
                let (kind,flags,ordinal,c,stored) = r.parts();
                &&& (kind,flags) == match entry {DataKind::Object(f) => (WalRecordKind::Object,f), DataKind::Root => (WalRecordKind::Root,0u8)}
                &&& ordinal == before.logical && stored == body
                &&& c.sequence == before.sequence && c.logical as int == 1 + before.logical
                &&& c.bytes as int == before.bytes as int + super::record_wire::HEADER_LEN as int + body.len()
                &&& c.objects as int == before.objects as int + if entry is Object {1int} else {0int}
                &&& c.roots as int == before.roots as int + if entry is Root {1int} else {0int}
            }),
    {
        let (counter,kind,flags) = match entry {
            DataKind::Object(f) => (Entry::Object,WalRecordKind::Object,f),
            DataKind::Root => (Entry::Root,WalRecordKind::Root,0),
        };
        let counts = measurement::append(before,counter,body)?;
        Ok(Self {kind,flags,ordinal:before.logical,counts,body})
    }

    pub(super) fn body(&self) -> (bytes:&'a [u8]) ensures bytes == self.parts().4 { self.body }

    pub(super) open spec fn payload(&self) -> Seq<u8> {
        let (kind,flags,ordinal,c,body) = self.parts();
        let tag:u8 = match kind {WalRecordKind::Begin=>1,WalRecordKind::Object=>2,WalRecordKind::Root=>3,WalRecordKind::Commit=>4};
        seq![tag,flags,0u8,0u8] + vstd::bytes::spec_u64_to_le_bytes(c.sequence) +
            vstd::bytes::spec_u64_to_le_bytes(ordinal) + body@
    }

    pub(super) open spec fn sealed<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(&self,hash:H,encoded:Seq<u8>) -> bool {
        exists|p:&[u8],sum:[u8;32]| p@ == self.payload() &&
            #[trigger] hash.ensures((physical_wire::MAGIC,p.len() as u64,p),sum) &&
            encoded == (physical_wire::Envelope {version:if self.parts().1 == 0 {1} else {2},
                size:p.len() as u64,checksum:sum}).wire() + self.payload()
    }

    /// The caller supplies a fallibly reserved buffer with room for one frame.
    pub(super) fn encode<H>(&self, mut frame:Vec<u8>, hash:H) -> (result:Option<Vec<u8>>)
        where H:FnOnce([u8;8],u64,&[u8])->[u8;32],
        requires forall|p:&[u8],n:u64| #[trigger] hash.requires((physical_wire::MAGIC,n,p)),
        ensures result.is_some() == (frame.len() == physical_wire::WIDTH),
            result matches Some(encoded) ==> self.sealed(hash,encoded@),
    {
        if frame.len() != physical_wire::WIDTH {return None;}
        let header = Header { kind:self.kind.tag(),flags:self.flags,reserved:[0;2],
            sequence:little_endian(self.counts.sequence), ordinal:little_endian(self.ordinal) };
        header.append(&mut frame,self.body);
        assert(frame@.skip(52) =~= self.payload());
        if !physical_wire::seal(frame.as_mut_slice(),self.flags,hash) { return None; }
        assert(self.sealed(hash,frame@));
        Some(frame)
    }

    pub(super) open spec fn observed<T,F:FnOnce(&[u8],&[u8])->T>(&self,update:F,value:T) -> bool {
        let (kind,flags,ordinal,c,body) = self.parts();
        exists|h:&[u8]| h@ == measurement::digest_header(kind,flags,c.sequence,ordinal,body.len() as u64)
            && #[trigger] update.ensures((h,body),value)
    }

    pub(super) fn observe<T,F>(self, update:F) -> (result:(Counts,T))
        where F:FnOnce(&[u8],&[u8])->T,
        requires forall|h:&[u8],p:&[u8]| #[trigger] update.requires((h,p)),
        ensures result.0 == self.parts().3, self.observed(update,result.1),
    {
        let value = measurement::digest_record(self.kind,self.flags,self.counts.sequence,self.ordinal,self.body,update);
        proof {
            let h = choose|h:&[u8]| h@ == measurement::digest_header(self.kind,self.flags,self.counts.sequence,self.ordinal,self.body.len() as u64)
                && #[trigger] update.ensures((h,self.body),value);
            assert(update.ensures((h,self.parts().4),value));
            assert(self.observed(update,value));
        }
        (self.counts,value)
    }
    /// Seal and measure the same input before the caller can append the bytes.
    pub(super) fn write<H,F,T>(self, frame:Vec<u8>, hash:H, update:F) -> (out:Option<(Vec<u8>,Counts,T)>)
        where H:FnOnce([u8;8],u64,&[u8])->[u8;32], F:FnOnce(&[u8],&[u8])->T,
        requires forall|p:&[u8],n:u64| #[trigger] hash.requires((physical_wire::MAGIC,n,p)),
            forall|h:&[u8],p:&[u8]| #[trigger] update.requires((h,p)),
        ensures out.is_some() == (frame.len() == physical_wire::WIDTH),
            out matches Some((bytes,c,value)) ==> self.sealed(hash,bytes@) && c == self.parts().3 && self.observed(update,value),
    {
        let bytes = self.encode(frame,hash)?;
        let (counts,value) = self.observe(update);
        Some((bytes,counts,value))
    }

}

}
