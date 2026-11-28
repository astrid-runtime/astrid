//! Fixed fields between the KV delta tag and its first mutation.
use super::{ObjectId, ObjectReference, ReferenceLabel, reference_lookup};
use crate::storage_fields::{ReadError, fixed};
use crate::storage_words::{little_endian, little_endian_u32, read_u32};
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) struct Header {
    pub(super) depth:u64,
    pub(super) delta_bytes:u64,
    pub(super) entries:u64,
    pub(super) quota_bytes:u64,
    pub(super) count:u32,
}

impl Header {
    pub(super) open spec fn wire(self) -> Seq<u8> {
        vstd::bytes::spec_u64_to_le_bytes(self.depth) +
        vstd::bytes::spec_u64_to_le_bytes(self.delta_bytes) +
        vstd::bytes::spec_u64_to_le_bytes(self.entries) +
        vstd::bytes::spec_u64_to_le_bytes(self.quota_bytes) +
        crate::storage_words::word32(self.count)
    }

    pub(super) fn append(self,bytes:&mut Vec<u8>)
        ensures final(bytes)@ == old(bytes)@ + self.wire(),
    {
        bytes.extend_from_slice(&little_endian(self.depth));
        bytes.extend_from_slice(&little_endian(self.delta_bytes));
        bytes.extend_from_slice(&little_endian(self.entries));
        bytes.extend_from_slice(&little_endian(self.quota_bytes));
        bytes.extend_from_slice(&little_endian_u32(self.count));
        assert(bytes@ =~= old(bytes)@ + self.wire());
    }

    /// The fixed header follows the dispatch byte at offset zero.
    pub(super) fn read(bytes:&[u8]) -> (out:Result<(Self,usize),ReadError>)
        ensures out.is_ok() == (bytes.len() >= 37),
            out.is_err() ==> out == Err(ReadError::Truncated),
            out matches Ok((h,end)) ==> end == 37 && bytes@.subrange(1,37) == h.wire(),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
        let mut cursor = 1usize;
        let depth = fixed::<8>(bytes,&mut cursor)?;
        let charge = fixed::<8>(bytes,&mut cursor)?;
        let entries = fixed::<8>(bytes,&mut cursor)?;
        let quota = fixed::<8>(bytes,&mut cursor)?;
        let count = read_u32(fixed::<4>(bytes,&mut cursor)?);
        let header = Self {
            depth:u64::from_le_bytes(depth), delta_bytes:u64::from_le_bytes(charge),
            entries:u64::from_le_bytes(entries), quota_bytes:u64::from_le_bytes(quota), count,
        };
        assert(bytes@.subrange(1,37) =~= header.wire());
        Ok((header,cursor))
    }
}

pub(super) const PREVIOUS:[u8;8] = [b'p',b'r',b'e',b'v',b'i',b'o',b'u',b's'];

pub(super) fn predecessor_label() -> (label:ReferenceLabel)
    ensures label.value()@ == PREVIOUS@,
{
    let mut bytes = Vec::with_capacity(PREVIOUS.len());
    bytes.extend_from_slice(&PREVIOUS);
    ReferenceLabel::new(bytes)
}

pub(super) fn predecessor_edges(previous:Option<ObjectId>) -> (refs:Vec<ObjectReference>)
    ensures match previous {
        None => refs.len() == 0,
        Some(id) => refs.len() == 1 && refs@[0].fields() == (PREVIOUS@,id,super::ReferenceKind::Owns),
    },
{
    let mut refs = Vec::new();
    if let Some(id) = previous {
        refs.push(ObjectReference::owns(predecessor_label(),id));
    }
    refs
}

pub(super) enum EdgeError { NonOwning }

pub(super) fn predecessor(refs:&[ObjectReference]) -> (out:Result<Option<ObjectId>,EdgeError>)
    ensures out == match reference_lookup::selected(refs@,PREVIOUS@,0,refs.len() as int) {
        None => Ok(None),
        Some(r) => if r.fields().2 is Owns {Ok(Some(r.fields().1))} else {Err(EdgeError::NonOwning)},
    },
{
    let Some(reference) = reference_lookup::find(refs,&PREVIOUS) else {return Ok(None);};
    match reference.owning_target() {
        Some(id) => Ok(Some(id)),
        None => Err(EdgeError::NonOwning),
    }
}
}
