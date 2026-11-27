//! Persisted totals used in checkpoint page headers and branch child pointers.
use crate::storage_fields::{ReadError, fixed};
use crate::storage_words::little_endian;
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct NodeTotals {
    pub(super) entries: u64,
    pub(super) logical_bytes: u64,
    pub(super) quota_bytes: u64,
}


impl NodeTotals {
    pub(super) open spec fn wire(self) -> Seq<u8> {
        vstd::bytes::spec_u64_to_le_bytes(self.entries) +
        vstd::bytes::spec_u64_to_le_bytes(self.logical_bytes) +
        vstd::bytes::spec_u64_to_le_bytes(self.quota_bytes)
    }

    pub(super) fn append(self, bytes: &mut Vec<u8>)
        ensures final(bytes)@ == old(bytes)@ + self.wire(),
    {
        bytes.extend_from_slice(&little_endian(self.entries));
        bytes.extend_from_slice(&little_endian(self.logical_bytes));
        bytes.extend_from_slice(&little_endian(self.quota_bytes));
        assert(bytes@ =~= old(bytes)@ + self.wire());
    }

    pub(super) fn read(bytes: &[u8], cursor: &mut usize) -> (out: Result<Self,ReadError>)
        ensures
            out.is_ok() == (*old(cursor) as int + 24 <= bytes.len()),
            out matches Ok(t) ==> *final(cursor) as int == *old(cursor) as int + 24 &&
                crate::storage_fields::at(bytes@,*old(cursor) as int,t.wire()),
    {
        let ghost start = *cursor as int;
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
        let entries = fixed::<8>(bytes,cursor)?;
        let logical = fixed::<8>(bytes,cursor)?;
        let quota = fixed::<8>(bytes,cursor)?;
        let totals = Self {
            entries: u64::from_le_bytes(entries),
            logical_bytes: u64::from_le_bytes(logical),
            quota_bytes: u64::from_le_bytes(quota),
        };
        assert(bytes@.subrange(start,start+24) =~= entries@ + logical@ + quota@);
        Ok(totals)
    }
}
}
