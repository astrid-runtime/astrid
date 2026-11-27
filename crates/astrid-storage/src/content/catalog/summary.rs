//! Checked accounting shared by catalog construction and validation.
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CatalogSummary {
    pub(crate) logical_bytes: u64,
    pub(crate) quota_bytes: u64,
    pub(crate) entries: u64,
}

impl CatalogSummary {
    pub(super) fn leaf(name: &[u8], logical: u64) -> (out: Option<Self>)
        ensures
            out.is_some() == (logical + name.len() <= u64::MAX),
            out matches Some(s) ==> s.logical_bytes == logical
                && s.quota_bytes == logical + name.len() && s.entries == 1,
    {
        let quota = logical.checked_add(u64::try_from(name.len()).ok()?)?;
        Some(Self { logical_bytes: logical, quota_bytes: quota, entries: 1 })
    }

    pub(super) fn join(left: Self, right: Self) -> (out: Option<Self>)
        ensures
            out.is_some() == (left.logical_bytes + right.logical_bytes <= u64::MAX
                && left.quota_bytes + right.quota_bytes <= u64::MAX
                && left.entries + right.entries <= u64::MAX),
            out matches Some(s) ==> s.logical_bytes == left.logical_bytes + right.logical_bytes
                && s.quota_bytes == left.quota_bytes + right.quota_bytes
                && s.entries == left.entries + right.entries,
    {
        Some(Self {
            logical_bytes: left.logical_bytes.checked_add(right.logical_bytes)?,
            quota_bytes: left.quota_bytes.checked_add(right.quota_bytes)?,
            entries: left.entries.checked_add(right.entries)?,
        })
    }
}
}
