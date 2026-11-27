//! Concrete catalog charges compose without saturation or truncation.
use crate::catalog_summary::CatalogSummary;
use vstd::prelude::*;

verus! {
fn extend(branch: CatalogSummary, name: &[u8], logical: u64) -> (out: Option<CatalogSummary>)
    ensures
        out.is_some() == (branch.logical_bytes + logical <= u64::MAX
            && branch.quota_bytes + logical + name.len() <= u64::MAX
            && branch.entries < u64::MAX),
        out matches Some(s) ==> s.logical_bytes == branch.logical_bytes + logical
            && s.quota_bytes == branch.quota_bytes + logical + name.len()
            && s.entries == branch.entries + 1,
{
    let leaf = CatalogSummary::leaf(name, logical)?;
    CatalogSummary::join(branch, leaf)
}
}
