//! Concrete catalog charges compose without saturation or truncation.
use crate::catalog_summary::CatalogSummary;
use crate::quota_transition::{self, Refusal};
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

/// Compare both production policies to totals in mathematical integers. The
/// owner may already exceed the limit when a write shrinks or preserves usage.
fn owner_replacement(other:u64, old:u64, new:u64, limit:u64) -> (out:Result<(),Refusal>)
    ensures ({
        let before = other + old;
        let after = other + new;
        &&& (out == Ok(())) == (before <= u64::MAX && after <= u64::MAX && (after <= limit || new <= old))
        &&& (out == Err(Refusal::AccountingOverflow)) == (before > u64::MAX || after > u64::MAX)
        &&& out matches Err(Refusal::Exceeded {used,limit:l}) ==> used == after && l == limit
    }),
{
    quota_transition::replace(other,old,new,limit)
}

fn branch_replacement(catalog:u64, components:u64, old:u64, new:u64, limit:u64) -> (out:Result<(),Refusal>)
    ensures ({
        let before = catalog + components;
        let after = before - old + new;
        let invalid = old > components || before > u64::MAX || after > u64::MAX;
        &&& (out == Err(Refusal::AccountingOverflow)) == invalid
        &&& (out == Ok(())) == (!invalid && (after <= limit || new <= old))
        &&& out matches Err(Refusal::Exceeded {used,limit:l}) ==> used == after && l == limit
    }),
{
    quota_transition::replace_branch(catalog,components,old,new,limit)
}

/// Inserting a fresh leaf charges its name bytes as well as its payload.
fn branch_insert(catalog:u64, components:u64, branch:CatalogSummary, name:&[u8], logical:u64, limit:u64)
    -> (out:Result<(),Refusal>)
    requires branch.quota_bytes <= components, catalog + components <= u64::MAX,
        branch.entries < u64::MAX, branch.logical_bytes + logical <= u64::MAX,
    ensures ({
        let added = name.len() + logical;
        let after = catalog + components + added;
        &&& (out == Ok(())) == (after <= u64::MAX && (after <= limit || added == 0))
        &&& (out == Err(Refusal::AccountingOverflow)) == (after > u64::MAX)
        &&& out matches Err(Refusal::Exceeded {used,limit:l}) ==> used == after && l == limit
    }),
{
    let updated = extend(branch,name,logical).ok_or(Refusal::AccountingOverflow)?;
    branch_replacement(catalog,components,branch.quota_bytes,updated.quota_bytes,limit)
}

/// A published owner cannot gain uncharged bytes by consuming a branch. If the
/// merged catalog fits within the two replaced charges, a lowered limit permits it.
fn promotion(components:u64,catalog:u64,branch:u64,merged:u64,limit:u64) -> (out:Result<(),Refusal>)
    ensures ({
        let before = components + catalog;
        let after = components - branch + merged;
        let invalid = branch > components || before > u64::MAX || after > u64::MAX;
        &&& (out == Err(Refusal::AccountingOverflow)) == invalid
        &&& (out == Ok(())) == (!invalid && (after <= limit || merged <= catalog + branch))
        &&& out matches Err(Refusal::Exceeded { used, limit:l }) ==> used == after && l == limit
    }),
{
    quota_transition::promote(components,catalog,branch,merged,limit)
}
}
