//! Quota policy for replacing one catalog in a sampled owner header.
use vstd::prelude::*;

verus! {
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    AccountingOverflow,
    Exceeded { used: u64, limit: u64 },
}

pub(super) open spec fn decision(before:int, after:int, limit:u64) -> Result<(),Refusal> {
    if before > u64::MAX || after > u64::MAX || after < 0 {
        Err(Refusal::AccountingOverflow)
    } else if after > limit && after > before {
        Err(Refusal::Exceeded { used:after as u64, limit })
    } else {
        Ok(())
    }
}

pub(super) fn replace(other:u64, previous:u64, next:u64, limit:u64) -> (out:Result<(),Refusal>)
    ensures out == decision(other + previous, other + next, limit),
{
    let before = other.checked_add(previous).ok_or(Refusal::AccountingOverflow)?;
    let after = other.checked_add(next).ok_or(Refusal::AccountingOverflow)?;
    if after > limit && after > before {
        Err(Refusal::Exceeded { used:after, limit })
    } else {
        Ok(())
    }
}

/// The other-components charge includes the branch being replaced.
pub(super) fn replace_branch(catalog:u64, components:u64, previous:u64, next:u64, limit:u64)
    -> (out:Result<(),Refusal>)
    ensures out == if previous > components { Err(Refusal::AccountingOverflow) }
        else { decision(catalog + components, catalog + components - previous + next, limit) },
{
    let remaining = components.checked_sub(previous).ok_or(Refusal::AccountingOverflow)?;
    let updated = remaining.checked_add(next).ok_or(Refusal::AccountingOverflow)?;
    replace(catalog, components, updated, limit)
}
}
