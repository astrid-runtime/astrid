//! Decision made under the pending-request lock before consuming an answer.
use vstd::prelude::*;

verus! {

pub(super) fn admits(
    owner: &str, caller: &str,
    expected: Option<(&str, Option<u128>)>, presented: Option<(&str, Option<u128>)>,
) -> (ok: bool)
    ensures ok == (owner@ == caller@ && match expected {
        None => true,
        Some((k, g)) => match presented {
            None => false,
            Some((p, r)) => k@ == p@ && g == r,
        },
    }),
{
    if owner != caller { return false; }
    let Some((bound, generation)) = expected else { return true; };
    let Some((key, registration)) = presented else { return false; };
    bound == key && match (generation, registration) {
        (Some(a), Some(b)) => a == b,
        (None, None) => true,
        _ => false,
    }
}

}
