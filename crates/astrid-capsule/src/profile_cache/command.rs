//! Admit the durable command update on the profile selected inside the write lock.
use vstd::prelude::*;

verus! {

pub(super) fn on_current_profile<P, S: Copy, R, Check, Commit>(
    profile: P, devices: [S; 2], current: Check, commit: Commit,
) -> (result: Option<R>)
    where Check: Fn(&P, S) -> bool, Commit: FnOnce(P) -> R,
    requires
        current.requires((&profile, devices[0])),
        current.requires((&profile, devices[1])),
        commit.requires((profile,)),
    ensures
        match result {
            Some(r) => current.ensures((&profile, devices[0]), true)
                && current.ensures((&profile, devices[1]), true)
                && commit.ensures((profile,), r),
            None => current.ensures((&profile, devices[0]), false)
                || current.ensures((&profile, devices[1]), false),
        },
{
    if current(&profile, devices[0]) && current(&profile, devices[1]) {
        Some(commit(profile))
    } else {
        None
    }
}

}
