//! An authorized port and all IP classifications constrain the complete dial list.
use crate::tcp_destinations::{connect,Refusal};
use vstd::prelude::*;

verus! {
fn dial(answers:&[(bool,u16,u128)], port:u16) -> (out:Result<&[(bool,u16,u128)],Refusal>)
    ensures
        (out matches Err(Refusal::Empty)) == (answers.len() == 0),
        (out matches Err(Refusal::Denied)) == (exists|i:int| 0 <= i < answers.len()
            && (!(#[trigger] answers@[i]).0 || answers@[i].1 != port)),
        out matches Ok(selected) ==> selected == answers && selected.len() > 0
            && forall|i:int| 0 <= i < selected.len() ==> (#[trigger] selected@[i]).0 && selected@[i].1 == port,
{
    let check = |a:&(bool,u16,u128),p:u16| -> (allow:bool)
        ensures allow == (a.0 && a.1 == p), { a.0 && a.1 == p };
    let out = connect(answers,port,check,
        |selected:&[(bool,u16,u128)]| -> (r:&[(bool,u16,u128)]) ensures r == selected, { selected });
    proof {
        match out {
            Ok(_) => {
                assert forall|i:int| 0 <= i < answers.len() implies
                    (#[trigger] answers@[i]).0 && answers@[i].1 == port by {
                    assert(check.ensures((&answers@[i],port),true));
                }
            }
            Err(Refusal::Denied) => {
                let i = choose|i:int| 0 <= i < answers.len() && #[trigger] check.ensures((&answers@[i],port),false);
                assert(!answers@[i].0 || answers@[i].1 != port);
            }
            _ => {}
        }
    }
    out
}
}

verus! {
fn accepted_listener(request: crate::tcp_bind_target::Address, port: u16,
    actual: crate::tcp_bind_target::Address, assigned: u16) -> (out: Option<(crate::tcp_bind_target::Address,u16)>)
    ensures out == if request.loopback() && actual == request && assigned != 0 && (port == 0 || assigned == port) {
        Some((request,port))
    } else { None },
{
    let target = crate::tcp_bind_target::Target::admit(request, port)?;
    if target.matches_bound(actual, assigned) { Some(target.endpoint()) } else { None }
}
}

verus! {
// A contender that observes a committed change must use the new occupancy.
fn successive_reservations(count: usize, limit: usize) -> (second: Option<usize>)
    ensures if count as int + 2 <= limit as int {
        second matches Some(n) && n as int == count as int + 2
    } else { second.is_none() },
{
    let first = crate::net_reservation::reserve(count, limit)?;
    crate::net_reservation::reserve(first, limit)
}
}
