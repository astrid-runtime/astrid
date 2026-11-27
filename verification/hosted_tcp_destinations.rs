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
    ensures ({
        let loopback = match request {
            crate::tcp_bind_target::Address::V4(bits) => 0x7f000000 <= bits <= 0x7fffffff,
            crate::tcp_bind_target::Address::V6(bits) => bits == 1,
        };
        out == if loopback && actual == request && assigned != 0 && (port == 0 || assigned == port) {
            Some((actual,assigned))
        } else { None }
    }),
{
    let target = crate::tcp_bind_target::Target::admit(request, port)?;
    let (ip, requested_port) = target.endpoint();
    assert(ip == request && requested_port == port);
    target.confirm((actual,assigned), |observed:&(crate::tcp_bind_target::Address,u16)|
        -> (r:(crate::tcp_bind_target::Address,u16)) ensures r == *observed, { *observed }).ok()
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

verus! {
// The second accept cannot receive the first accept's reserved socket, even
// when the stream budget is already exhausted at the first observation.
fn successive_accepts<T>(slot: &mut Option<T>, count: usize, limit: usize)
    -> (out: (crate::net_reservation::TcpAcceptAdmission<T>, crate::net_reservation::TcpAcceptAdmission<T>))
    ensures
        final(slot).is_none(),
        match *old(slot) {
            Some(value) => out.0 matches crate::net_reservation::TcpAcceptAdmission::Reserved(v) && v == value,
            None => if count < limit { out.0 is Fresh } else { out.0 is Full },
        },
        if count < limit { out.1 is Fresh } else { out.1 is Full },
{
    let first = crate::net_reservation::admit(slot, limit, || -> (n: usize) ensures n == count, { count });
    let second = crate::net_reservation::admit(slot, limit, || -> (n: usize) ensures n == count, { count });
    (first, second)
}
}

verus! {
// Delivering a readiness reservation at capacity cannot take a fresh quota
// unit. A failed insertion must release the charge and return the table error.
fn publish_reserved<S,H,E,B:crate::net_reservation::StreamTable<S,H,E>>(
    table: &mut B, slot: &mut Option<S>, limit: usize,
) -> (out: Result<H,crate::net_reservation::RegisterError<E>>)
    requires old(slot).is_some(),
    ensures final(slot).is_none(),
        match out {
            Ok(h) => final(table).events() == old(table).events()
                .push(crate::net_reservation::Event::Claim)
                .push(crate::net_reservation::Event::Publish(old(slot).unwrap(),Ok(h))),
            Err(crate::net_reservation::RegisterError::Table(e)) => final(table).events() == old(table).events()
                .push(crate::net_reservation::Event::Claim)
                .push(crate::net_reservation::Event::Publish(old(slot).unwrap(),Err(e)))
                .push(crate::net_reservation::Event::Release),
            Err(crate::net_reservation::RegisterError::Quota) => false,
        },
{
    use crate::net_reservation::{admit,register,TcpAcceptAdmission,StreamCharge};
    match admit(slot,limit,|| -> (n:usize) ensures n == limit, { limit }) {
        TcpAcceptAdmission::Reserved(s) => register(table,s,StreamCharge::Reserved),
        _ => { assert(false); Err(crate::net_reservation::RegisterError::Quota) },
    }
}
}
