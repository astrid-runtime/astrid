//! Recipient selection at the native socket delivery queue.

use vstd::prelude::*;

verus! {

pub(super) struct Address<'a> {
    pub principal: Option<&'a [u8]>,
    pub device: Option<&'a [u8]>,
    pub session: Option<&'a [u8]>,
}

pub(super) open spec fn present_equal(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => a@ == b@,
        _ => false,
    }
}

fn same(left: Option<&[u8]>, right: Option<&[u8]>) -> (equal: bool)
    ensures equal == present_equal(left, right),
{
    match (left, right) {
        (Some(a), Some(b)) => {
            if a != b { return false; }
            assert(a@ =~= b@);
            true
        },
        _ => false,
    }
}

pub(super) fn admits(target: &Address<'_>, client: &Address<'_>, allowed: bool, broadcast: bool, chat: bool) -> (admitted: bool)
    ensures admitted == (allowed
        && (present_equal(target.principal, client.principal) || (target.principal.is_none() && broadcast))
        && (target.device.is_none() || present_equal(target.device, client.device))
        && (!chat || present_equal(target.session, client.session))),
{
    allowed
        && match target.principal {
            Some(_) => same(target.principal, client.principal),
            None => broadcast,
        }
        && (target.device.is_none() || same(target.device, client.device))
        && (!chat || same(target.session, client.session))
}

/// Authority required to send an operator approval to this socket.
pub(super) fn approval_owner(
    source: u128, stamp: Option<u128>, client: u128, payload_owner: &[u8], client_text: &[u8],
) -> (allowed: bool)
    ensures allowed == (source == 0 && stamp == Some(client) && payload_owner@ == client_text@),
{
    source == 0 && stamp == Some(client) && same(Some(payload_owner), Some(client_text))
}

pub(super) fn ordinary_owner(stamp: Option<u128>, expected: u128) -> (allowed: bool)
    ensures allowed == (stamp.is_none() || stamp == Some(expected)),
{
    match stamp { Some(actual) => actual == expected, None => true }
}

#[derive(Clone, Copy)]
pub(super) struct ResponseCorrelation {
    pub(super) producer: u128,
    pub(super) nonce: u128,
}

/// A turn can establish its producer/nonce pair once. An unstamped terminal
/// response must match both values established by an owned nonterminal frame.
pub(super) fn admit_turn(
    owner: u128, stamp: Option<u128>, producer: u128, nonce: Option<u128>,
    completed: bool, binding: &mut Option<ResponseCorrelation>,
) -> (admitted: bool)
    ensures
        admitted == (stamp == Some(owner) || (stamp.is_none() && completed &&
            (nonce matches Some(n) && *old(binding) == Some(ResponseCorrelation { producer, nonce: n })))),
        *final(binding) == (if stamp == Some(owner) && !completed && old(binding).is_none()
            && producer != 0 && (nonce matches Some(n) && n != 0) {
            Some(ResponseCorrelation { producer, nonce: nonce.unwrap() })
        } else { *old(binding) }),
{
    if stamp == Some(owner) {
        match nonce {
            Some(n) if !completed && binding.is_none() && producer != 0 && n != 0 => {
                *binding = Some(ResponseCorrelation { producer, nonce: n });
            },
            _ => {},
        }
        return true;
    }
    if stamp.is_some() || !completed { return false; }
    match (*binding, nonce) {
        (Some(saved), Some(actual)) => saved.producer == producer && saved.nonce == actual,
        _ => false,
    }
}

}
