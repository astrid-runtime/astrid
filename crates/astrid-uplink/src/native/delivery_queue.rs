//! FIFO storage owned by one native socket subscription.

use std::collections::VecDeque;
use vstd::prelude::*;

verus! {

/// Release this queue handle only to the socket whose handshake minted its owner.
pub(super) fn bind_writer<T>(registered: u128, handshake: u128, handle: T) -> (bound: Option<T>)
    ensures bound == if registered == handshake { Some(handle) } else { None },
{
    if registered == handshake { Some(handle) } else { None }
}

pub(super) struct DeliveryQueue<T> {
    events: VecDeque<(T, usize)>,
    bytes: usize,
    closed: bool,
}

pub(super) enum Receipt<T> {
    Closed,
    Empty,
    Event(T),
}

spec fn weight<T>(entries: Seq<(T, usize)>) -> nat
    decreases entries.len(),
{
    if entries.len() == 0 { 0 } else { entries[0].1 as nat + weight(entries.drop_first()) }
}

proof fn weight_append<T>(entries: Seq<(T, usize)>, entry: (T, usize))
    ensures weight(entries.push(entry)) == weight(entries) + entry.1,
    decreases entries.len(),
{
    reveal_with_fuel(weight, 2);
    if entries.len() != 0 {
        assert(entries.push(entry)[0] == entries[0]);
        assert(entries.push(entry).drop_first() =~= entries.drop_first().push(entry));
        weight_append(entries.drop_first(), entry);
    } else {
        assert(entries.push(entry)[0] == entry);
        assert(entries.push(entry).drop_first().len() == 0);
    }
}

impl<T> DeliveryQueue<T> {
    pub(super) closed spec fn contents(&self) -> Seq<(T, usize)> { self.events@ }
    pub(super) closed spec fn retained(&self) -> nat { self.bytes as nat }
    pub(super) closed spec fn terminal(&self) -> bool { self.closed }
    pub(super) closed spec fn consistent(&self) -> bool {
        self.bytes == weight(self.events@) && (self.closed ==> self.events@.len() == 0)
    }

    pub(super) fn new() -> (q: Self)
        ensures q.consistent(), !q.terminal(), q.contents().len() == 0, q.retained() == 0,
    {
        Self { events: VecDeque::new(), bytes: 0, closed: false }
    }

    pub(super) fn is_closed(&self) -> (closed: bool)
        ensures closed == self.terminal(),
    { self.closed }

    pub(super) fn enqueue(&mut self, event: T, bytes: usize, slots: usize, budget: usize, reply_overflow: bool) -> (accepted: bool)
        ensures
            accepted == (!old(self).terminal() && !reply_overflow && old(self).contents().len() < slots &&
                old(self).retained() + bytes <= budget),
            final(self).terminal() == !accepted,
            accepted ==> final(self).contents() == old(self).contents().push((event, bytes)),
            accepted ==> final(self).retained() == old(self).retained() + bytes,
            !accepted ==> final(self).contents().len() == 0 && final(self).retained() == 0,
            old(self).consistent() ==> final(self).consistent(),
    {
        if self.closed || reply_overflow || self.events.len() >= slots
            || self.bytes > budget || bytes > budget.saturating_sub(self.bytes)
        {
            self.events.clear();
            self.bytes = 0;
            self.closed = true;
            return false;
        }
        proof { weight_append(self.events@, (event, bytes)); }
        self.bytes = self.bytes.saturating_add(bytes);
        self.events.push_back((event, bytes));
        true
    }

    pub(super) fn receive(&mut self) -> (result: Receipt<T>)
        ensures
            old(self).terminal() == final(self).terminal(),
            old(self).consistent() ==> final(self).consistent(),
            match result {
                Receipt::Closed => old(self).terminal() && final(self).contents() == old(self).contents() && final(self).retained() == old(self).retained(),
                Receipt::Empty => !old(self).terminal() && old(self).contents().len() == 0 && final(self).contents() == old(self).contents() && final(self).retained() == old(self).retained(),
                Receipt::Event(event) => !old(self).terminal() && old(self).contents().len() > 0 &&
                    event == old(self).contents()[0].0 && final(self).contents() == old(self).contents().drop_first()
                    && (old(self).consistent() ==> final(self).retained() + old(self).contents()[0].1 == old(self).retained()),
            },
    {
        if self.closed { return Receipt::Closed; }
        let Some((event, bytes)) = self.events.pop_front() else { return Receipt::Empty; };
        self.bytes = self.bytes.saturating_sub(bytes);
        Receipt::Event(event)
    }
}

}

impl<T> Default for DeliveryQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl<T> DeliveryQueue<T> {
    pub(super) fn retained_size(&self) -> (usize, usize) {
        (self.events.len(), self.bytes)
    }
}
