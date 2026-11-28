//! Classify a damaged journal suffix and sequence repair on the same media handle.
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Bound { Live(u64), Committed {start:u64,end:u64} }

#[derive(Clone,Copy)]
pub(super) struct Window {
    pub(super) start:u64, pub(super) end:u64, pub(super) protected:u64, pub(super) restore_cursor:bool,
}

pub(super) fn window(physical:u64,bound:Bound) -> (out:Option<Window>)
    ensures match bound {
        Bound::Live(p) => out.is_some() == (p <= physical) && (out matches Some(w) ==>
            w.start == 0 && w.end == physical && w.protected == p && !w.restore_cursor),
        Bound::Committed {start,end} => out.is_some() == (start <= end <= physical) && (out matches Some(w) ==>
            w.start == start && w.end == end && w.protected == end && w.restore_cursor),
    },
{
    match bound {
        Bound::Live(p) if p <= physical => Some(Window {start:0,end:physical,protected:p,restore_cursor:false}),
        Bound::Committed {start,end} if start <= end && end <= physical =>
            Some(Window {start,end,protected:end,restore_cursor:true}),
        _ => None,
    }
}

pub(super) enum Extent { Complete(u64), Incomplete, Oversize {interior:bool}, Overflow }

pub(super) fn extent(offset:u64,end:u64,len:u64,limit:u64) -> (out:Extent)
    ensures ({
        let next = offset as int + super::arena_frame::WIDTH + len;
        match out {
            Extent::Complete(n) => len <= limit && n == next && offset < n <= end,
            Extent::Incomplete => len <= limit && end < next <= u64::MAX,
            Extent::Overflow => len <= limit && next > u64::MAX,
            Extent::Oversize {interior} => len > limit && interior == (next <= end),
        }
    }),
{
    let next = match (super::arena_frame::WIDTH as u64).checked_add(len) {Some(n) => offset.checked_add(n),None => None};
    if len > limit {return Extent::Oversize {interior:match next {Some(n) => n <= end,None => false}};}
    match next {
        None => Extent::Overflow,
        Some(n) if n > end => Extent::Incomplete,
        Some(n) => Extent::Complete(n),
    }
}

#[derive(Clone,Copy)]
pub(super) enum Damage { Incomplete, Suspect { known_interior:bool } }

#[cfg(verus_keep_ghost)]
pub(super) enum Event { Probe(u64), Resize(u64), Flush }

pub(super) trait Medium {
    type Error;
    spec fn calls(&self) -> Seq<Event>;
    spec fn bytes(&self) -> Seq<u8>;
    spec fn durable(&self) -> Seq<u8>;
    spec fn probe_result(&self, offset:u64, result:Result<bool,Self::Error>) -> bool;

    fn later_frame(&mut self,offset:u64) -> (out:Result<bool,Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Probe(offset)),
            final(self).bytes() == old(self).bytes(), final(self).durable() == old(self).durable(),
            old(self).probe_result(offset,out);

    fn resize(&mut self,offset:u64) -> (out:Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Resize(offset)),
            out.is_ok() && offset <= old(self).bytes().len() ==> final(self).bytes() == old(self).bytes().take(offset as int);

    fn flush(&mut self) -> (out:Result<(),Self::Error>)
        ensures final(self).calls() == old(self).calls().push(Event::Flush),
            out.is_ok() ==> final(self).durable() == old(self).bytes() && final(self).bytes() == old(self).bytes();
}

pub(super) enum Outcome { Reject, Repaired }
pub(super) enum Error<E> { Probe(E), Resize(E), Flush(E) }

pub(super) fn repair<M:Medium>(media:&mut M,offset:u64,end:u64,protected:u64,damage:Damage)
    -> (out:Result<Outcome,Error<M::Error>>)
    ensures ({
        let before = old(media).calls();
        let blocked = offset < protected || offset >= end || (damage matches Damage::Suspect {known_interior:true});
        let probe = !blocked && (damage matches Damage::Suspect {known_interior:false});
        let prefix = if probe {before.push(Event::Probe(offset))} else {before};
        &&& match out {
            Ok(Outcome::Reject) => (blocked || (probe && old(media).probe_result(offset,Ok(true)))) &&
                final(media).calls() == prefix && final(media).bytes() == old(media).bytes() &&
                final(media).durable() == old(media).durable(),
            Err(Error::Probe(e)) => probe && old(media).probe_result(offset,Err(e)) &&
                final(media).calls() == prefix && final(media).bytes() == old(media).bytes() &&
                final(media).durable() == old(media).durable(),
            _ => !blocked && (probe ==> old(media).probe_result(offset,Ok(false))) &&
                match out {
                    Err(Error::Resize(_)) => final(media).calls() == prefix.push(Event::Resize(offset)),
                    _ => final(media).calls() == prefix.push(Event::Resize(offset)).push(Event::Flush),
                },
        }
        &&& out matches Ok(Outcome::Repaired) ==> (offset <= old(media).bytes().len() ==>
            final(media).bytes() == old(media).bytes().take(offset as int) && final(media).durable() == final(media).bytes())
    }),
{
    if offset < protected || offset >= end {return Ok(Outcome::Reject);}
    if let Damage::Suspect {known_interior} = damage {
        if known_interior {return Ok(Outcome::Reject);}
        match media.later_frame(offset) {
            Ok(false) => {},
            Ok(true) => return Ok(Outcome::Reject),
            Err(e) => return Err(Error::Probe(e)),
        }
    }
    if let Err(e) = media.resize(offset) {return Err(Error::Resize(e));}
    if let Err(e) = media.flush() {return Err(Error::Flush(e));}
    Ok(Outcome::Repaired)
}
}
