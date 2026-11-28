//! Commit receipt transitions under the receipt mutex and ordered batch delivery.
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

verus! {
#[derive(Default)]
pub(super) enum Slot<T> { #[default] Waiting, Promoted, Ready(T), Consumed }

pub(super) enum Action<T> { Lead, Complete(T) }

impl<T> Slot<T> {
    /// Only the first pending result occupies the slot, superseding promotion.
    pub(super) fn complete(&mut self,result:T) -> (notify:bool)
        ensures notify == (*old(self) is Waiting || *old(self) is Promoted),
            *final(self) == if notify {Self::Ready(result)} else {*old(self)},
    {
        if matches!(self,Self::Ready(_) | Self::Consumed) {return false;}
        *self = Self::Ready(result);
        true
    }

    pub(super) fn promote(&mut self) -> (notify:bool)
        ensures notify == (*old(self) is Waiting),
            *final(self) == if notify {Self::Promoted} else {*old(self)},
    {
        if !matches!(self,Self::Waiting) {return false;}
        *self = Self::Promoted;
        true
    }

    pub(super) fn poll(&mut self) -> (out:Option<Action<T>>)
        ensures *final(self) == if *old(self) is Ready || *old(self) is Consumed {Self::Consumed} else {Self::Waiting},
            out == match *old(self) {Self::Ready(t) => Some(Action::Complete(t)),
                Self::Promoted => Some(Action::Lead),Self::Waiting | Self::Consumed => None},
    {
        let mut pending = Self::Waiting;
        std::mem::swap(self,&mut pending);
        match pending {
            Self::Waiting => None,
            Self::Promoted => Some(Action::Lead),
            Self::Ready(t) => {*self = Self::Consumed; Some(Action::Complete(t))},
            Self::Consumed => {*self = Self::Consumed; None},
        }
    }
}

/// Preparation and its submitter's receipt stay together while the group
/// crosses the durability frontier. Only this entry's result is queued.
pub(super) struct Accepted<P,R,B> {
    pub(super) prepared:P,
    pub(super) receipt:R,
    pub(super) observer:B,
}

impl<P,R,B> Accepted<P,R,B> {
    pub(super) fn published<O,E,F:FnOnce(P)->O>(self,done:&mut Vec<(R,Result<O,E>)>,publish:F)
        requires publish.requires((self.prepared,)),
        ensures exists|out:O| #[trigger] publish.ensures((self.prepared,),out) &&
            final(done)@ == old(done)@.push((self.receipt,Ok(out))),
    {
        let out = publish(self.prepared);
        done.push((self.receipt,Ok(out)));
    }

    pub(super) fn failed<O,E>(self,done:&mut Vec<(R,Result<O,E>)>,error:E)
        ensures final(done)@ == old(done)@.push((self.receipt,Err(error))),
    {
        done.push((self.receipt,Err(error)));
    }
}

pub(super) trait Delivery<R,T> {
    spec fn sent(&self) -> Seq<(R,T)>;
    fn send(&mut self,receipt:R,result:T)
        ensures final(self).sent() == old(self).sent().push((receipt,result));
}

pub(super) fn deliver<R,T,D:Delivery<R,T>>(sink:&mut D,batch:Vec<(R,T)>)
    ensures final(sink).sent() == old(sink).sent() + batch@,
{
    let mut it = batch.into_iter();
    let ghost mut pos = 0int;
    loop
        invariant 0 <= pos <= batch.len(), it.remaining() == batch@.skip(pos),
            sink.sent() == old(sink).sent() + batch@.take(pos),
        ensures sink.sent() == old(sink).sent() + batch@,
        decreases batch.len()-pos,
    {
        let Some((receipt,result)) = it.next() else {
            assert(pos == batch.len());
            assert(batch@.take(pos) =~= batch@);
            break;
        };
        sink.send(receipt,result);
        assert(it.remaining() =~= batch@.skip(pos+1));
        assert(sink.sent() =~= old(sink).sent() + batch@.take(pos+1));
        proof {pos = pos+1;};
    }
}
}
