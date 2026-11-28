//! Commit receipt transitions under the receipt mutex and ordered batch delivery.
use std::sync::Arc;
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

pub(super) struct Submission<T,R,B> {
    pub(super) transaction:T,
    pub(super) receipt:Arc<R>,
    pub(super) observer:B,
}

type Preparation<P,R,B,E> = Result<Accepted<P,Arc<R>,B>,(Arc<R>,E)>;

impl<T,R,B> Submission<T,R,B> {
    pub(super) fn enqueue(queue:&mut Vec<Self>,active:&mut bool,transaction:T,receipt:&Arc<R>,observer:B)
        -> (lead:bool)
        ensures final(queue)@ == old(queue)@.push(Self {transaction,receipt:*receipt,observer}),
            *final(active), lead == !*old(active),
    {
        queue.push(Self {transaction,receipt:Arc::clone(receipt),observer});
        let lead = !*active;
        *active = true;
        lead
    }

    /// Move the entire FIFO allocation to its leader under the queue mutex.
    pub(super) fn drain(queue:&mut Vec<Self>) -> (batch:Vec<Self>)
        ensures final(queue)@ == Seq::<Self>::empty(), batch@ == old(queue)@,
    {
        let mut batch = Vec::new();
        std::mem::swap(queue,&mut batch);
        batch
    }

    pub(super) fn successor(queue:&[Self],active:&mut bool) -> (out:Option<Arc<R>>)
        ensures out == if queue.len() == 0 {None} else {Some(queue@[0].receipt)},
            *final(active) == (queue.len() > 0 && *old(active)),
    {
        if let Some(next) = queue.first() {Some(Arc::clone(&next.receipt))}
        else {*active = false; None}
    }

    pub(super) fn prepare<P,E,F:FnOnce(T,&B)->Result<P,E>>(self,prepare:F)
        -> (out:Preparation<P,R,B,E>)
        requires prepare.requires((self.transaction,&self.observer)),
        ensures match out {
            Ok(a) => a.receipt == self.receipt && a.observer == self.observer &&
                prepare.ensures((self.transaction,&self.observer),Ok(a.prepared)),
            Err((receipt,e)) => receipt == self.receipt && prepare.ensures((self.transaction,&self.observer),Err(e)),
        },
    {
        match prepare(self.transaction,&self.observer) {
            Ok(prepared) => Ok(Accepted {prepared,receipt:self.receipt,observer:self.observer}),
            Err(error) => Err((self.receipt,error)),
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
