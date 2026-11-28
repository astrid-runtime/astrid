//! Commit receipt transitions under the receipt mutex and ordered batch delivery.
use super::Published;
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

    /// The caller samples receipt allocation identity while holding the queue lock.
    pub(super) fn handoff(queue:&mut Vec<Self>,active:&mut bool,owns_front:bool)
        -> (out:(Option<Self>,Option<Arc<R>>))
        requires *old(active),
        ensures out.0 == if owns_front && old(queue).len() > 0 {Some(old(queue)@[0])} else {None},
            final(queue)@ == if owns_front && old(queue).len() > 0 {old(queue)@.skip(1)} else {old(queue)@},
            out.1 == if final(queue).len() > 0 {Some(final(queue)@[0].receipt)} else {None},
            *final(active) == (final(queue).len() > 0),
    {
        let departing = if owns_front && !queue.is_empty() {Some(queue.remove(0))} else {None};
        let next = Self::successor(queue,active);
        (departing,next)
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
    pub(super) fn published<S,O,E,F:FnOnce(P)->(S,O)>(self,done:&mut Vec<(R,Result<O,E>)>,publish:F) -> (next:S)
        requires publish.requires((self.prepared,)),
        ensures exists|out:O| #[trigger] publish.ensures((self.prepared,),(next,out)) &&
            final(done)@ == old(done)@.push((self.receipt,Ok(out))),
    {
        let (next,out) = publish(self.prepared);
        done.push((self.receipt,Ok(out)));
        next
    }

    pub(super) fn failed<O,E>(self,done:&mut Vec<(R,Result<O,E>)>,error:E)
        ensures final(done)@ == old(done)@.push((self.receipt,Err(error))),
    {
        done.push((self.receipt,Err(error)));
    }
}

/// Each completion is paired with its submitting receipt and the result of publishing that entry.
pub(super) open spec fn completed<P,R,B,S,O,E,F:Fn(S,P)->(S,O)>(
    entries:Seq<Accepted<P,R,B>>,initial:S,states:Seq<S>,results:Seq<(R,Result<O,E>)>,publish:F) -> bool {
    &&& states.len()==entries.len()+1 && states[0]==initial && results.len()==entries.len()
    &&& forall|i:int| 0<=i<entries.len() ==> {
        let r=#[trigger] results[i];
        &&& r.0==entries[i].receipt
        &&& r.1 matches Ok(value) && publish.ensures((states[i],entries[i].prepared),(states[i+1],value))
    }
}

pub(super) open spec fn preserves<P,S,O,F:Fn(S,P)->(S,O)>(valid:spec_fn(S)->bool,publish:F) -> bool {
    &&& forall|s:S,p:P| valid(s) ==> #[trigger] publish.requires((s,p))
    &&& forall|s:S,p:P,v:(S,O)| valid(s) && #[trigger] publish.ensures((s,p),v) ==> valid(v.0)
}

pub(super) fn release<P,R,B,S,O,E,F:Fn(S,P)->(S,O)>(group:Published<Vec<Accepted<P,R,B>>>,done:&mut Vec<(R,Result<O,E>)>,
    initial:S,publish:F) -> (last:S)
    requires exists|valid:spec_fn(S)->bool| valid(initial) && #[trigger] preserves(valid,publish),
    ensures final(done)@.take(old(done).len() as int)==old(done)@,
        exists|states:Seq<S>| #[trigger] completed(group.batch()@,initial,states,final(done)@.skip(old(done).len() as int),publish) &&
            states.last()==last,
{
    let ghost valid=choose|v:spec_fn(S)->bool| v(initial) && #[trigger] preserves(v,publish);
    let batch=group.into_batch();
    let mut it=batch.into_iter();
    let mut state=initial;
    let ghost mut n=0int;
    let ghost mut states=seq![initial];
    let ghost mut results:Seq<(R,Result<O,E>)>=Seq::empty();
    assert(completed(batch@.take(0),initial,states,results,publish));
    loop
        invariant 0<=n<=batch.len(),it.remaining()==batch@.skip(n),
            group.batch()==batch,completed(batch@.take(n),initial,states,results,publish),states.last()==state,
            done@==old(done)@+results,
            valid(state),preserves(valid,publish),
        decreases batch.len()-n,
    {
        let Some(entry)=it.next() else {
            assert(n==batch.len());
            assert(batch@.take(n) =~= batch@);
            assert(done@.take(old(done).len() as int) =~= old(done)@);
            assert(done@.skip(old(done).len() as int) =~= results);
            assert(completed(group.batch()@,initial,states,done@.skip(old(done).len() as int),publish));
            return state;
        };
        assert(entry==batch@[n]);
        let ghost prior=state;
        state=entry.published(done,|p:P| -> (v:(S,O)) ensures publish.ensures((prior,p),v) {publish(state,p)});
        proof {
            let r=done@.last();
            let next_states=states.push(state);
            let next_results=results.push(r);
            assert(r.0==entry.receipt && r.1 is Ok);
            assert(publish.ensures((prior,entry.prepared),(state,(choose|value:O| r.1==Ok(value)))));
            assert forall|i:int| 0<=i<n+1 implies {
                let row=#[trigger] next_results[i];
                &&& row.0==batch@.take(n+1)[i].receipt
                &&& row.1 matches Ok(value) && publish.ensures((next_states[i],batch@.take(n+1)[i].prepared),(next_states[i+1],value))
            } by {
                if i<n {assert(results[i]==next_results[i]);assert(batch@.take(n)[i]==batch@[i]);}
                else {assert(states[n]==prior);}
            }
            assert(done@ =~= old(done)@+next_results);
            states=next_states;results=next_results;n=n+1;
        };
        assert(it.remaining() =~= batch@.skip(n));
    }
}

/// Preserve the original failure for the first submitter and mark its peers unavailable.
pub(super) fn reject<P,R,B,O,E,F:Fn()->E>(batch:Vec<Accepted<P,R,B>>,done:&mut Vec<(R,Result<O,E>)>,error:E,unavailable:F)
    requires unavailable.requires(()),
    ensures final(done)@.take(old(done).len() as int)==old(done)@,
        final(done).len()==old(done).len()+batch.len(),
        forall|i:int| 0<=i<batch.len() ==> {
            let row=#[trigger] final(done)@[old(done).len()+i];
            &&& row.0==batch@[i].receipt
            &&& row.1 matches Err(e) && (if i==0 {e==error} else {unavailable.ensures((),e)})
        },
{
    let mut first=Some(error);
    let mut it=batch.into_iter();
    let ghost mut n=0int;
    loop
        invariant 0<=n<=batch.len(),it.remaining()==batch@.skip(n),unavailable.requires(()),
            first==(if n==0 {Some(error)} else {None}),done.len()==old(done).len()+n,
            done@.take(old(done).len() as int)==old(done)@,
            forall|i:int| 0<=i<n ==> {
                let row=#[trigger] done@[old(done).len()+i];
                &&& row.0==batch@[i].receipt
                &&& row.1 matches Err(e) && (if i==0 {e==error} else {unavailable.ensures((),e)})
            },
        decreases batch.len()-n,
    {
        let Some(entry)=it.next() else {assert(n==batch.len());return;};
        assert(entry==batch@[n]);
        let reason=match first.take() {Some(e)=>e,None=>unavailable()};
        let ghost before=done@;
        entry.failed(done,reason);
        proof {
            assert(done@.take(old(done).len() as int) =~= before.take(old(done).len() as int));
            assert forall|i:int| 0<=i<n+1 implies {
                let row=#[trigger] done@[old(done).len()+i];
                &&& row.0==batch@[i].receipt
                &&& row.1 matches Err(e) && (if i==0 {e==error} else {unavailable.ensures((),e)})
            } by {if i<n {assert(before[old(done).len()+i]==done@[old(done).len()+i]);}}
            n=n+1;
        };
        assert(it.remaining() =~= batch@.skip(n));
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
