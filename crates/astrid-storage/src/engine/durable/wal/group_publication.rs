//! Pair each accepted transaction with its own WAL frames and publish the group in order.
use vstd::prelude::*;

verus! {

pub(super) struct Entry<'a,T,F> {
    pub(super) transaction:&'a T,
    pub(super) frames:F,
}

pub(super) fn prepare<'a,T,F,E,C:Fn(&'a T)->Result<F,E>>(transactions:&'a [T],collect:C)
    -> (result:Result<Vec<Entry<'a,T,F>>,E>)
    requires forall|t:&'a T| #[trigger] collect.requires((t,)),
    ensures match result {
        Ok(entries)=>entries.len()==transactions.len() && forall|i:int| 0<=i<entries.len() ==> {
            let entry=#[trigger] entries@[i];
            &&& *entry.transaction==transactions@[i]
            &&& collect.ensures((entry.transaction,),Ok(entry.frames))
        },
        Err(error)=>exists|i:int| 0<=i<transactions.len() && #[trigger] collect.ensures((&transactions@[i],),Err(error)),
    },
{
    let mut entries:Vec<Entry<'a,T,F>>=Vec::with_capacity(transactions.len());
    while entries.len()<transactions.len()
        invariant entries.len()<=transactions.len(),
            forall|t:&'a T| #[trigger] collect.requires((t,)),
            forall|i:int| 0<=i<entries.len() ==> {
                let entry=#[trigger] entries@[i];
                &&& *entry.transaction==transactions@[i]
                &&& collect.ensures((entry.transaction,),Ok(entry.frames))
            },
        decreases transactions.len()-entries.len(),
    {
        let t=&transactions[entries.len()];
        let frames=collect(t)?;
        entries.push(Entry{transaction:t,frames});
    }
    Ok(entries)
}

/// The overlay receives the same group that completed publication, together with its flush result.
pub(super) fn install_after_flush<'a,T,F,M,R,O,E,P,I>(entries:&'a [Entry<'a,T,F>],staged:&'a M,publish:P,install:I)
    -> (out:Result<O,E>)
    where P:FnOnce(&'a [Entry<'a,T,F>],&'a M)->Result<R,E>,
          I:FnOnce(&'a [Entry<'a,T,F>],&'a M,R)->Result<O,E>,
    requires publish.requires((entries,staged)),
        forall|r:R| publish.ensures((entries,staged),Ok(r)) ==> #[trigger] install.requires((entries,staged,r)),
    ensures match out {
        Ok(value)=>exists|r:R| publish.ensures((entries,staged),Ok(r)) && #[trigger] install.ensures((entries,staged,r),Ok(value)),
        Err(error)=>publish.ensures((entries,staged),Err(error)) || exists|r:R|
            publish.ensures((entries,staged),Ok(r)) && #[trigger] install.ensures((entries,staged,r),Err(error)),
    },
{
    let receipt=publish(entries,staged)?;
    let result=install(entries,staged,receipt);
    proof {
        let observed=result;
        assert(publish.ensures((entries,staged),Ok(receipt)));
        match observed {
            Ok(value)=>{assert(install.ensures((entries,staged,receipt),Ok(value)));},
            Err(error)=>{assert(install.ensures((entries,staged,receipt),Err(error)));},
        }
    };
    result
}

pub(super) enum Action<'a,T,F> { Begin, Objects{first:bool,frames:&'a F}, Root(&'a T), Commit }

/// Each transaction contributes its begin, objects, root and commit before the group flush.
pub(super) open spec fn actions<'a,T,F>(entries:Seq<Entry<'a,T,F>>) -> Seq<Action<'a,T,F>> {
    Seq::new(4 * entries.len(), |position:int| {
        let transaction=position / 4;
        let entry=entries[transaction];
        let phase=position % 4;
        if phase==0 {Action::Begin}
        else if phase==1 {Action::Objects{first:transaction==0,frames:&entry.frames}}
        else if phase==2 {Action::Root(entry.transaction)}
        else {Action::Commit}
    })
}

pub(super) open spec fn applied<'a,T,F,S,E,W:Fn(S,Action<'a,T,F>)->Result<S,E>>(write:W,initial:S,steps:Seq<Action<'a,T,F>>,state:S) -> bool
    decreases steps.len(),
{
    if steps.len()==0 {state==initial} else {
        exists|prior:S| applied(write,initial,steps.drop_last(),prior) &&
            #[trigger] write.ensures((prior,steps.last()),Ok(state))
    }
}

pub(super) open spec fn stopped<'a,T,F,S,E,W:Fn(S,Action<'a,T,F>)->Result<S,E>>(write:W,initial:S,steps:Seq<Action<'a,T,F>>,error:E) -> bool {
    exists|index:int,prior:S| 0<=index<steps.len() && applied(write,initial,steps.take(index),prior) &&
        #[trigger] write.ensures((prior,steps[index]),Err(error))
}

fn step<'a,T,F,S,E,W:Fn(S,Action<'a,T,F>)->Result<S,E>>(write:&W,state:S,action:Action<'a,T,F>,
    _initial:Ghost<S>,_all:Ghost<Seq<Action<'a,T,F>>>,_position:Ghost<int>) -> (out:Result<S,E>)
    requires 0<=_position@<_all@.len(),_all@[_position@]==action,write.requires((state,action)),
        applied(*write,_initial@,_all@.take(_position@),state),
    ensures match out {Ok(s)=>applied(*write,_initial@,_all@.take(_position@+1),s),Err(e)=>stopped(*write,_initial@,_all@,e)},
{
    let result=write(state,action);
    proof {
        let next=_all@.take(_position@+1);
        assert(next.drop_last() =~= _all@.take(_position@));
        assert(next.last()==action);
        let observed=result;
        match observed {
            Ok(s)=>{assert(applied(*write,_initial@,next.drop_last(),state));assert(applied(*write,_initial@,next,s));},
            Err(e)=>{assert(stopped(*write,_initial@,_all@,e));},
        }
    };
    result
}

pub(super) fn publish<'a,T,F,S,E,R,W:Fn(S,Action<'a,T,F>)->Result<S,E>,Sync:FnOnce(S)->Result<R,E>>(
    entries:&'a [Entry<'a,T,F>],initial:S,write:W,flush:Sync) -> (out:Result<R,E>)
    requires forall|s:S,a:Action<'a,T,F>| #[trigger] write.requires((s,a)),
        forall|s:S| #[trigger] flush.requires((s,)),
    ensures ({
        let steps=actions(entries@);
        match out {
            Ok(receipt)=>exists|s:S| applied(write,initial,steps,s) && #[trigger] flush.ensures((s,),Ok(receipt)),
            Err(e)=>stopped(write,initial,steps,e) ||
                exists|s:S| applied(write,initial,steps,s) && #[trigger] flush.ensures((s,),Err(e)),
        }
    }),
{
    let ghost all=actions(entries@);
    let mut state=initial;
    let mut i=0usize;
    while i<entries.len()
        invariant i<=entries.len(),applied(write,initial,all.take(4*i as int),state),
            all==actions(entries@),
            forall|s:S,a:Action<'a,T,F>| #[trigger] write.requires((s,a)),
        decreases entries.len()-i,
    {
        let e=&entries[i];
        let ghost n=4*i as int;
        state=step(&write,state,Action::Begin,Ghost(initial),Ghost(all),Ghost(n))?;
        state=step(&write,state,Action::Objects{first:i==0,frames:&e.frames},Ghost(initial),Ghost(all),Ghost(n+1))?;
        state=step(&write,state,Action::Root(e.transaction),Ghost(initial),Ghost(all),Ghost(n+2))?;
        state=step(&write,state,Action::Commit,Ghost(initial),Ghost(all),Ghost(n+3))?;
        i=i.saturating_add(1);
    }
    assert(all.take(4*i as int) =~= all);
    let result=flush(state);
    proof {
        let observed=result;
        match observed {
            Ok(receipt)=>{assert(flush.ensures((state,),Ok(receipt)));assert(applied(write,initial,all,state));},
            Err(error)=>{assert(flush.ensures((state,),Err(error)));assert(applied(write,initial,all,state));},
        }
    };
    result
}

}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Seen {
        Begin,
        Objects(bool, u8),
        Root(u8),
        Commit,
        Flush,
    }

    #[test]
    fn group_keeps_two_roots_with_their_frames_and_stops_at_each_failed_write() {
        let entries = prepare(&[7u8, 3], |owner| Ok::<_, ()>(owner.saturating_add(10))).unwrap();
        let expected = [
            Seen::Begin,
            Seen::Objects(true, 17),
            Seen::Root(7),
            Seen::Commit,
            Seen::Begin,
            Seen::Objects(false, 13),
            Seen::Root(3),
            Seen::Commit,
            Seen::Flush,
        ];
        for stop in 0..=expected.len() {
            let mut trace = Vec::new();
            let result = publish(
                &entries,
                &mut trace,
                |trace, action| {
                    let event = match action {
                        Action::Begin => Seen::Begin,
                        Action::Objects { first, frames } => Seen::Objects(first, *frames),
                        Action::Root(owner) => Seen::Root(*owner),
                        Action::Commit => Seen::Commit,
                    };
                    if trace.len() == stop {
                        return Err(event);
                    }
                    trace.push(event);
                    Ok(trace)
                },
                |trace| {
                    if trace.len() == stop {
                        return Err(Seen::Flush);
                    }
                    trace.push(Seen::Flush);
                    Ok(trace.len())
                },
            );
            assert_eq!(
                result,
                expected.get(stop).copied().map_or(Ok(expected.len()), Err)
            );
            assert_eq!(trace, expected[..stop]);
        }
    }
}
