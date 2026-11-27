//! Principal-scoped cache probes, duplicate miss positions and content traversal handoff.
use crate::{ObjectId, ObjectRecord, batch_slots as slots, child_range};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
fn publish_one<P,F,I>(owner:&P,ids:&[ObjectId],id:ObjectId,loaded:ObjectRecord,probe:F,insert:I,
    cache:Ghost<spec_fn(P,ObjectId)->Option<Arc<ObjectRecord>>>)
    -> (out:Vec<Option<Arc<ObjectRecord>>>)
    where F:Fn(&P,ObjectId)->Option<Arc<ObjectRecord>>,
        I:FnOnce(&P,ObjectId,ObjectRecord)->Arc<ObjectRecord>,
    requires vstd::laws_cmp::obeys_cmp::<ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        forall|key:ObjectId| #[trigger] probe.requires((owner,key)),
        forall|key:ObjectId,row:Option<Arc<ObjectRecord>>| #[trigger] probe.ensures((owner,key),row) ==> row == (cache@)(*owner,key),
        insert.requires((owner,id,loaded)),
    ensures out.len() == ids.len(), exists|kept:Arc<ObjectRecord>| #[trigger] insert.ensures((owner,id,loaded),kept)
        && forall|i:int| 0 <= i < ids.len() ==> #[trigger] out@[i] ==
            if ids@[i] == id && (cache@)(*owner,id).is_none() { Some(kept) } else { (cache@)(*owner,ids@[i]) },
{
    let mut batch = slots::prepare(owner,ids,probe);
    let ghost before = batch.records@;
    let ghost missing = batch.missing@;
    assert forall|j:int| #[trigger] slots::waiting(missing,id,j) implies j < batch.records.len() by {}
    slots::publish(&mut batch,owner,id,loaded,insert);
    proof {
        let kept = choose|kept:Arc<ObjectRecord>| #[trigger] insert.ensures((owner,id,loaded),kept)
            && forall|j:int| 0 <= j < before.len() ==> #[trigger] batch.records@[j] ==
                if slots::waiting(missing,id,j) { Some(kept) } else { before[j] };
        assert forall|j:int| 0 <= j < ids.len() implies #[trigger] batch.records@[j] ==
            if ids@[j] == id && (cache@)(*owner,id).is_none() { Some(kept) } else { (cache@)(*owner,ids@[j]) } by {
            assert(probe.ensures((owner,ids@[j]),before[j]));
            if slots::waiting(missing,id,j) { assert(ids@[j] == id); }
        }
    }
    batch.records
}

fn load_visits<R,E,F>(plan:&[child_range::Visit],read:F, table:Ghost<spec_fn(ObjectId)->Option<R>>,
    error:Ghost<E>) -> (out:Result<Vec<(child_range::Visit,R)>,child_range::LoadError<E>>)
    where F:FnOnce(Vec<ObjectId>)->Result<Vec<Option<R>>,E>,
    requires forall|ids:Vec<ObjectId>| #[trigger] read.requires((ids,)),
        forall|ids:Vec<ObjectId>,rows:Vec<Option<R>>| #[trigger] read.ensures((ids,),Ok(rows)) ==>
            (forall|j:int| 0 <= j < rows.len() && j < ids.len() ==> #[trigger] rows@[j] == (table@)(ids@[j])),
        forall|ids:Vec<ObjectId>,e:E| #[trigger] read.ensures((ids,),Err(e)) ==> e == error@,
    ensures out matches Ok(pairs) ==> pairs.len() == plan.len() &&
        forall|j:int| 0 <= j < plan.len() ==> #[trigger] pairs@[j].0 == plan@[j] &&
            (table@)(plan@[j].object) == Some(pairs@[j].1),
        out matches Err(child_range::LoadError::Source(e)) ==> e == error@,
        out matches Err(child_range::LoadError::Length(id)) ==> plan.len() > 0 && id == plan@[0].object,
        out matches Err(child_range::LoadError::Missing(id)) ==> exists|i:int| 0 <= i < plan.len() &&
            #[trigger] plan@[i].object == id && (table@)(id).is_none() &&
            forall|j:int| 0 <= j < i ==> (table@)(#[trigger] plan@[j].object).is_some(),
{
    let out = child_range::load(plan,read);
    proof {
        if let Ok(pairs) = &out {
            if plan.len() > 0 {
                let (ids,rows) = choose|ids:Vec<ObjectId>,rows:Vec<Option<R>>| ids@ == child_range::keys(plan@) &&
                    #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == pairs.len() &&
                    forall|i:int| 0 <= i < pairs.len() ==> #[trigger] pairs@[i].0 == plan@[i] && rows@[i] == Some(pairs@[i].1);
                assert forall|j:int| 0 <= j < plan.len() implies #[trigger] pairs@[j].0 == plan@[j] &&
                    (table@)(plan@[j].object) == Some(pairs@[j].1) by {
                    assert(ids@[j] == plan@[j].object);
                    assert(pairs@[j].0 == plan@[j]);
                    assert(rows@[j] == Some(pairs@[j].1));
                }
            }
        } else if let Err(child_range::LoadError::Missing(id)) = &out {
            let (ids,rows,i) = choose|ids:Vec<ObjectId>,rows:Vec<Option<R>>,i:int|
                ids@ == child_range::keys(plan@) && #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == plan.len()
                && 0 <= i < plan.len() && #[trigger] plan@[i].object == *id && rows@[i].is_none()
                && forall|j:int| 0 <= j < i ==> (#[trigger] rows@[j]).is_some();
            assert(ids@[i] == *id);
            assert forall|j:int| 0 <= j < i implies (table@)(#[trigger] plan@[j].object).is_some() by {
                assert(ids@[j] == plan@[j].object);
                assert(rows@[j].is_some());
            }
        }
    }
    out
}

/// A backend supplying every requested row in order cannot cause a batch refusal.
fn complete<R,E,F>(plan:&[child_range::Visit],read:F)
    -> (out:Result<Vec<(child_range::Visit,R)>,child_range::LoadError<E>>)
    where F:FnOnce(Vec<ObjectId>)->Result<Vec<Option<R>>,E>,
    requires forall|ids:Vec<ObjectId>| #[trigger] read.requires((ids,)),
        forall|ids:Vec<ObjectId>,result:Result<Vec<Option<R>>,E>| #[trigger] read.ensures((ids,),result) ==>
            (result matches Ok(rows) && rows.len() == ids.len() &&
             forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows@[i]).is_some()),
    ensures out.is_ok(),
{
    child_range::load(plan,read)
}
}
