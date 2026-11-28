//! Select chunk-tree children for a range using their decoded order and lengths.
use super::ObjectId;
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy)]
pub(super) struct Visit {
    pub(super) index: usize,
    pub(super) object: ObjectId,
    pub(super) length: u64,
    pub(super) chunks: u64,
    pub(super) base: u64,
}

pub(super) open spec fn length(children:Seq<(ObjectId,u64,u64)>) -> nat
    decreases children.len(),
{
    if children.len() == 0 { 0 } else { length(children.drop_last()) + children.last().1 as nat }
}

pub(super) open spec fn visits(children:Seq<(ObjectId,u64,u64)>, base:u64, start:u64, end:u64) -> Seq<Visit>
    decreases children.len(),
{
    if children.len() == 0 { Seq::empty() } else {
        let prefix = children.drop_last();
        let before = visits(prefix,base,start,end);
        let at = base + length(prefix);
        let (object,len,chunks) = children.last();
        if start < at+len && end > at {
            before.push(Visit { index:prefix.len() as usize,object,length:len,chunks,base:at as u64 })
        } else { before }
    }
}

pub(super) fn select(children:&[(ObjectId,u64,u64)],base:u64,start:u64,end:u64)
    -> (out:Option<Vec<Visit>>)
    ensures out.is_some() == (base + length(children@) <= u64::MAX),
        out matches Some(plan) ==> plan@ == visits(children@,base,start,end),
{
    let mut chosen = Vec::new();
    let mut cursor = base;
    let mut index = 0usize;
    while index < children.len()
        invariant index <= children.len(), cursor == base + length(children@.take(index as int)),
            chosen@ == visits(children@.take(index as int),base,start,end),
        decreases children.len()-index,
    {
        let (object,len,chunks) = children[index];
        let ghost prefix = children@.take(index as int);
        let ghost next_prefix = children@.take(index as int+1);
        assert(next_prefix.drop_last() =~= prefix);
        assert(next_prefix.last() == children@[index as int]);
        let Some(next) = cursor.checked_add(len) else {
            proof { prefix_bound(children@,index as nat+1); }
            return None;
        };
        if start < next && end > cursor {
            chosen.push(Visit { index,object,length:len,chunks,base:cursor });
        }
        cursor = next;
        index = index.saturating_add(1);
    }
    assert(children@.take(index as int) =~= children@);
    Some(chosen)
}

proof fn prefix_bound(children:Seq<(ObjectId,u64,u64)>,n:nat)
    requires n <= children.len(),
    ensures length(children.take(n as int)) <= length(children),
    decreases children.len()-n,
{
    if n < children.len() {
        assert(children.drop_last().take(n as int) =~= children.take(n as int));
        prefix_bound(children.drop_last(),n);
    } else { assert(children.take(n as int) =~= children); }
}

pub(super) enum LoadError<E> { Source(E), Length(ObjectId), Missing(ObjectId) }

pub(super) open spec fn keys(plan: Seq<Visit>) -> Seq<ObjectId> {
    plan.map_values(|v:Visit| v.object)
}

/// Request records in visit order and pair each complete result with its original visit.
pub(super) fn load<R,E,F>(plan:&[Visit],read:F) -> (out:Result<Vec<(Visit,R)>,LoadError<E>>)
    where F:FnOnce(Vec<ObjectId>)->Result<Vec<Option<R>>,E>,
    requires forall|ids:Vec<ObjectId>| ids@ == keys(plan@) ==> #[trigger] read.requires((ids,)),
    ensures
        out matches Ok(pairs) ==> pairs.len() == plan.len() && (plan.len() == 0 ||
            exists|ids:Vec<ObjectId>,rows:Vec<Option<R>>| ids@ == keys(plan@) &&
            #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == pairs.len() &&
            forall|i:int| 0 <= i < pairs.len() ==> #[trigger] pairs@[i].0 == plan@[i] &&
                rows@[i] == Some(pairs@[i].1)),
        out matches Err(LoadError::Source(e)) ==> exists|ids:Vec<ObjectId>| #[trigger] ids@ == keys(plan@) &&
            read.ensures((ids,),Err(e)),
        out matches Err(LoadError::Length(id)) ==> plan.len() > 0 && id == plan@[0].object &&
            exists|ids:Vec<ObjectId>,rows:Vec<Option<R>>| ids@ == keys(plan@) &&
                #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() != plan.len(),
        out matches Err(LoadError::Missing(id)) ==> exists|ids:Vec<ObjectId>,rows:Vec<Option<R>>,i:int|
            ids@ == keys(plan@) && #[trigger] read.ensures((ids,),Ok(rows)) && rows.len() == plan.len()
            && 0 <= i < plan.len() && #[trigger] plan@[i].object == id && rows@[i].is_none()
            && forall|j:int| 0 <= j < i ==> (#[trigger] rows@[j]).is_some(),
{
    let mut pairs = Vec::with_capacity(plan.len());
    if plan.is_empty() { return Ok(pairs); }
    let mut ids = Vec::with_capacity(plan.len());
    let mut i = 0usize;
    while i < plan.len()
        invariant i <= plan.len(), ids.len() == i,
            forall|j:int| 0 <= j < i ==> #[trigger] ids@[j] == plan@[j].object,
        decreases plan.len()-i,
    {
        ids.push(plan[i].object);
        i = i.saturating_add(1);
    }
    assert(ids@ =~= keys(plan@));
    let ghost request = ids;
    let mut rows = match read(ids) { Ok(rows) => rows, Err(e) => {
        assert(read.ensures((request,),Err(e)));
        assert(request@ == keys(plan@));
        assert(exists|w:Vec<ObjectId>| #[trigger] w@ == keys(plan@) && read.ensures((w,),Err(e)));
        return Err(LoadError::Source(e));
    } };
    if rows.len() != plan.len() { return Err(LoadError::Length(plan[0].object)); }
    let ghost initial = rows;
    let mut j = 0usize;
    while j < plan.len()
        invariant j <= plan.len(), pairs.len() == j, rows.len() == initial.len() == plan.len(),
            request@ == keys(plan@), read.ensures((request,),Ok(initial)),
            forall|k:int| j <= k < plan.len() ==> #[trigger] rows@[k] == initial@[k],
            forall|k:int| 0 <= k < j ==> #[trigger] pairs@[k].0 == plan@[k] && initial@[k] == Some(pairs@[k].1),
        decreases plan.len()-j,
    {
        let visit = plan[j];
        let Some(record) = rows[j].take() else {
            assert forall|k:int| 0 <= k < j implies (#[trigger] initial@[k]).is_some() by { assert(pairs@[k].0 == plan@[k]); }
            return Err(LoadError::Missing(visit.object));
        };
        pairs.push((visit,record));
        j = j.saturating_add(1);
    }
    Ok(pairs)
}
}
