//! Ordered, addressed application of a recovered delta to its checkpoint overlay.
use super::{
    ObjectId,
    checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
    delta_mutation::Mutation,
    delta_totals::ApplyError,
    mutation_replay,
    replay_values::{self, Bytes},
    traversal, update,
};
use std::sync::Arc;
use vstd::prelude::*;

verus! {
pub(crate) type Failure<E> = (usize,(ObjectId,ApplyError<E>));
pub(super) type State<C> = (C,Option<Arc<traversal::Node>>,NodeTotals);

pub(super) open spec fn installed<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(before:State<C>,tree:Option<ObjectId>,row:&Mutation,
    lookup:L,value:V,next:State<C>,pair:(Bytes,Bytes)) -> bool {
    &&& replay_values::resolved(before.0,tree,&row.key,replay_values::borrowed(&row.value),
        traversal::lookup_spec(before.1,row.key@).is_none(),lookup,value,Ok((next.0,pair)))
    &&& update::changed(before.1,next.1,row,before.2,next.2,pair,Ok(()))
}
pub(super) open spec fn advanced<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(before:State<C>,tree:Option<ObjectId>,row:&Mutation,
    lookup:L,value:V,next:State<C>) -> bool {
    exists|p:(Bytes,Bytes)| #[trigger] installed(before,tree,row,lookup,value,next,p)
}
pub(super) open spec fn transition<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(before:State<C>,tree:Option<ObjectId>,id:ObjectId,
    row:&Mutation,lookup:L,value:V,out:Result<State<C>,(ObjectId,ApplyError<E>)>) -> bool {
    if out.is_ok() {
        advanced(before,tree,row,lookup,value,out->Ok_0)
    } else {
        let need = traversal::lookup_spec(before.1,row.key@).is_none();
        let (k,e)=out->Err_0;
        k==id && match e {
            ApplyError::Load(e) => replay_values::resolved(before.0,tree,&row.key,replay_values::borrowed(&row.value),need,lookup,value,Err(e)),
            ApplyError::Change(e) => exists|after:C,p:(Bytes,Bytes)| #[trigger] replay_values::resolved(before.0,tree,&row.key,
                replay_values::borrowed(&row.value),need,lookup,value,Ok((after,p))) && update::changed(before.1,before.1,row,before.2,before.2,p,Err(e)),
        }
    }
}
proof fn accepted<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(before:State<C>,tree:Option<ObjectId>,id:ObjectId,row:&Mutation,
    lookup:L,value:V,next:State<C>,pair:(Bytes,Bytes))
    requires installed(before,tree,row,lookup,value,next,pair),
    ensures transition(before,tree,id,row,lookup,value,Ok(next)),
{
    assert(advanced(before,tree,row,lookup,value,next));
}
pub(super) open spec fn history<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(initial:State<C>,tree:Option<ObjectId>,id:ObjectId,rows:Seq<Mutation>,
    lookup:L,value:V,states:Seq<State<C>>) -> bool {
    &&& 1 <= states.len() <= rows.len()+1 && states[0]==initial
    &&& forall|i:int| 0 <= i < states.len()-1 ==> transition(#[trigger] states[i],tree,id,&rows[i],lookup,value,Ok(states[i+1]))
}

/// Absent, deleted and present are distinct observations of an immutable overlay.
pub(super) open spec fn presence(root:Option<Arc<traversal::Node>>,key:Seq<u8>) -> Option<bool> {
    match traversal::lookup_spec(root,key) {None => None,Some(v) => Some(v.is_some())}
}

pub(super) open spec fn after_rows(rows:Seq<Mutation>,n:nat,key:Seq<u8>,initial:Option<bool>) -> Option<bool>
    decreases n,
{
    if n==0 {initial}
    else if rows[n-1].key@==key {Some(rows[n-1].value.is_some())}
    else {after_rows(rows,(n-1) as nat,key,initial)}
}

proof fn replay_presence<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(
    initial:State<C>,tree:Option<ObjectId>,id:ObjectId,rows:Seq<Mutation>,lookup:L,value:V,h:Seq<State<C>>,n:nat,key:Seq<u8>)
    requires history(initial,tree,id,rows,lookup,value,h),n<h.len(),
    ensures presence(h[n as int].1,key) == after_rows(rows,n,key,presence(initial.1,key)),
    decreases n,
{
    if n==0 {return;}
    replay_presence(initial,tree,id,rows,lookup,value,h,(n-1) as nat,key);
    let before=h[n-1];let after=h[n as int];let row=rows[n-1];
    assert(transition(before,tree,id,&row,lookup,value,Ok(after)));
    let pair=choose|pair:(Bytes,Bytes)| #[trigger] installed(before,tree,&row,lookup,value,after,pair);
    assert(update::changed(before.1,after.1,&row,before.2,after.2,pair,Ok(())));
    if key==row.key@ {
        if traversal::lookup_spec(before.1,key).is_none() {
            let (c,prior)=choose|c:C,prior:Bytes| #[trigger] lookup.ensures((before.0,tree,&row.key),Ok((c,prior))) &&
                replay_values::finish(c,prior,replay_values::borrowed(&row.value),value,Ok((after.0,pair)));
            assert(pair.1.is_some() == row.value.is_some());
        }
        assert(pair.1.is_some()==row.value.is_some());
    }
    assert(traversal::lookup_spec(after.1,key)==if key==row.key@ {Some(pair.1)} else {traversal::lookup_spec(before.1,key)});
}

pub(super) fn run<C,E,L:Fn(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>+Copy,
    V:Fn(C,&ValueSlot)->Result<(C,Vec<u8>),E>+Copy>(initial:State<C>,tree:Option<ObjectId>,id:ObjectId,
    rows:&[Mutation],lookup:L,value:V) -> (out:Result<State<C>,Failure<E>>)
    requires traversal::ordered(initial.1),forall|s:C,t:Option<ObjectId>,key:&Vec<u8>| #[trigger] lookup.requires((s,t,key)),
        forall|s:C,v:&ValueSlot| #[trigger] value.requires((s,v)),
    ensures out matches Ok(s) ==> traversal::ordered(s.1),
        out matches Ok(s) ==> forall|key:Seq<u8>| #[trigger] presence(s.1,key) ==
            after_rows(rows@,rows.len() as nat,key,presence(initial.1,key)),
        exists|h:Seq<State<C>>| #[trigger] history(initial,tree,id,rows@,lookup,value,h) && match out {
        Ok(s) => h.len()==rows.len()+1 && h.last()==s,
        Err((i,e)) => i<rows.len() && h.len()==i+1 && transition(h.last(),tree,id,&rows@[i as int],lookup,value,Err(e)),
    },
{
    let step = |s:State<C>,base:Option<ObjectId>,object:ObjectId,row:&Mutation| -> (r:Result<State<C>,(ObjectId,ApplyError<E>)>)
        requires traversal::ordered(s.1),
        ensures transition(s,base,object,row,lookup,value,r),r matches Ok(after) ==> traversal::ordered(after.1),
    {
        let (ctx,mut root,mut totals) = s;
        let load = |key:&Vec<u8>,slot:&Option<ValueSlot>,need:bool| -> (v:Result<(C,(Bytes,Bytes)),E>)
            ensures replay_values::resolved(ctx,base,key,replay_values::borrowed(slot),need,lookup,value,v),
        {replay_values::resolve_state(ctx,base,key,slot.as_ref(),need,lookup,value)};
        let ghost args = (&row.key,&row.value,traversal::lookup_spec(s.1,row.key@).is_none());
        let got = update::apply_state(&mut root,&mut totals,row,load);
        let ghost observed = got;
        proof {
            if !(observed matches Err(ApplyError::Load(_))) {
                let (c,p)=choose|c:C,p:(Bytes,Bytes)| #[trigger] load.ensures(args,Ok((c,p))) && match observed {
                    Ok(next)=>next==c && update::changed(s.1,root,row,s.2,totals,p,Ok(())),
                    Err(ApplyError::Change(e))=>update::changed(s.1,root,row,s.2,totals,p,Err(e)),
                    _=>false,
                };
                assert(replay_values::resolved(ctx,base,&row.key,replay_values::borrowed(&row.value),args.2,lookup,value,Ok((c,p))));
                match observed {
                    Ok(next) => {
                        assert(next==c && ctx==s.0);
                        let dest:State<C> = (next,root,totals);
                        assert(installed(s,base,row,lookup,value,dest,p));
                        accepted(s,base,object,row,lookup,value,dest,p);
                    },
                    Err(ApplyError::Change(e)) => {
                        assert(root==s.1 && totals==s.2);
                        assert(update::changed(s.1,s.1,row,s.2,s.2,p,Err(e)));
                        assert(transition(s,base,object,row,lookup,value,Err((object,ApplyError::Change(e)))));
                    },
                    _ => {},
                }
            } else if let Err(ApplyError::Load(e)) = observed {
                assert(load.ensures(args,Err(e)));
                assert(transition(s,base,object,row,lookup,value,Err((object,ApplyError::Load(e)))));
            }
        }
        match got {
            Ok(c) => Ok((c,root,totals)),
            Err(e) => {assert(root==s.1 && totals==s.2);Err((object,e))},
        }
    };
    assert forall|h:Seq<State<C>>| #[trigger] mutation_replay::prefix(initial,tree,id,rows@,h,step) && h.len()<=rows.len()
        implies step.requires((h.last(),tree,id,&rows@[h.len()-1])) by {
        if h.len()>1 {
            let j=h.len() as int-2;assert(step.ensures((h[j],tree,id,&rows@[j]),Ok(h[j+1])));
        }
    }
    let out = mutation_replay::run_at(initial,tree,id,rows,step);
    let ghost saved = out;
    proof {
        let h=choose|h:Seq<State<C>>| #[trigger] mutation_replay::prefix(initial,tree,id,rows@,h,step) && match out {
            Ok(s)=>h.len()==rows.len()+1 && h.last()==s,
            Err((i,e))=>h.len()==i+1 && i<rows.len() && step.ensures((h.last(),tree,id,&rows@[h.len()-1]),Err(e)),
        };
        assert forall|j:int| 0<=j<h.len()-1 implies transition(#[trigger] h[j],tree,id,&rows@[j],lookup,value,Ok(h[j+1])) by {
            assert(step.ensures((h[j],tree,id,&rows@[j]),Ok(h[j+1])));
        }
        assert(history(initial,tree,id,rows@,lookup,value,h));
        if let Ok(s)=saved {
            if rows.len()>0 {
                assert(transition(h[rows.len()-1],tree,id,&rows@[rows.len()-1],lookup,value,Ok(s)));
            }
            assert(traversal::ordered(s.1));
            assert forall|key:Seq<u8>| #[trigger] presence(s.1,key) ==
                after_rows(rows@,rows.len() as nat,key,presence(initial.1,key)) by {
                replay_presence(initial,tree,id,rows@,lookup,value,h,rows.len() as nat,key);
            }
        }
    }
    out
}
}
