//! Admit the validated checkpoint before opening the replay context.
use super::{
    ObjectId,
    checkpoint_totals::NodeTotals,
    delta_chain::Chain,
    delta_mutation::Mutation,
    delta_replay::{self, Cursor},
};
use vstd::prelude::*;

verus! {
pub(super) enum Error<E> {
    Root,
    Totals,
    Replay(delta_replay::Error<E>),
}

pub(super) fn recover<S,E,I:FnOnce()->S,F:Fn(S,Option<ObjectId>,ObjectId,&Vec<Mutation>,NodeTotals)->Result<(S,NodeTotals),E>>(
    chain:Chain,root:Option<ObjectId>,measured:NodeTotals,start:I,apply:F,Ghost(valid):Ghost<spec_fn(S)->bool>) -> (out:Result<Cursor<S>,Error<E>>)
    requires start.requires(()),
        forall|s:S| #[trigger] start.ensures((),s) ==> valid(s),delta_replay::preserves(apply,valid),
    ensures
        (out is Err && out->Err_0 is Root) == (chain.tree != root),
        (out is Err && out->Err_0 is Totals) == (chain.tree == root && measured != chain.totals),
        out matches Ok(c) ==> exists|s:S| #[trigger] start.ensures((),s) &&
            delta_replay::replayed(s,measured,root,chain.newest_first@,0,apply,c),
        out matches Err(Error::Replay(e)) ==> exists|s:S| #[trigger] start.ensures((),s) &&
            delta_replay::failed(s,measured,root,chain.newest_first@,apply,e),
{
    let matches_root = match (chain.tree,root) {
        (Some(a),Some(b)) => a.same(&b),
        (None,None) => true,
        _ => false,
    };
    if !matches_root {return Err(Error::Root);}
    if measured.entries != chain.totals.entries || measured.logical_bytes != chain.totals.logical_bytes ||
        measured.quota_bytes != chain.totals.quota_bytes {return Err(Error::Totals);}
    let state = start();
    match delta_replay::run(state,chain.totals,chain.tree,chain.newest_first,apply,Ghost(valid)) {
        Ok(cursor) => Ok(cursor),
        Err(e) => Err(Error::Replay(e)),
    }
}
}
