//! Select one complete immutable KV projection for a captured component head.
use super::{ObjectId, checkpoint_totals::NodeTotals, overlay::OverlayMap};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
#[derive(Debug)]
pub(super) struct Projection<B> {
    pub(super) head:Option<ObjectId>,
    pub(super) tree:Option<ObjectId>,
    pub(super) overlay:OverlayMap,
    pub(super) depth:u64,
    pub(super) delta_bytes:u64,
    pub(super) totals:NodeTotals,
    pub(super) boundary:Option<B>,
}

impl<B> Projection<B> {
    fn matches(&self,id:ObjectId) -> (yes:bool)
        ensures yes == (self.head == Some(id)),
    { match self.head { Some(h) => h.same(&id),None => false } }
}

impl<B:Copy> Projection<B> {
    pub(super) fn snapshot(&self) -> (out:Self)
        ensures out == *self,
    {
        Self {head:self.head,tree:self.tree,overlay:self.overlay.snapshot(),depth:self.depth,
            delta_bytes:self.delta_bytes,totals:self.totals,boundary:self.boundary}
    }
}

impl<B:Copy> Clone for Projection<B> {
    fn clone(&self) -> Self {self.snapshot()}
}

pub(super) fn capture<P:Ord,B:Copy>(map:&BTreeMap<P,Projection<B>>,owner:&P) -> (out:Option<Projection<B>>)
    requires btree_map_inv(map),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
    ensures out == map@.get(*owner),
{
    Some(map.get(owner)?.snapshot())
}

pub(super) fn current<P:Ord,B:Copy>(map:&BTreeMap<P,Projection<B>>,owner:&P,id:ObjectId)
    -> (out:Option<Projection<B>>)
    requires btree_map_inv(map),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
    ensures out == if map@.contains_key(*owner) && map@[*owner].head == Some(id) {
        Some(map@[*owner])
    } else { None },
{
    let item = map.get(owner)?;
    if item.matches(id) {Some(item.snapshot())} else {None}
}

pub(super) open spec fn at_component<P,G,T,E,L,Z,D>(owner:&P,root:super::RootState,graph:L,empty:Z,resolve:D,g:G,t:T) -> bool
    where L:FnOnce(&P,super::RootState)->Result<(G,Option<ObjectId>),E>,
        Z:FnOnce()->T,D:FnOnce(&P,ObjectId)->Result<T,E>,
{
    (graph.ensures((owner,root),Ok((g,None))) && empty.ensures((),t)) ||
    exists|id:ObjectId| #[trigger] graph.ensures((owner,root),Ok((g,Some(id)))) &&
        #[trigger] resolve.ensures((owner,id),Ok(t))
}

/// Select the projection using the component in this owner's captured graph.
pub(super) fn read_root<P,G,T,E,L,Z,D>(owner:&P,root:super::RootState,graph:L,empty:Z,resolve:D)
    -> (out:Result<(G,T),E>)
    where L:FnOnce(&P,super::RootState)->Result<(G,Option<ObjectId>),E>,
        Z:FnOnce()->T,D:FnOnce(&P,ObjectId)->Result<T,E>,
    requires graph.requires((owner,root)),empty.requires(()),
        forall|id:ObjectId| #[trigger] resolve.requires((owner,id)),
    ensures out matches Ok((g,t)) ==> at_component(owner,root,graph,empty,resolve,g,t),
        out matches Err(e) ==> graph.ensures((owner,root),Err(e)) ||
            exists|g:G,id:ObjectId| #[trigger] graph.ensures((owner,root),Ok((g,Some(id)))) &&
                resolve.ensures((owner,id),Err(e)),
{
    let (g,component)=graph(owner,root)?;
    let t=match component {
        Some(id)=>{
            assert(graph.ensures((owner,root),Ok((g,Some(id)))));
            resolve(owner,id)?
        },
        None=>empty(),
    };
    assert(at_component(owner,root,graph,empty,resolve,g,t));
    Ok((g,t))
}

/// Prefer the already captured projection, then query the current owner memo,
/// then decode the addressed component. Only decoding produces a certificate.
pub(super) fn resolve<P,B,C,E,L,D>(owner:&P,id:ObjectId,captured:Option<Projection<B>>,lookup:L,decode:D)
    -> (out:Result<(Projection<B>,Option<C>),E>)
    where L:FnOnce(&P,ObjectId)->Option<Projection<B>>,D:FnOnce(&P,ObjectId)->Result<(Projection<B>,C),E>,
    requires lookup.requires((owner,id)),decode.requires((owner,id)),
        forall|m:Projection<B>| #[trigger] lookup.ensures((owner,id),Some(m)) ==> m.head == Some(id),
    ensures if captured matches Some(p) && p.head == Some(id) { out == Ok((captured.unwrap(),None)) }
        else { match out {
            Ok((p,None)) => p.head == Some(id) && lookup.ensures((owner,id),Some(p)),
            Ok((p,Some(c))) => lookup.ensures((owner,id),None) && decode.ensures((owner,id),Ok((p,c))),
            Err(e) => lookup.ensures((owner,id),None) && decode.ensures((owner,id),Err(e)),
        } },
{
    match captured { Some(p) if p.matches(id) => return Ok((p,None)),_ => {} }
    if let Some(p) = lookup(owner,id) { return Ok((p,None)); }
    let (p,c) = decode(owner,id)?;
    Ok((p,Some(c)))
}
}
