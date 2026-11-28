//! Check every restored journal root against one immutable preloaded object table.
#[cfg(verus_keep_ghost)]
use super::closure_walk::Source;
use super::{
    ObjectId, ObjectRecord, RootState, closure_load as load, closure_walk as walk,
    recovered_closure as closure,
};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{
        btree::{btree_map_inv, btree_set_inv},
        cmp::OrdSpec,
        iter::IteratorSpec,
    },
};

verus! {
pub(super) enum Failure {
    Walk(u64,walk::Failure<ObjectId,ObjectId>),
    Commit(u64,ObjectId,load::CommitError),
}

pub(super) open spec fn admitted(table:&BTreeMap<ObjectId,ObjectRecord>,root:ObjectId,nodes:Set<ObjectId>) -> bool {
    let graph = load::Preload(table).edges();
    &&& table@.contains_key(root) && table@[root].contents().0 is Commit
    &&& nodes.subset_of(table@.dom())
    &&& walk::closed(root,Set::empty(),graph,nodes)
    &&& forall|scope:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),graph,scope) ==> nodes.subset_of(scope)
    &&& exists|rank:Map<ObjectId,nat>| rank.dom() == nodes && #[trigger] walk::ranked(graph,Set::empty(),rank)
}

pub(super) open spec fn refused(table:&BTreeMap<ObjectId,ObjectRecord>,root:ObjectId,at:u64,e:Failure) -> bool {
    let graph = load::Preload(table).edges();
    match e {
        Failure::Walk(pos,walk::Failure::Cycle(id)) => at == pos && walk::reaches(graph,Set::empty(),id,id) &&
            forall|scope:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),graph,scope) ==> scope.contains(id),
        Failure::Walk(pos,walk::Failure::Source(id,missing)) => at == pos && missing == id && !table@.contains_key(id) &&
            forall|scope:Set<ObjectId>| #[trigger] walk::closed(root,Set::empty(),graph,scope) ==> scope.contains(id),
        Failure::Commit(pos,id,load::CommitError::WrongKind(k)) => at == pos && id == root &&
            table@.contains_key(root) && table@[root].contents().0 == k && !(k is Commit),
        _ => false,
    }
}

type Rows<'a> = Vec<(ObjectId,&'a ObjectRecord)>;

fn read(table:&BTreeMap<ObjectId,ObjectRecord>,root:ObjectId,at:u64) -> (out:Result<Rows<'_>,Failure>)
    requires load::Preload(table).valid(),
    ensures match out {
        Ok(rows) => admitted(table,root,closure::ids(rows@)),
        Err(e) => refused(table,root,at,e),
    },
{
    let rows = match load::materialize(table,root) {Ok(r)=>r,Err(f)=>return Err(Failure::Walk(at,f))};
    let ghost nodes = load::row_ids(rows@).to_set();
    assert(rows@.map(|i:int,row:(ObjectId,&ObjectRecord)| row.0) =~= load::row_ids(rows@));
    assert(closure::ids(rows@) =~= nodes);
    assert forall|k:ObjectId| nodes.contains(k) implies #[trigger] table@.contains_key(k) by {
        let i = load::row_ids(rows@).index_of(k);
        assert(rows@[i].0 == k);
    }
    assert(nodes.subset_of(table@.dom()));
    assert(nodes.contains(root));
    let ghost i = load::row_ids(rows@).index_of(root);
    assert(rows@[i].0 == root);
    match load::commit_kind(&rows,root) {
        Ok(()) => {
            let ghost j = choose|j:int| 0 <= j < rows.len() && #[trigger] rows@[j].0 == root && rows@[j].1.contents().0 is Commit;
            assert(table@[root].contents().0 is Commit);
            Ok(rows)
        },
        Err(load::CommitError::WrongKind(k)) => {
            let ghost j = choose|j:int| 0 <= j < rows.len() && #[trigger] rows@[j].0 == root && rows@[j].1.contents().0 == k;
            assert(table@[root].contents().0 == k);
            Err(Failure::Commit(at,root,load::CommitError::WrongKind(k)))
        },
        Err(load::CommitError::Missing) => {assert(false);Err(Failure::Commit(at,root,load::CommitError::Missing))}
    }
}

/// Select exactly the commits named by the recovered principal table.
pub(super) fn commits<P:Ord>(history:&BTreeMap<P,(RootState,u64)>) -> (ids:BTreeSet<ObjectId>)
    requires btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures btree_set_inv(&ids),
        forall|p:P| #[trigger] history@.contains_key(p) ==> ids@.contains(history@[p].0.commit),
        forall|k:ObjectId| #[trigger] ids@.contains(k) ==> exists|p:P| history@.contains_key(p) && #[trigger] history@[p].0.commit == k,
{
    let mut ids = BTreeSet::new();
    let mut it = history.iter();
    let ghost all = it.remaining();
    let ghost mut n:int = 0;
    loop
        invariant all.len() == history.len(),0 <= n <= all.len(),it.remaining() == all.skip(n),all.unref().to_set() == history@.kv_pairs(),
            btree_set_inv(&ids),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            forall|j:int| 0 <= j < n ==> ids@.contains(#[trigger] all[j].1.0.commit),
            forall|k:ObjectId| #[trigger] ids@.contains(k) ==> exists|p:P| history@.contains_key(p) && #[trigger] history@[p].0.commit == k,
        decreases history.len()-n,
    {
        let Some((_p,entry)) = it.next() else {
            assert(n==all.len());
            assert forall|p:P| #[trigger] history@.contains_key(p) implies ids@.contains(history@[p].0.commit) by {
                let pair = (p,history@[p]);
                assert(all.unref().to_set().contains(pair));
                let i = all.unref().index_of(pair);
                assert(all.unref()[i]==pair && *all[i].1==pair.1);
            }
            return ids;
        };
        assert(all.unref()[n]==(*_p,*entry));
        assert(history@.kv_pairs().contains((*_p,*entry)));
        assert(history@.contains_key(*_p) && history@[*_p]==*entry);
        ids.insert(entry.0.commit);
        proof { n=n+1; };
    }
}

/// Compare every principal and its pair of values before exposing a built map.
pub(super) fn matching<P:Ord,A,B,F:Fn(&A,&B)->bool>(history:&BTreeMap<P,A>,roots:&BTreeMap<P,B>,same:F) -> (ok:bool)
    requires btree_map_inv(history),btree_map_inv(roots),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|x:&A,y:&B| #[trigger] same.requires((x,y)),
    ensures if ok {
        roots@.dom() == history@.dom() && forall|p:P| #[trigger] history@.contains_key(p) ==> same.ensures((&history@[p],&roots@[p]),true)
    } else {
        roots@.dom() != history@.dom() || exists|p:P| history@.contains_key(p) && roots@.contains_key(p) &&
            #[trigger] same.ensures((&history@[p],&roots@[p]),false)
    },
{
    if history.len() != roots.len() {return false;}
    let mut input = history.iter();
    let mut output = roots.iter();
    let ghost src = input.remaining();
    let ghost dst = output.remaining();
    let ghost a = src.map_values(|kv:(&P,&A)| *kv.0);
    let ghost b = dst.map_values(|kv:(&P,&B)| *kv.0);
    let ghost mut n:int = 0;
    loop
        invariant 0 <= n <= src.len(),src.len() == history.len(),src.len()==dst.len(),
            input.remaining()==src.skip(n), output.remaining()==dst.skip(n),
            src.unref().to_set()==history@.kv_pairs(),dst.unref().to_set()==roots@.kv_pairs(),
            a == src.map_values(|kv:(&P,&A)| *kv.0),
            b == dst.map_values(|kv:(&P,&B)| *kv.0),
            vstd::std_specs::btree::increasing_seq(a),vstd::std_specs::btree::increasing_seq(b),
            obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            forall|x:&A,y:&B| #[trigger] same.requires((x,y)),
            forall|j:int| 0 <= j < n ==> #[trigger] src[j].0 == dst[j].0 && same.ensures((src[j].1,dst[j].1),true),
        decreases history.len()-n,
    {
        let Some((principal,entry)) = input.next() else {
            assert(n==src.len());
            assert forall|p:P| #[trigger] history@.contains_key(p) implies roots@.contains_key(p) && same.ensures((&history@[p],&roots@[p]),true) by {
                let pair = (p,history@[p]);
                assert(src.unref().to_set().contains(pair));
                let j = src.unref().index_of(pair);
                assert(src.unref()[j]==pair && *dst[j].0==p);
                assert(roots@.kv_pairs().contains(dst.unref()[j]));
            }
            assert forall|p:P| #[trigger] roots@.contains_key(p) implies history@.contains_key(p) by {
                let pair = (p,roots@[p]);
                assert(dst.unref().to_set().contains(pair));
                let j = dst.unref().index_of(pair);
                assert(dst.unref()[j]==pair && *src[j].0==p);
                assert(history@.kv_pairs().contains(src.unref()[j]));
            }
            assert(roots@.dom() =~= history@.dom());
            return true;
        };
        let Some((owner,root)) = output.next() else {return false;};
        proof {
            reveal(vstd::laws_cmp::obeys_cmp_ord);
            assert(src.unref()[n]==(*principal,*entry) && dst.unref()[n]==(*owner,*root));
            assert(history@.kv_pairs().contains((*principal,*entry)) && roots@.kv_pairs().contains((*owner,*root)));
            if roots@.dom() == history@.dom() {
                assert(a[n]==*principal && b[n]==*owner);
                if *principal != *owner {
                    let x = (*principal,roots@[*principal]);
                    let y = (*owner,history@[*owner]);
                    assert(dst.unref().to_set().contains(x) && src.unref().to_set().contains(y));
                    let i = dst.unref().index_of(x);
                    let j = src.unref().index_of(y);
                    assert(b[i]==a[n] && a[j]==b[n]);
                    reveal(vstd::laws_cmp::obeys_partial_cmp_spec_properties);
                    if i < n { assert(a[i]==b[i] && a[i].cmp_spec(&a[n]) is Less); }
                    else if j < n { assert(a[j]==b[j] && b[j].cmp_spec(&b[n]) is Less); }
                    else {
                        assert(i>n && j>n);
                        assert(b[n].cmp_spec(&b[i]) is Less && a[n].cmp_spec(&a[j]) is Less);
                    }
                    assert(false);
                }
                assert(*principal == *owner);
            }
        }
        match P::cmp(principal,owner) {std::cmp::Ordering::Equal => {}, _ => return false}
        assert(principal.cmp_spec(owner) is Equal);
        if !same(entry,root) {
            assert(history@.contains_key(*principal) && roots@.contains_key(*principal));
            assert(same.ensures((&history@[*principal],&roots@[*principal]),false));
            return false;
        }
        assert(*owner == *principal);
        assert(src[n] == (principal,entry) && dst[n] == (owner,root));
        assert forall|j:int| 0 <= j < n+1 implies #[trigger] src[j].0 == dst[j].0 && same.ensures((src[j].1,dst[j].1),true) by {
            if j < n { assert(src[j].0 == dst[j].0 && same.ensures((src[j].1,dst[j].1),true)); }
            else { assert(j==n && same.ensures((entry,root),true)); }
        }
        proof { n=n+1; };
    }
}

/// Check fresh live slots while the candidate still belongs exclusively to its builder.
pub(super) fn install<P:Ord,S,T,F:Fn(&S)->RootState+Copy,W:FnOnce(BTreeMap<P,S>)->T>(roots:&BTreeMap<P,RootState>,candidate:BTreeMap<P,S>,read:F,write:W)
    -> (out:Option<T>)
    requires btree_map_inv(roots),btree_map_inv(&candidate),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|s:&S| #[trigger] read.requires((s,)),
        candidate@.dom() == roots@.dom() && (forall|p:P| #[trigger] roots@.contains_key(p) ==> read.ensures((&candidate@[p],),roots@[p])) ==> write.requires((candidate,)),
    ensures match out {
        Some(value) => write.ensures((candidate,),value) && candidate@.dom() == roots@.dom() &&
            forall|p:P| #[trigger] roots@.contains_key(p) ==> read.ensures((&candidate@[p],),roots@[p]),
        None => candidate@.dom() != roots@.dom() || exists|p:P,r:RootState| roots@.contains_key(p) && candidate@.contains_key(p) &&
            #[trigger] read.ensures((&candidate@[p],),r) && r != roots@[p],
    },
{
    let same = |root:&RootState,slot:&S| -> (ok:bool)
        ensures if ok {read.ensures((slot,),*root)} else {exists|r:RootState| #[trigger] read.ensures((slot,),r) && r!=*root},
    {
        let observed = read(slot);
        root.same(observed)
    };
    if matching(roots,&candidate,same) {Some(write(candidate))} else {None}
}

/// Certify the bulk-built root map against the journal in principal order.
/// No property of the key copier or collection builder is needed on success.
pub(super) fn project<P:Ord>(history:&BTreeMap<P,(RootState,u64)>,roots:BTreeMap<P,RootState>) -> (out:Option<BTreeMap<P,RootState>>)
    requires btree_map_inv(history),btree_map_inv(&roots),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
    ensures match out {
        Some(map) => map == roots && map@ == history@.map_values(|entry:(RootState,u64)| entry.0),
        None => roots@ != history@.map_values(|entry:(RootState,u64)| entry.0),
    },
{
    let same = |entry:&(RootState,u64),root:&RootState| -> (ok:bool)
        ensures ok == (entry.0 == *root), {entry.0.same(*root)};
    if matching(history,&roots,same) {
        assert(roots@ =~= history@.map_values(|entry:(RootState,u64)| entry.0));
        Some(roots)
    } else {
        None
    }
}

pub(super) fn validate<P:Ord>(history:&BTreeMap<P,(RootState,u64)>,table:&BTreeMap<ObjectId,ObjectRecord>)
    -> (out:Result<BTreeSet<ObjectId>,Failure>)
    requires btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),load::Preload(table).valid(),
    ensures match out {
        Ok(known) => btree_set_inv(&known) && (
            forall|p:P| #[trigger] history@.contains_key(p) ==> exists|s:Set<ObjectId>|
                #[trigger] admitted(table,history@[p].0.commit,s) && s.subset_of(known@)
        ) && (forall|k:ObjectId| #[trigger] known@.contains(k) ==> exists|p:P,s:Set<ObjectId>|
            history@.contains_key(p) && #[trigger] admitted(table,history@[p].0.commit,s) && s.contains(k)),
        Err(e) => exists|p:P| history@.contains_key(p) && #[trigger] refused(table,history@[p].0.commit,history@[p].1,e),
    },
{
    let load = |k:ObjectId,a:u64| -> (v:Result<Rows,Failure>)
        ensures match v {Ok(rows)=>admitted(table,k,closure::ids(rows@)),Err(e)=>refused(table,k,a,e)},
        {read(table,k,a)};
    let checked = |_:&Rows,_:ObjectId,_:u64| -> (r:Result<(),Failure>) ensures r == Ok(()), {Ok(())};
    let known = match closure::check_all(history,load,checked) {
        Ok(v)=>v,
        Err(e)=>{
            let ghost p = choose|p:P| history@.contains_key(p) && ({
                let (r,at) = history@[p];
                load.ensures((r.commit,at),Err(e)) || exists|rows:Rows| #[trigger] load.ensures((r.commit,at),Ok(rows)) &&
                    checked.ensures((&rows,r.commit,at),Err(e))
            });
            assert(refused(table,history@[p].0.commit,history@[p].1,e));
            return Err(e);
        }
    };
    proof {
        let (entries,sets) = choose|es:Seq<(P,(RootState,u64))>,rs:Seq<Rows>|
            es.to_set() == history@.kv_pairs() && es.len() == history.len() &&
                #[trigger] closure::complete(es,rs,known@,load,checked);
        assert forall|p:P| #[trigger] history@.contains_key(p) implies exists|s:Set<ObjectId>|
            #[trigger] admitted(table,history@[p].0.commit,s) && s.subset_of(known@) by {
            let pair = (p,history@[p]);
            assert(entries.to_set().contains(pair));
            let i = entries.index_of(pair);
            assert(closure::accepted(entries[i].1,sets[i],load,checked));
            let nodes = closure::ids(sets[i]@);
            assert(admitted(table,history@[p].0.commit,nodes));
            assert forall|k:ObjectId| #[trigger] nodes.contains(k) implies known@.contains(k) by {assert(closure::recorded(sets,k));}
            assert(nodes.subset_of(known@));
        }
        assert forall|k:ObjectId| #[trigger] known@.contains(k) implies exists|p:P,s:Set<ObjectId>|
            history@.contains_key(p) && #[trigger] admitted(table,history@[p].0.commit,s) && s.contains(k) by {
            assert(closure::recorded(sets,k));
            let i = choose|i:int| 0 <= i < sets.len() && #[trigger] closure::ids(sets[i]@).contains(k);
            let (p,entry) = entries[i];
            assert(entries.to_set().contains((p,entry)));
            assert(history@[p] == entry);
            assert(closure::accepted(entry,sets[i],load,checked));
            assert(admitted(table,entry.0.commit,closure::ids(sets[i]@)));
        }
    }
    Ok(known)
}
}
