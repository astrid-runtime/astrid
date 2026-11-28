//! Select the staged declarations reachable by owning references from the commit.
use super::{ObjectId, ObjectRecord, ObjectReference};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(crate) open spec fn targets(refs:Seq<ObjectReference>) -> Set<ObjectId>
    decreases refs.len(),
{
    if refs.len()==0 {Set::empty()} else {
        let rest=targets(refs.drop_last());
        let edge=refs.last().fields();
        if edge.2 is Owns {rest.insert(edge.1)} else {rest}
    }
}

spec fn pending_ids(s:Seq<ObjectId>) -> Set<ObjectId>
    decreases s.len(),
{
    if s.len()==0 {Set::empty()} else {pending_ids(s.drop_last()).insert(s.last())}
}

fn schedule(stack:&mut Vec<ObjectId>,refs:&[ObjectReference])
    ensures pending_ids(final(stack)@)==pending_ids(old(stack)@).union(targets(refs@)),
{
    let mut i=0usize;
    while i<refs.len()
        invariant i<=refs.len(),pending_ids(stack@)==pending_ids(old(stack)@).union(targets(refs@.take(i as int))),
        decreases refs.len()-i,
    {
        let ghost before=stack@;
        if let Some(child)=refs[i].owning_target() {
            assert(refs@[i as int].fields().2 is Owns && child==refs@[i as int].fields().1);
            stack.push(child);
            assert(stack@.drop_last() =~= before);
            assert(pending_ids(stack@)==pending_ids(before).insert(child));
        }
        proof {
            let prefix=refs@.take(i as int+1);
            assert(prefix.drop_last() =~= refs@.take(i as int));
            assert(prefix.last()==refs@[i as int]);
            assert(pending_ids(stack@) =~= pending_ids(old(stack)@).union(targets(prefix)));
        }
        i=i.saturating_add(1);
    }
    assert(refs@.take(i as int) =~= refs@);
}

pub(crate) open spec fn closed(source:Map<ObjectId,ObjectRecord>,root:ObjectId,ids:Set<ObjectId>) -> bool {
    &&& source.contains_key(root) ==> ids.contains(root)
    &&& forall|parent:ObjectId| ids.contains(parent) && source.contains_key(parent) ==>
        (#[trigger] targets(source[parent].contents().3)).intersect(source.dom()).subset_of(ids)
}

pub(crate) open spec fn contents(rows:Seq<(ObjectId,ObjectRecord)>,records:Map<ObjectId,ObjectRecord>) -> bool {
    forall|row:(ObjectId,ObjectRecord)| #[trigger] rows.to_set().contains(row) <==> records.contains_key(row.0) && records[row.0]==row.1
}

pub(crate) open spec fn ordered(rows:Seq<(ObjectId,ObjectRecord)>) -> bool {
    forall|i:int,j:int| #![trigger rows[i],rows[j]] 0<=i<j<rows.len() ==>
        vstd::std_specs::cmp::OrdSpec::cmp_spec(&rows[i].0,&rows[j].0)!=core::cmp::Ordering::Greater
}

pub(crate) open spec fn exact_rows(source:Map<ObjectId,ObjectRecord>,root:ObjectId,
    kept:Map<ObjectId,ObjectRecord>,rows:Seq<(ObjectId,ObjectRecord)>) -> bool {
    &&& kept.submap_of(source)
    &&& closed(source,root,kept.dom())
    &&& forall|ids:Set<ObjectId>| #[trigger] closed(source,root,ids) ==> kept.dom().subset_of(ids)
    &&& contents(rows,kept)
    &&& rows.len()==kept.len()
    &&& ordered(rows)
}

proof fn permutation_members<T>(before:Seq<T>,after:Seq<T>)
    requires before.to_multiset()==after.to_multiset(),
    ensures before.to_set()==after.to_set(),
{
    before.to_multiset_ensures(); after.to_multiset_ensures();
    before.to_set_ensures(); after.to_set_ensures();
    assert(before.to_set() =~= after.to_set()) by {
        assert forall|r:T| before.to_set().contains(r) <==> #[trigger] after.to_set().contains(r) by {
            vstd::seq_lib::to_multiset_contains(before,r);
            vstd::seq_lib::to_multiset_contains(after,r);
        }
    }
}

#[verifier::loop_isolation(false)]
pub(crate) fn select(staged:BTreeMap<ObjectId,ObjectRecord>,root:ObjectId) -> (rows:Vec<(ObjectId,ObjectRecord)>)
    requires btree_map_inv(&staged),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures exists|kept:Map<ObjectId,ObjectRecord>| #[trigger] exact_rows(staged@,root,kept,rows@),
{
    let ghost source=staged@;
    let mut remaining=staged;
    let ghost mut kept:Map<ObjectId,ObjectRecord>=Map::empty();
    let mut rows:Vec<(ObjectId,ObjectRecord)>=Vec::new();
    assert(contents(rows@,kept));
    let key=|row:&(ObjectId,ObjectRecord)| -> (k:ObjectId) ensures k==row.0 { row.0 };
    let mut stack=vec![root];
    assert(stack@.drop_last() =~= Seq::empty());
    assert(pending_ids(stack@) =~= set![root]) by { reveal_with_fuel(pending_ids,2); }
    assert forall|ids:Set<ObjectId>| #[trigger] closed(source,root,ids) implies
        kept.dom().union(pending_ids(stack@).intersect(source.dom())).subset_of(ids) by {
        if source.contains_key(root) {assert(ids.contains(root));}
    }
    #[expect(clippy::manual_while_let_some, reason = "the proof snapshots the pending set before popping the next object")]
    while !stack.is_empty()
        invariant
            btree_map_inv(&remaining),rows.len()==kept.len(),contents(rows@,kept),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            forall|r:(ObjectId,ObjectRecord)| rows@.to_set().contains(r) ==> #[trigger] key.ensures((&r,),r.0),
            forall|k:ObjectId| #[trigger] remaining@.contains_key(k) ==> source.contains_key(k) && remaining@[k]==source[k],
            kept.submap_of(source),remaining@.dom().disjoint(kept.dom()),
            source.dom()==remaining@.dom().union(kept.dom()),
            source.contains_key(root) ==> kept.contains_key(root) || pending_ids(stack@).contains(root),
            forall|p:ObjectId| kept.contains_key(p) ==> (#[trigger] targets(source[p].contents().3)).intersect(source.dom()).subset_of(kept.dom().union(pending_ids(stack@))),
            forall|ids:Set<ObjectId>| #[trigger] closed(source,root,ids) ==> kept.dom().union(pending_ids(stack@).intersect(source.dom())).subset_of(ids),
        decreases remaining.len(),stack.len(),
    {
        let ghost from=stack@;
        let ghost pending=pending_ids(from);
        let ghost prior=kept.dom();
        let id=stack.pop().expect("nonempty staged-object worklist");
        assert(stack@ =~= from.drop_last());
        assert(pending =~= pending_ids(stack@).insert(id));
        let ghost unvisited=remaining@;
        assert(unvisited.contains_key(id) ==> unvisited[id]==source[id]);
        if let Some(record)=remaining.remove(&id) {
            assert(unvisited.get(id)==Some(record));
            assert(unvisited.contains_key(id));
            assert(record==unvisited[id]);
            let ghost tail=pending_ids(stack@);
            let references=record.references();
            assert(references@==source[id].contents().3);
            schedule(&mut stack,references);
            let ghost before=rows@;
            let row=(id,record);
            let retained_id=key(&row);
            assert(key.ensures((&row,),id));
            rows.push((retained_id,row.1));
            proof {
                assert(!kept.contains_key(id));
                kept=kept.insert(id,record);
                assert(rows@.to_set() =~= before.to_set().insert((id,record))) by {
                    before.lemma_push_to_set_commute((id,record));
                }
                assert(contents(rows@,kept));
            };
            proof {
                assert(record==source[id]);
                assert(targets(source[id].contents().3).subset_of(pending_ids(stack@)));
                assert(kept.dom() =~= prior.insert(id));
                assert(source.dom() =~= remaining@.dom().union(kept.dom()));
                assert forall|ids:Set<ObjectId>| #[trigger] closed(source,root,ids) implies
                    kept.dom().union(pending_ids(stack@).intersect(source.dom())).subset_of(ids) by {
                    assert(prior.union(pending.intersect(source.dom())).subset_of(ids));
                    assert(ids.contains(id));
                    assert(pending_ids(stack@)==tail.union(targets(source[id].contents().3)));
                    assert(targets(source[id].contents().3).intersect(source.dom()).subset_of(ids));
                }
            };
        } else {
            assert(kept.dom()==prior);
            assert(!source.contains_key(id) || kept.contains_key(id));
        }
        proof {
            assert(prior.union(pending.intersect(source.dom())).subset_of(kept.dom().union(pending_ids(stack@))));
            assert forall|p:ObjectId| kept.contains_key(p) implies (#[trigger] targets(source[p].contents().3)).intersect(source.dom()).subset_of(kept.dom().union(pending_ids(stack@))) by {
                if prior.contains(p) {
                    assert(targets(source[p].contents().3).intersect(source.dom()).subset_of(prior.union(pending)));
                } else {
                    assert(p==id && targets(source[p].contents().3).subset_of(pending_ids(stack@)));
                }
            }
        };
    }
    assert(pending_ids(stack@) =~= Set::empty());
    let ghost before=rows@;
    proof { reveal(vstd::laws_cmp::obeys_cmp_ord); }
    rows.as_mut_slice().sort_unstable_by_key(key);
    proof {
        permutation_members(before,rows@);
        assert forall|i:int,j:int| #![trigger rows@[i],rows@[j]] 0<=i<j<rows.len() implies
            vstd::std_specs::cmp::OrdSpec::cmp_spec(&rows@[i].0,&rows@[j].0)!=core::cmp::Ordering::Greater by {
            assert(vstd::std_specs::slice::key_le(key,rows@[i],rows@[j]));
            assert(before.to_set().contains(rows@[i]) && before.to_set().contains(rows@[j]));
            assert(key.ensures((&rows@[i],),rows@[i].0));
            assert(key.ensures((&rows@[j],),rows@[j].0));
        }
        assert(exact_rows(source,root,kept,rows@));
    };
    rows
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_model::{
        ObjectClass, ObjectFormatVersion, ObjectKind, ReferenceKind, ReferenceLabel,
    };

    fn record(edges: &[(ReferenceKind, u8)]) -> ObjectRecord {
        let references = edges
            .iter()
            .zip(0u8..)
            .map(|(&(kind, target), label)| {
                ObjectReference::new(
                    ReferenceLabel::new(vec![label]),
                    ObjectId::new([target; 32]),
                    kind,
                )
            })
            .collect();
        ObjectRecord::new(
            ObjectKind::NamespaceMap,
            ObjectFormatVersion::new(1).unwrap(),
            Vec::new(),
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap()
    }

    #[test]
    fn pruning_follows_only_staged_owning_edges() {
        use ReferenceKind::{Derived, Evidence, Lineage, Owns};
        let root = ObjectId::new([7; 32]);
        let child = ObjectId::new([2; 32]);
        let mut staged = BTreeMap::new();
        staged.insert(
            root,
            record(&[
                (Owns, 2),
                (Owns, 2),
                (Owns, 8),
                (Lineage, 3),
                (Evidence, 4),
                (Derived, 5),
            ]),
        );
        staged.insert(child, record(&[(Owns, 7)]));
        for n in 3..=6 {
            staged.insert(ObjectId::new([n; 32]), record(&[(Owns, 6)]));
        }
        assert!(select(staged.clone(), ObjectId::new([8; 32])).is_empty());
        let expected = vec![
            (child, staged[&child].clone()),
            (root, staged[&root].clone()),
        ];
        assert_eq!(select(staged, root), expected);
    }
}
