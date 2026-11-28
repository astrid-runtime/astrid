//! Canonical record fields determine page classification, retained charge, and the returned handle.
use crate::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    checkpoint_page::{Handle, Node}, checkpoint_record::{self, EnvelopeError, PageKind, SizeError}};
use vstd::prelude::*;

verus! {
fn classify(record: &ObjectRecord, version: ObjectFormatVersion) -> (out: Result<PageKind, EnvelopeError>)
    ensures ({
        let (kind, schema, _, _, logical, class) = record.contents();
        if logical != 0 || class != ObjectClass::Metadata || schema != version.number() {
            out == Err(EnvelopeError::Header)
        } else {
            match kind {
                ObjectKind::KvLeaf => out == Ok(PageKind::Leaf),
                ObjectKind::KvBranch => out == Ok(PageKind::Branch),
                _ => out == Err(EnvelopeError::Kind),
            }
        }
    }),
{ checkpoint_record::classify(record, version) }

fn single_edge<T,V>(record: &ObjectRecord, id: ObjectId, page: Node<ObjectId,T,V>)
    -> (out: Result<Handle<ObjectId,T,V>, SizeError>)
    requires record.contents().3.len() == 1,
    ensures ({
        let (_, _, bytes, refs, _, _) = record.contents();
        let cost = 29 + bytes.len() + 41 + refs[0].fields().0.len();
        let split = match page {
            Node::Leaf(l) => l.entries.len() >= 2,
            Node::Branch(b) => b.children.len() >= 4,
        };
        if cost > u64::MAX { out == Err(SizeError::Overflow) }
        else if cost > 4096 && split { out == Err(SizeError::Oversize) }
        else { out matches Ok(h) && h.object == id && h.node == page }
    }),
{
    proof { reveal_with_fuel(ObjectRecord::reference_charge, 2); }
    checkpoint_record::finish(id, record, page)
}
fn read<E,F:Fn(&[u8])->Result<(),E>+Copy>(id:ObjectId, record:&ObjectRecord, v:ObjectFormatVersion, validate:F)
    -> (out:Result<Handle<ObjectId,crate::checkpoint_totals::NodeTotals,crate::checkpoint_value::ValueSlot>,checkpoint_record::ReadError<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures ({
        let f = record.contents();
        if f.1 != v.number() || f.4 != 0 || f.5 != ObjectClass::Metadata {
            out matches Err(checkpoint_record::ReadError::Envelope(EnvelopeError::Header))
        } else if !(f.0 is KvLeaf) && !(f.0 is KvBranch) {
            out matches Err(checkpoint_record::ReadError::Envelope(EnvelopeError::Kind))
        } else {
            out matches Ok(h) ==> h.object == id && checkpoint_record::parsed(record,h.node,validate) &&
                record.retained_cost() <= u64::MAX &&
                (record.retained_cost() <= 4096 || match h.node {
                    Node::Leaf(l) => l.entries.len() <= 1, Node::Branch(b) => b.children.len() <= 3,
                })
        }
    }),
{ checkpoint_record::read(id,record,v,validate) }

// The production range reader must discharge the walker's rank precondition from
// the requested record even when its source is adversarial or unreadable.
fn range_reader<E,F:Fn(&[u8])->Result<(),E>+Copy,L:FnOnce(ObjectId)->Result<ObjectRecord,E>>(
    page:&crate::checkpoint_range::Page<ObjectId,crate::checkpoint_totals::NodeTotals>,
    v:ObjectFormatVersion,load:L,validate:F,
) -> (out:Result<crate::checkpoint_walk::Contents<ObjectId,crate::checkpoint_totals::NodeTotals,crate::checkpoint_value::ValueSlot>,
    checkpoint_record::ScheduledError<E>>)
    requires load.requires((crate::checkpoint_page::object(*page),)),
        forall|k:&[u8]| #[trigger] validate.requires((k,)),
        vstd::laws_eq::obeys_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<crate::checkpoint_totals::NodeTotals>(),
    ensures out matches Ok(crate::checkpoint_walk::Contents::Branch(level,children)) ==> level > 0 &&
        (*page matches crate::checkpoint_range::Page::Child(child) ==> child.level == level) &&
        forall|i:int| 0 <= i < children.len() ==> (#[trigger] children@[i]).level as nat + 1 == level,
        out matches Ok(body) ==> exists|record:ObjectRecord| #[trigger] load.ensures((crate::checkpoint_page::object(*page),),Ok(record)) &&
            record.contents().1 == v.number() && exists|node:Node<ObjectId,crate::checkpoint_totals::NodeTotals,crate::checkpoint_value::ValueSlot>|
                #[trigger] checkpoint_record::parsed(&record,node,validate) && checkpoint_record::ordered(node) && node.contents() == body &&
                crate::checkpoint_page::agrees(*page,Handle {object:crate::checkpoint_page::object(*page),node}),
        out matches Err(checkpoint_record::ScheduledError::Record(e)) ==> exists|record:ObjectRecord|
            #[trigger] load.ensures((crate::checkpoint_page::object(*page),),Ok(record)) &&
            checkpoint_record::refusal(&record,validate,e) &&
            (e matches checkpoint_record::ReadError::Envelope(EnvelopeError::Kind) ==> record.contents().1 == v.number() &&
                record.contents().4 == 0 && record.contents().5 == ObjectClass::Metadata &&
                !(record.contents().0 is KvLeaf) && !(record.contents().0 is KvBranch)),
        out matches Err(checkpoint_record::ScheduledError::Summary) ==> exists|record:ObjectRecord|
            #[trigger] load.ensures((crate::checkpoint_page::object(*page),),Ok(record)) &&
            exists|node:Node<ObjectId,crate::checkpoint_totals::NodeTotals,crate::checkpoint_value::ValueSlot>|
                #[trigger] checkpoint_record::parsed(&record,node,validate) && checkpoint_record::ordered(node) &&
                checkpoint_record::descending(node) && record.contents().1 == v.number() &&
                !crate::checkpoint_page::agrees(*page,Handle {object:crate::checkpoint_page::object(*page),node}),
        out matches Err(checkpoint_record::ScheduledError::Source(e)) ==> load.ensures((crate::checkpoint_page::object(*page),),Err(e)),
{ checkpoint_record::load_scheduled(page,v,load,validate) }

// A denied owner and an absent ID take distinct paths; a staged body at the
// scheduled address wins even when the backing reader would deny this owner.
fn owner_selection<F:Fn(&[u8])->Result<(),u8>+Copy>(
    staged:&std::collections::BTreeMap<ObjectId,ObjectRecord>,owner:u64,allowed:u64,
    page:&crate::checkpoint_range::Page<ObjectId,crate::checkpoint_totals::NodeTotals>,
    version:ObjectFormatVersion,address:ObjectId,record:ObjectRecord,validate:F,
) -> (out:Result<crate::checkpoint_walk::Contents<ObjectId,crate::checkpoint_totals::NodeTotals,crate::checkpoint_value::ValueSlot>,
        checkpoint_record::ScheduledError<u8>>)
    requires vstd::std_specs::btree::btree_map_inv(staged),
        vstd::laws_cmp::obeys_cmp::<ObjectId>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<ObjectId>(),
        forall|k:&[u8]| #[trigger] validate.requires((k,)),
        vstd::laws_eq::obeys_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<crate::checkpoint_totals::NodeTotals>(),
    ensures ({
        let id = crate::checkpoint_page::object(*page);
        if staged@.contains_key(id) { checkpoint_record::scheduled_result(page,&staged@[id],version,validate,out) }
        else if owner != allowed { out == Err(checkpoint_record::ScheduledError::Source(1u8)) }
        else if id != address { out == Err(checkpoint_record::ScheduledError::Source(2u8)) }
        else { checkpoint_record::scheduled_result(page,&record,version,validate,out) }
    }),
{
    let engine = |p:&u64,k:ObjectId| -> (r:Result<Option<ObjectRecord>,u8>)
        ensures r == (if *p != allowed {Err(1u8)} else if k == address {Ok(Some(record))} else {Ok(None)}),
    {
        if *p != allowed {Err(1u8)} else if k.same(&address) {Ok(Some(record))} else {Ok(None)}
    };
    checkpoint_record::owner_page(staged,&owner,page,version,engine,
        |_id:ObjectId| -> (e:u8) ensures e == 2u8, {2u8},validate)
}

// The two maps may differ at every owner, including the selected owner. The
// cold result carries the exact projection and certificate for that decode.
fn projection_for_root(
    before:&std::collections::BTreeMap<u64,crate::memo_projection::Projection<u64>>,
    now:&std::collections::BTreeMap<u64,crate::memo_projection::Projection<u64>>,
    owner:u64,head:ObjectId,cold:Result<(crate::memo_projection::Projection<u64>,u32),u8>,
) -> (out:Result<(crate::memo_projection::Projection<u64>,Option<u32>),u8>)
    requires vstd::std_specs::btree::btree_map_inv(before),vstd::std_specs::btree::btree_map_inv(now),
    ensures if before@.contains_key(owner) && before@[owner].head==Some(head) {out == Ok((before@[owner],None))}
        else if now@.contains_key(owner) && now@[owner].head==Some(head) {out == Ok((now@[owner],None))}
        else {match cold {Ok((p,c)) => out==Ok((p,Some(c))),Err(e) => out==Err(e)}},
{
    assert(vstd::laws_cmp::obeys_cmp::<u64>());
    assert(vstd::laws_cmp::obeys_cmp_concrete_eq::<u64>());
    let captured = crate::memo_projection::capture(before,&owner);
    let lookup = |p:&u64,id:ObjectId| -> (r:Option<crate::memo_projection::Projection<u64>>)
        ensures r == if now@.contains_key(*p) && now@[*p].head==Some(id) {Some(now@[*p])} else {None},
    { crate::memo_projection::current(now,p,id) };
    let decode = |p:&u64,id:ObjectId| -> (r:Result<(crate::memo_projection::Projection<u64>,u32),u8>)
        requires *p==owner && id==head, ensures r==cold, {cold};
    assert(lookup.requires((&owner,head)) && decode.requires((&owner,head)));
    assert forall|m:crate::memo_projection::Projection<u64>|
        #[trigger] lookup.ensures((&owner,head),Some(m)) implies m.head == Some(head) by {
        assert(m == now@[owner]);
    }
    crate::memo_projection::resolve(&owner,head,captured,lookup,decode)
}

}
