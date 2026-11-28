//! Validate the canonical object envelope and the retained charge of a decoded KV page.
use super::checkpoint_page::{self, Handle, Node};
use super::checkpoint_range::Page;
use super::checkpoint_walk::Contents;
use super::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

#[cfg(verus_keep_ghost)]
use super::checkpoint_branch::Header;
use super::{
    checkpoint_header as header, checkpoint_leaf_record as leaf, checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot,
};

verus! {
pub(super) const NODE_MAX_RETAINED_BYTES: u64 = 4_096;
pub(super) enum PageKind { Leaf, Branch }
pub(super) enum EnvelopeError { Header, Kind }

pub(super) fn classify(record: &ObjectRecord, version: ObjectFormatVersion)
    -> (out: Result<PageKind, EnvelopeError>)
    ensures ({
        let fields = record.contents();
        if fields.1 != version.number() || fields.4 != 0 || fields.5 != ObjectClass::Metadata {
            out == Err(EnvelopeError::Header)
        } else {
            match fields.0 {
                ObjectKind::KvLeaf => out == Ok(PageKind::Leaf),
                ObjectKind::KvBranch => out == Ok(PageKind::Branch),
                _ => out == Err(EnvelopeError::Kind),
            }
        }
    }),
{
    if record.format_version().get() != version.get() || record.logical_bytes() != 0
        || !matches!(record.class(), ObjectClass::Metadata) {
        return Err(EnvelopeError::Header);
    }
    match record.kind() {
        ObjectKind::KvLeaf => Ok(PageKind::Leaf),
        ObjectKind::KvBranch => Ok(PageKind::Branch),
        _ => Err(EnvelopeError::Kind),
    }
}

pub(super) enum SizeError { Overflow, Oversize }

pub(super) fn finish<T,V>(id: ObjectId, record: &ObjectRecord, node: Node<ObjectId,T,V>)
    -> (out: Result<Handle<ObjectId,T,V>, SizeError>)
    ensures ({
        let cost = record.retained_cost();
        let splittable = match node {
            Node::Leaf(l) => l.entries.len() > 1,
            Node::Branch(b) => b.children.len() > 3,
        };
        if cost > u64::MAX { out == Err(SizeError::Overflow) }
        else if cost > NODE_MAX_RETAINED_BYTES && splittable { out == Err(SizeError::Oversize) }
        else { out matches Ok(handle) && handle.object == id && handle.node == node }
    }),
{
    let Some(cost) = record.retained_usage() else { return Err(SizeError::Overflow); };
    if cost > NODE_MAX_RETAINED_BYTES {
        let splittable = match &node {
            Node::Leaf(l) => l.entries.len() > 1,
            Node::Branch(b) => b.children.len() > 3,
        };
        if splittable { return Err(SizeError::Oversize); }
    }
    Ok(Handle { object: id, node })
}
pub(super) enum ReadError<E> {
    Envelope(EnvelopeError), Leaf(leaf::Error<E>), Branch(header::RecordError<E>), Size(SizeError),
}

#[cfg(verus_keep_ghost)]
type DecodedNode = Node<ObjectId,NodeTotals,ValueSlot>;

pub(super) open spec fn ordered(node:DecodedNode) -> bool {
    match node {
        Node::Leaf(l) => super::checkpoint_leaf_summary::ordered(l.entries@,l.entries.len() as nat),
        Node::Branch(b) => super::checkpoint_summary::ordered(b.children@,b.children.len() as nat),
    }
}

pub(super) open spec fn descending(node:DecodedNode) -> bool {
    match node {
        Node::Leaf(_) => true,
        Node::Branch(b) => b.level > 0 && forall|i:int| 0 <= i < b.children.len() ==>
            (#[trigger] b.children@[i]).level as nat + 1 == b.level,
    }
}

pub(super) open spec fn parsed<E,F:Fn(&[u8])->Result<(),E>>(
    record:&ObjectRecord, node:DecodedNode, validate:F,
) -> bool {
    let fields = record.contents();
    match node {
        Node::Leaf(l) => fields.0 == ObjectKind::KvLeaf &&
            exists|h:Header,s:usize| #[trigger] header::present(fields.2,header::Kind::Leaf,h,s) &&
                leaf::body(fields.2,fields.3,s,h,validate,Ok(l)),
        Node::Branch(b) => fields.0 == ObjectKind::KvBranch &&
            exists|h:Header,s:usize| #[trigger] header::present(fields.2,header::Kind::Branch,h,s) &&
                h.field_outcome(fields.2,fields.3,s,validate,Ok(b)),
    }
}

pub(super) open spec fn refusal<E,F:Fn(&[u8])->Result<(),E>>(
    record:&ObjectRecord, validate:F, reason:ReadError<E>,
) -> bool {
    let f = record.contents();
    match reason {
        ReadError::Envelope(_) => true,
        ReadError::Leaf(e) => f.0 == ObjectKind::KvLeaf && match e {
            leaf::Error::Prefix(p) => header::prefix_error(f.2,header::Kind::Leaf,p),
            _ => exists|h:Header,s:usize| #[trigger] header::present(f.2,header::Kind::Leaf,h,s) &&
                leaf::body(f.2,f.3,s,h,validate,Err(e)),
        },
        ReadError::Branch(e) => f.0 == ObjectKind::KvBranch && match e {
            header::RecordError::Prefix(p) => header::prefix_error(f.2,header::Kind::Branch,p),
            header::RecordError::Body(b) => exists|h:Header,s:usize| #[trigger] header::present(f.2,header::Kind::Branch,h,s) &&
                h.field_outcome(f.2,f.3,s,validate,Err(b)),
        },
        ReadError::Size(e) => exists|n:DecodedNode| #[trigger] parsed(record,n,validate) && match e {
            SizeError::Overflow => record.retained_cost() > u64::MAX,
            SizeError::Oversize => NODE_MAX_RETAINED_BYTES < record.retained_cost() <= u64::MAX && match n {
                Node::Leaf(l) => l.entries.len() > 1,
                Node::Branch(b) => b.children.len() > 3,
            },
        },
    }
}

pub(super) fn read<E,F:Fn(&[u8])->Result<(),E>+Copy>(
    id:ObjectId, record:&ObjectRecord, version:ObjectFormatVersion, validate:F,
) -> (out:Result<Handle<ObjectId,NodeTotals,ValueSlot>,ReadError<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures (out matches Err(ReadError::Envelope(EnvelopeError::Header))) ==
            (record.contents().1 != version.number() || record.contents().4 != 0 || record.contents().5 != ObjectClass::Metadata),
        (out matches Err(ReadError::Envelope(EnvelopeError::Kind))) ==
            (record.contents().1 == version.number() && record.contents().4 == 0 && record.contents().5 == ObjectClass::Metadata &&
            !(record.contents().0 is KvLeaf) && !(record.contents().0 is KvBranch)),
        out matches Err(reason) ==> refusal(record,validate,reason),
        out matches Ok(handle) ==> ({
        let fields = record.contents();
        &&& fields.1 == version.number() && fields.4 == 0 && fields.5 == ObjectClass::Metadata
        &&& handle.object == id && parsed(record,handle.node,validate) && ordered(handle.node) && descending(handle.node)
        &&& record.retained_cost() <= u64::MAX
        &&& record.retained_cost() <= NODE_MAX_RETAINED_BYTES || match handle.node {
            Node::Leaf(l) => l.entries.len() <= 1,
            Node::Branch(b) => b.children.len() <= 3,
        }
    }),
{
    let kind = match classify(record,version) { Ok(k) => k, Err(e) => return Err(ReadError::Envelope(e)) };
    let data = record.canonical_bytes();
    let edges = record.references();
    let node = match kind {
        PageKind::Leaf => match leaf::read(data,edges,validate) {
            Ok(l) => Node::Leaf(l),
            Err(e) => { assert(refusal(record,validate,ReadError::Leaf(e))); return Err(ReadError::Leaf(e)); },
        },
        PageKind::Branch => match header::branch(data,edges,validate) {
            Ok(b) => {
                proof {
                    let (h,s) = choose|h:Header,s:usize| #[trigger] header::present(data@,header::Kind::Branch,h,s)
                        && h.outcome(data,edges,s,validate,Ok(b));
                    assert(h.field_outcome(record.contents().2,record.contents().3,s,validate,Ok(b)));
                    let pos = choose|p:Seq<usize>| #[trigger] super::checkpoint_branch::layout(
                        data@,edges@,s,data.len() as usize,b.level,b.children@,p,validate);
                    assert forall|i:int| 0 <= i < b.children.len() implies
                        (#[trigger] b.children@[i]).level as nat + 1 == b.level by {
                        assert(super::checkpoint_branch::row_at(data@,edges@,i,pos[i],pos[i+1],
                            b.level,b.children@[i],validate));
                    }
                    assert(parsed(record,Node::Branch(b),validate));
                }
                Node::Branch(b)
            },
            Err(e) => {
                proof {
                    if let header::RecordError::Body(b_ref) = &e {
                        let b = *b_ref;
                        let (h,s) = choose|h:Header,s:usize| #[trigger] header::present(data@,header::Kind::Branch,h,s) &&
                            h.outcome(data,edges,s,validate,Err(b));
                        assert(h.field_outcome(record.contents().2,record.contents().3,s,validate,Err(b)));
                    }
                    assert(refusal(record,validate,ReadError::Branch(e)));
                }
                return Err(ReadError::Branch(e));
            },
        },
    };
    assert(parsed(record,node,validate));
    match finish(id,record,node) { Ok(h) => Ok(h), Err(e) => Err(ReadError::Size(e)) }
}

pub(super) enum ScheduledError<E> { Source(E), Record(ReadError<E>), Summary }

pub(super) open spec fn scheduled_result<E,F:Fn(&[u8])->Result<(),E>>(
    page:&Page<ObjectId,NodeTotals>,record:&ObjectRecord,
    version:ObjectFormatVersion,validate:F,out:Result<Contents<ObjectId,NodeTotals,ValueSlot>,ScheduledError<E>>,
) -> bool {
    match out {
        Ok(body) => ({
            &&& record.contents().1 == version.number() && record.contents().4 == 0 && record.contents().5 == ObjectClass::Metadata
            &&& exists|n:DecodedNode| #[trigger] parsed(record,n,validate) && ordered(n) &&
                checkpoint_page::agrees(*page,Handle {object:checkpoint_page::object(*page),node:n}) &&
                body == n.contents()
            &&& body matches Contents::Branch(h,rows) ==> h > 0 &&
                (*page matches Page::Child(c) ==> c.level == h) &&
                forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows@[i]).level as nat + 1 == h
        }),
        Err(ScheduledError::Source(_)) => false,
        Err(ScheduledError::Record(e)) => refusal(record,validate,e) && match e {
            ReadError::Envelope(EnvelopeError::Header) => record.contents().1 != version.number() ||
                record.contents().4 != 0 || record.contents().5 != ObjectClass::Metadata,
            ReadError::Envelope(EnvelopeError::Kind) => record.contents().1 == version.number() &&
                record.contents().4 == 0 && record.contents().5 == ObjectClass::Metadata &&
                !(record.contents().0 is KvLeaf) && !(record.contents().0 is KvBranch),
            _ => true,
        },
        Err(ScheduledError::Summary) => exists|n:DecodedNode| #[trigger] parsed(record,n,validate) &&
            !checkpoint_page::agrees(*page,Handle {object:checkpoint_page::object(*page),node:n}),
    }
}

/// Decode the fetched record and check the pointer that scheduled its traversal.
fn scheduled<E,F:Fn(&[u8])->Result<(),E>+Copy>(
    page:&Page<ObjectId,NodeTotals>, record:&ObjectRecord,
    version:ObjectFormatVersion, validate:F,
) -> (out:Result<Contents<ObjectId,NodeTotals,ValueSlot>,ScheduledError<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
        vstd::laws_eq::obeys_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<NodeTotals>(),
    ensures scheduled_result(page,record,version,validate,out),
{
    let id = page.object();
    let h = match read(id,record,version,validate) {
        Ok(h) => h,
        Err(e) => return Err(ScheduledError::Record(e)),
    };
    let ghost source = h;
    let fetch = |_id:ObjectId| -> (r:Result<Handle<ObjectId,NodeTotals,ValueSlot>,ScheduledError<E>>)
        ensures r == Ok(source), { Ok(h) };
    checkpoint_page::read(page,fetch,|_id:ObjectId| -> (e:ScheduledError<E>)
        ensures e == ScheduledError::Summary, { ScheduledError::Summary })
}

/// Load by the scheduled object ID before decoding or validating the child summary.
pub(super) fn load_scheduled<E,F:Fn(&[u8])->Result<(),E>+Copy,L:FnOnce(ObjectId)->Result<ObjectRecord,E>>(
    page:&Page<ObjectId,NodeTotals>,version:ObjectFormatVersion,load:L,validate:F,
) -> (out:Result<Contents<ObjectId,NodeTotals,ValueSlot>,ScheduledError<E>>)
    requires load.requires((checkpoint_page::object(*page),)),
        forall|k:&[u8]| #[trigger] validate.requires((k,)),
        vstd::laws_eq::obeys_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<NodeTotals>(),
    ensures match out {
        Err(ScheduledError::Source(e)) => load.ensures((checkpoint_page::object(*page),),Err(e)),
        _ => exists|record:ObjectRecord| #[trigger] load.ensures((checkpoint_page::object(*page),),Ok(record)) &&
            scheduled_result(page,&record,version,validate,out),
    },
{
    let id = page.object();
    let record = match load(id) { Ok(r) => r, Err(e) => return Err(ScheduledError::Source(e)) };
    scheduled(page,&record,version,validate)
}

/// Traverse a staged record in place. Only a miss consults the captured owner's engine.
pub(super) fn owner_page<P,E,F,L,M>(
    staged:&BTreeMap<ObjectId,ObjectRecord>,owner:&P,page:&Page<ObjectId,NodeTotals>,
    version:ObjectFormatVersion,engine:L,missing:M,validate:F,
) -> (out:Result<Contents<ObjectId,NodeTotals,ValueSlot>,ScheduledError<E>>)
    where F:Fn(&[u8])->Result<(),E>+Copy,L:FnOnce(&P,ObjectId)->Result<Option<ObjectRecord>,E>,
        M:FnOnce(ObjectId)->E,
    requires btree_map_inv(staged),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        engine.requires((owner,checkpoint_page::object(*page))),missing.requires((checkpoint_page::object(*page),)),
        forall|k:&[u8]| #[trigger] validate.requires((k,)),
        vstd::laws_eq::obeys_concrete_eq::<ObjectId>(),vstd::laws_eq::obeys_concrete_eq::<NodeTotals>(),
    ensures ({
        let id = checkpoint_page::object(*page);
        if staged@.contains_key(id) {
            scheduled_result(page,&staged@[id],version,validate,out)
        } else {
            match out {
                Err(ScheduledError::Source(e)) => engine.ensures((owner,id),Err(e)) ||
                    (engine.ensures((owner,id),Ok(None)) && missing.ensures((id,),e)),
                _ => exists|r:ObjectRecord| #[trigger] engine.ensures((owner,id),Ok(Some(r))) &&
                    scheduled_result(page,&r,version,validate,out),
            }
        }
    }),
{
    let id = page.object();
    if let Some(record) = staged.get(&id) {
        return scheduled(page,record,version,validate);
    }
    let fetch = |key:ObjectId| -> (r:Result<ObjectRecord,E>)
        requires key == id,
        ensures match r {
            Ok(record) => engine.ensures((owner,key),Ok(Some(record))),
            Err(e) => engine.ensures((owner,key),Err(e)) ||
                (engine.ensures((owner,key),Ok(None)) && missing.ensures((key,),e)),
        },
    {
        match engine(owner,key) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(missing(key)),
            Err(e) => Err(e),
        }
    };
    load_scheduled(page,version,fetch,validate)
}

}
