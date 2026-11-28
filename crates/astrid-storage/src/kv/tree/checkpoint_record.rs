//! Validate the canonical object envelope and the retained charge of a decoded KV page.
use super::checkpoint_page::{Handle, Node};
use super::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use super::checkpoint_branch::{self, Header};
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
                h.valid(fields.3.len() as usize) && h.level == b.level && h.totals == b.totals &&
                h.count == b.children.len() &&
                exists|path:Seq<usize>| #[trigger] checkpoint_branch::layout(fields.2,fields.3,s,
                    fields.2.len() as usize,b.level,b.children@,path,validate),
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
        out matches Ok(handle) ==> ({
        let fields = record.contents();
        &&& fields.1 == version.number() && fields.4 == 0 && fields.5 == ObjectClass::Metadata
        &&& handle.object == id && parsed(record,handle.node,validate)
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
            Err(e) => return Err(ReadError::Leaf(e)),
        },
        PageKind::Branch => match header::branch(data,edges,validate) {
            Ok(b) => {
                proof {
                    let (h,s) = choose|h:Header,s:usize| #[trigger] header::present(data@,header::Kind::Branch,h,s)
                        && h.outcome(data,edges,s,validate,Ok(b));
                    assert(h.valid(edges.len()));
                    assert(h.count == b.children.len() && h.level == b.level && h.totals == b.totals);
                    let path = choose|p:Seq<usize>| #[trigger] checkpoint_branch::layout(data@,edges@,s,data.len(),b.level,b.children@,p,validate);
                    let f = record.contents();
                    assert(header::present(f.2,header::Kind::Branch,h,s));
                    assert(checkpoint_branch::layout(f.2,f.3,s,f.2.len() as usize,b.level,b.children@,path,validate));
                    assert(parsed(record,Node::Branch(b),validate));
                }
                Node::Branch(b)
            },
            Err(e) => return Err(ReadError::Branch(e)),
        },
    };
    assert(parsed(record,node,validate));
    match finish(id,record,node) { Ok(h) => Ok(h), Err(e) => Err(ReadError::Size(e)) }
}

}
