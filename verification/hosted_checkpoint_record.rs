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

}
