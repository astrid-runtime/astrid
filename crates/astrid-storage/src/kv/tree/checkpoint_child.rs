//! Read one branch pointer from the page cursor and the corresponding owning edge.
use super::{
    ObjectId, ObjectReference, checkpoint_key_field as key, checkpoint_reference as edge,
    checkpoint_totals::NodeTotals,
};
use crate::storage_fields::ReadError;
use vstd::prelude::*;

verus! {
pub(super) enum ChildError<E> {
    Key(key::KeyError), InvalidKey(E), Totals(ReadError), Empty, Reference(edge::Rejection),
}

pub(super) fn read<E,F:FnOnce(&[u8])->Result<(),E>>(
    bytes: &[u8], cursor: &mut usize, refs: &[ObjectReference], index: usize, validate: F,
) -> (out: Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<E>>)
    requires forall|field:&[u8]| #[trigger] validate.requires((field,)),
    ensures out matches Ok(row) ==> ({
        let start = *old(cursor) as int;
        let n = key::length(bytes@,start) as int;
        let summary = start + 4 + n;
        &&& row.0@ == bytes@.subrange(start+4,summary)
        &&& exists|field:&[u8],r:Result<(),E>| field@ == row.0@ && r is Ok && #[trigger] validate.ensures((field,),r)
        &&& row.2.entries > 0 && crate::storage_fields::at(bytes@,summary,row.2.wire())
        &&& *final(cursor) as int == summary + 24
        &&& index < refs.len() && index <= u16::MAX
        &&& refs@[index as int].fields() == (edge::wire(edge::Relation::Child,index),row.1,super::ReferenceKind::Owns)
    }),
    out matches Err(reason) ==> ({
        let start = *old(cursor) as int;
        let summary = start + 4 + key::length(bytes@,start) as int;
        &&& (!(reason is Key) && !(reason is InvalidKey)) ==> exists|field:&[u8],r:Result<(),E>|
            field@ == bytes@.subrange(start+4,summary) && r is Ok && #[trigger] validate.ensures((field,),r)
        &&& reason is Reference ==> exists|t:NodeTotals| t.entries > 0 && crate::storage_fields::at(bytes@,summary,#[trigger] t.wire())
        &&& match reason {
            ChildError::Key(e) => key::failure(bytes@,start,*final(cursor) as int,e),
            ChildError::InvalidKey(e) => summary <= bytes.len() && *final(cursor) as int == summary && exists|field:&[u8],r:Result<(),E>|
                field@ == bytes@.subrange(start+4,summary) && r == Err(e) && #[trigger] validate.ensures((field,),r),
            ChildError::Totals(e) => summary <= bytes.len() && super::checkpoint_totals::failure(bytes@,summary,*final(cursor) as int,e),
            ChildError::Empty => *final(cursor) as int == summary+24 && exists|t:NodeTotals| t.entries == 0 && crate::storage_fields::at(bytes@,summary,#[trigger] t.wire()),
            ChildError::Reference(e) => *final(cursor) as int == summary+24 && if index >= refs.len() { e == edge::Rejection::Missing }
                else if index > u16::MAX { e == edge::Rejection::IndexOverflow } else {
                    let row = refs@[index as int].fields();
                    e == edge::Rejection::Mismatch && (row.0 != edge::wire(edge::Relation::Child,index) || !(row.2 is Owns))
                },
        }
    }),
{
    let ghost start = *cursor as int;
    let field = match key::read(bytes,cursor) {
        Ok(field) => field, Err(e) => return Err(ChildError::Key(e)),
    };
    let checked = validate(field);
    assert(validate.ensures((field,),checked));
    if let Err(e) = checked { return Err(ChildError::InvalidKey(e)); }
    assert(checked is Ok);
    let totals = match NodeTotals::read(bytes,cursor) {
        Ok(t) => t, Err(e) => return Err(ChildError::Totals(e)),
    };
    if totals.entries == 0 { return Err(ChildError::Empty); }
    let id = match edge::target(refs,index,edge::Relation::Child,index) {
        Ok(id) => id, Err(e) => return Err(ChildError::Reference(e)),
    };
    let mut fence = Vec::with_capacity(field.len());
    fence.extend_from_slice(field);
    assert(fence@ == field@);
    assert(exists|k:&[u8],r:Result<(),E>| k@ == fence@ && r is Ok && #[trigger] validate.ensures((k,),r));
    let ghost at = start + 4 + key::length(bytes@,start);
    assert(fence@ == bytes@.subrange(start+4,at));
    assert(crate::storage_fields::at(bytes@,at,totals.wire()));
    assert(*cursor as int == at + 24);
    assert(refs@[index as int].fields() == (edge::wire(edge::Relation::Child,index),id,super::ReferenceKind::Owns));
    let out:Result<(Vec<u8>,ObjectId,NodeTotals),ChildError<E>> = Ok((fence,id,totals));
    assert(out->Ok_0 == (fence,id,totals));
    out
}
}
