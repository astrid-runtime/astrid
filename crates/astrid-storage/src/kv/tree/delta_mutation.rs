//! One operation in a persisted KV delta.
use super::ObjectId;
use super::checkpoint_value::{INLINE_VALUE_MAX, ValueSlot};
use vstd::prelude::*;

verus! {
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mutation {
    pub(super) key: Vec<u8>,
    pub(super) value: Option<ValueSlot>,
}

/// Resolve borrowed mutation bytes without duplicating a spilled payload.
pub(super) fn encode<E,F:FnOnce(&[u8],u64)->Result<ObjectId,E>>(data:&[u8],spill:F)
    -> (out:Result<ValueSlot,E>)
    requires data.len() > INLINE_VALUE_MAX ==> spill.requires((data,data.len() as u64)),
    ensures match out {
        Ok(ValueSlot::Inline(v)) => data.len() <= INLINE_VALUE_MAX && v@ == data@,
        Ok(ValueSlot::Spilled {object,length}) => data.len() > INLINE_VALUE_MAX &&
            length == data.len() && spill.ensures((data,length),Ok(object)),
        Err(e) => data.len() > INLINE_VALUE_MAX && spill.ensures((data,data.len() as u64),Err(e)),
    },
{
    if data.len() <= INLINE_VALUE_MAX {
        let mut bytes = Vec::with_capacity(data.len());
        bytes.extend_from_slice(data);
        assert(bytes@ =~= data@);
        return Ok(ValueSlot::Inline(bytes));
    }
    let length = data.len() as u64;
    let object = spill(data,length)?;
    Ok(ValueSlot::Spilled {object,length})
}
}
