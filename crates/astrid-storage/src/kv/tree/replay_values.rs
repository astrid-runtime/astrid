//! Resolve the two byte values used to check one recovered mutation.
use super::{ObjectId, checkpoint_value::ValueSlot};
use vstd::prelude::*;

verus! {
pub(super) type Bytes = Option<Vec<u8>>;

pub(super) open spec fn replacement<C,E,V:FnOnce(C,&ValueSlot)->Result<Vec<u8>,E>>(
    context:C,slot:Option<&ValueSlot>,value:V,out:Result<Bytes,E>) -> bool {
    match slot {
        None => out == Ok(None),
        Some(v) => match out {
            Ok(Some(bytes)) => value.ensures((context,v),Ok(bytes)),
            Ok(None) => false,
            Err(e) => value.ensures((context,v),Err(e)),
        }
    }
}

pub(super) open spec fn after_prior<C,E,V:FnOnce(C,&ValueSlot)->Result<Vec<u8>,E>>(
    context:C,prior:Bytes,slot:Option<&ValueSlot>,value:V,out:Result<(Bytes,Bytes),E>) -> bool {
    match out {
        Ok(pair) => pair.0 == prior && replacement(context,slot,value,Ok(pair.1)),
        Err(e) => replacement(context,slot,value,Err(e)),
    }
}

pub(super) fn resolve<C,E,L:FnOnce(C,Option<ObjectId>,&[u8])->Result<(C,Bytes),E>,
    V:FnOnce(C,&ValueSlot)->Result<Vec<u8>,E>>(context:C,tree:Option<ObjectId>,key:&[u8],
    slot:Option<&ValueSlot>,needs_checkpoint:bool,lookup:L,value:V) -> (out:Result<(Bytes,Bytes),E>)
    requires lookup.requires((context,tree,key)), forall|c:C,v:&ValueSlot| #[trigger] value.requires((c,v)),
    ensures if needs_checkpoint {
        (exists|c:C,p:Bytes| #[trigger] lookup.ensures((context,tree,key),Ok((c,p))) && after_prior(c,p,slot,value,out))
        || (out matches Err(e) && lookup.ensures((context,tree,key),Err(e)))
    } else {after_prior(context,None,slot,value,out)},
{
    let (active,prior) = if needs_checkpoint {lookup(context,tree,key)?} else {(context,None)};
    let bytes = match slot {None => None, Some(v) => Some(value(active,v)?)};
    Ok((prior,bytes))
}
}
