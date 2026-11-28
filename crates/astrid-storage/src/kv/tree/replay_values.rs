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

#[cfg(verus_keep_ghost)]
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
pub(super) open spec fn borrowed(slot:&Option<ValueSlot>) -> Option<&ValueSlot> {match slot {None=>None,Some(v)=>Some(v)}}
pub(super) open spec fn finish<C,E,V:FnOnce(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(c:C,prior:Bytes,
    slot:Option<&ValueSlot>,value:V,out:Result<(C,(Bytes,Bytes)),E>) -> bool {
    match slot {
        None => out == Ok((c,(prior,None))),
        Some(v) => match out {
            Ok((next,(p,Some(b)))) => p==prior && value.ensures((c,v),Ok((next,b))),
            Ok(_) => false,
            Err(e) => value.ensures((c,v),Err(e)),
        }
    }
}
pub(super) open spec fn resolved<C,E,L:FnOnce(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:FnOnce(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(c:C,tree:Option<ObjectId>,key:&Vec<u8>,
    slot:Option<&ValueSlot>,need:bool,lookup:L,value:V,out:Result<(C,(Bytes,Bytes)),E>) -> bool {
    if need {
        (out matches Err(e) && lookup.ensures((c,tree,key),Err(e))) ||
        exists|after:C,prior:Bytes| #[trigger] lookup.ensures((c,tree,key),Ok((after,prior))) &&
            finish(after,prior,slot,value,out)
    } else {finish(c,None,slot,value,out)}
}
pub(super) fn resolve_state<C,E,L:FnOnce(C,Option<ObjectId>,&Vec<u8>)->Result<(C,Bytes),E>,
    V:FnOnce(C,&ValueSlot)->Result<(C,Vec<u8>),E>>(c:C,tree:Option<ObjectId>,key:&Vec<u8>,
    slot:Option<&ValueSlot>,need:bool,lookup:L,value:V) -> (out:Result<(C,(Bytes,Bytes)),E>)
    requires lookup.requires((c,tree,key)),forall|s:C,v:&ValueSlot| #[trigger] value.requires((s,v)),
    ensures resolved(c,tree,key,slot,need,lookup,value,out),
{
    let (current,prior) = if need {lookup(c,tree,key)?} else {(c,None)};
    match slot {
        None => Ok((current,(prior,None))),
        Some(v) => {let (next,bytes) = value(current,v)?;Ok((next,(prior,Some(bytes))))},
    }
}

}
