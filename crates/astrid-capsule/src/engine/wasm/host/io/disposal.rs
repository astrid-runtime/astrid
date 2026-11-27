//! Destruction consumes the exact owned, childless handle inspected on this table.
use vstd::prelude::*;

verus! {
pub(super) enum Refusal<E> { Borrowed, Table(E), HasChildren }

pub(super) fn dispose<T,H,R,E,O,C,D>(table:T,handle:H,owned:O,children:C,remove:D)
    -> (out: Result<R,Refusal<E>>)
    where O:FnOnce(&H)->bool, C:FnOnce(&T,&H)->Result<bool,E>, D:FnOnce(T,H)->R,
    requires owned.requires((&handle,)), children.requires((&table,&handle)), remove.requires((table,handle)),
    ensures match out {
        Err(Refusal::Borrowed) => owned.ensures((&handle,),false),
        Err(Refusal::Table(e)) => owned.ensures((&handle,),true) && children.ensures((&table,&handle),Err(e)),
        Err(Refusal::HasChildren) => owned.ensures((&handle,),true) && children.ensures((&table,&handle),Ok(true)),
        Ok(r) => owned.ensures((&handle,),true) && children.ensures((&table,&handle),Ok(false))
            && remove.ensures((table,handle),r),
    },
{
    if !owned(&handle) { return Err(Refusal::Borrowed); }
    match children(&table,&handle) {
        Err(e) => Err(Refusal::Table(e)),
        Ok(true) => Err(Refusal::HasChildren),
        Ok(false) => Ok(remove(table,handle)),
    }
}
}
