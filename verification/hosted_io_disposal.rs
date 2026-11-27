//! Pin both inspected inputs and the exact removal output of checked destruction.
use crate::io_disposal::{dispose,Refusal};
use vstd::prelude::*;

verus! {
fn retire(table:u64,rep:u32, owned:bool, entry:Result<bool,u8>) -> (out:Result<(u64,u32),Refusal<u8>>)
    ensures out == if !owned { Err(Refusal::Borrowed) } else { match entry {
        Err(e) => Err(Refusal::Table(e)), Ok(true) => Err(Refusal::HasChildren),
        Ok(false) => Ok((table,rep)),
    }},
{
    dispose(table,rep,
        |h:&u32| -> (yes:bool) ensures yes == (owned && *h == rep), { owned && *h == rep },
        |t:&u64,h:&u32| -> (v:Result<bool,u8>) ensures v == if *t == table && *h == rep { entry } else { Err(255u8) },
            { if *t == table && *h == rep { entry } else { Err(255u8) } },
        |t:u64,h:u32| -> (r:(u64,u32)) ensures r == (t,h), { (t,h) })
}
}
