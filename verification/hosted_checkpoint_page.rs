//! Decoded branch inputs supply the decreasing levels used by the production walk.
use crate::{checkpoint_page::{self,Branch,Handle,Node,agrees,decoded,object},checkpoint_range::{Child,Page},checkpoint_walk::Contents};
use vstd::prelude::*;

verus! {

// This reader returns the given decoded page for the scheduled address.
// Success is exact for roots and for matching children. A mismatch keeps the
// object ID of the pending pointer and exposes none of the rejected page.
fn open_decoded<V>(page:Page<u64,u64>,observed:u64,node:Node<u64,u64,V>)
    -> (out:Result<Contents<u64,u64,V>,u64>)
    ensures ({
        let id = object(page);
        let handle = Handle { object:observed,node };
        out == if agrees(page,handle) { Ok(node.contents()) } else { Err(id) }
    }),
{
    checkpoint_page::read(&page,
        |requested:u64| -> (out:Result<Handle<u64,u64,V>,u64>)
            ensures out == Ok(Handle { object:observed,node }),
        { Ok(Handle { object:observed,node }) },
        |requested:u64| -> (error:u64) ensures error == requested, { requested })
}

fn failed_fetch(page:Page<u64,u64>) -> (out:Result<Contents<u64,u64,u64>,u64>)
    ensures out == Err(object(page)),
{
    checkpoint_page::read(&page,
        |id:u64| -> (result:Result<Handle<u64,u64,u64>,u64>) ensures result == Err(id), { Err(id) },
        |_id:u64| -> (error:u64) ensures error == 0, { 0 })
}

// Every pointer used by the walker names the object, fence and totals read at
// its own wire index, and descends one level regardless of those input fields.
fn branch_from_rows<V>(page:Page<u64,u64>,level:u16,totals:u64,input:&[(Vec<u8>,u64,u64)])
    -> (out:Result<Contents<u64,u64,V>,u64>)
    requires level>0,
    ensures match out {
        Ok(Contents::Branch(h,rows)) => h == level && rows.len() == input.len() &&
            (page matches Page::Child(c) ==> c.level == h && c.totals == totals) &&
            forall|i:int| 0 <= i < rows.len() ==> {
                let c = #[trigger] rows@[i];
                &&& c.level as nat+1 == level
                &&& c.object == input@[i].1 && c.lower_bound@ == input@[i].0@ && c.totals == input@[i].2
            },
        Err(e) => page is Child && e == object(page),
        _ => false,
    },
{
    let fetch = |s:(),i:usize| -> (out:Result<((),Vec<u8>,u64,u64),u64>)
        requires i < input.len(),
        ensures match out {
            Ok(tuple) => tuple.1@ == input@[i as int].0@ && tuple.2 == input@[i as int].1 && tuple.3 == input@[i as int].2,
            Err(_) => false,
        },
    {
        let row = &input[i];
        let mut lower = Vec::new();
        lower.extend_from_slice(&row.0);
        assert(lower@ =~= row.0@);
        let result:Result<((),Vec<u8>,u64,u64),u64> = Ok((s,lower,row.1,row.2));
        assert(result is Ok);
        assert(result->Ok_0 == (s,lower,row.1,row.2));
        result
    };
    let parsed = checkpoint_page::children(level,input.len(),(),fetch,|| -> (error:u64) ensures error == 0, { 0 });
    let (_,rows) = match parsed { Ok(v) => v, Err(e) => { assert(false); return Err(e); } };
    let ghost states = choose|states:Seq<()>| #[trigger] decoded(rows@,states,(),(),level,fetch);
    assert forall|i:int| 0 <= i < rows.len() implies ({
        let c = #[trigger] rows@[i];
        &&& c.level as nat+1 == level
        &&& c.object == input@[i].1 && c.lower_bound@ == input@[i].0@ && c.totals == input@[i].2
    }) by {
        let c = rows@[i];
        assert(fetch.ensures((states[i],i as usize),Ok((states[i+1],c.lower_bound,c.object,c.totals))));
    }
    let id = page.object();
    open_decoded(page,id,Node::Branch(Branch { level,children:rows,totals }))
}
}
