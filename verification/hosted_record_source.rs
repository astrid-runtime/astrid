//! Staged bodies win at their own address. Misses retain the owner and requested ID.
use crate::{ObjectId,ObjectRecord,record_source as source};
use std::{collections::BTreeMap,sync::Arc};
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {
fn selection(staged:&BTreeMap<ObjectId,ObjectRecord>,owner:u64,allowed:u64,id:ObjectId,
    address:ObjectId,record:Arc<ObjectRecord>)
    requires btree_map_inv(staged),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
{
    let engine = |p:&u64,k:ObjectId| -> (out:Result<Option<Arc<ObjectRecord>>,u8>)
        ensures out == if *p != allowed {Err(7u8)} else if k == address {Ok(Some(record))} else {Ok(None)} {
        if *p != allowed {Err(7)} else if k.same(&address) {Ok(Some(record))} else {Ok(None)}
    };
    let shared = source::load(staged,&owner,id,source::shared,engine);
    proof {
        if staged@.contains_key(id) {
            assert(shared matches Ok(r) && r.same_contents(&staged@[id]));
        } else if owner != allowed {assert(shared == Err(source::Error::Source(7u8)));}
        else if id == address {assert(shared == Ok(record));}
        else {assert(shared == Err(source::Error::Missing(id)));}
    }
}

fn copy_fields(record:&ObjectRecord,i:usize) {
    let copy = record.owned_record();
    let shared = source::shared(record);
    proof {
        let a = record.contents(); let b = copy.contents(); let c = shared.contents();
        assert((b.0,b.1,b.2,b.4,b.5) == (a.0,a.1,a.2,a.4,a.5));
        assert((c.0,c.1,c.2,c.4,c.5) == (a.0,a.1,a.2,a.4,a.5));
        assert(a.3.len() == b.3.len() && a.3.len() == c.3.len());
        if i < a.3.len() {
            assert(a.3[i as int].fields() == b.3[i as int].fields() && a.3[i as int].fields() == c.3[i as int].fields());
        }
    }
}
}
