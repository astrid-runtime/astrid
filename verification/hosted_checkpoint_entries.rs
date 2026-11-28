//! A mixed leaf has two logical slots but consumes just one owning reference.
use crate::{ObjectId,ObjectReference,checkpoint_entries::{self as entries,Error,Row},
    checkpoint_key_field as key,checkpoint_value::{self as value,ValueSlot},checkpoint_reference as edge};
use vstd::prelude::*;

verus! {

#[verifier::rlimit(30)]
fn mixed(id:ObjectId,trail:bool,extra:bool,deny_second:bool) -> (out:Result<Vec<Row>,Error<()>>)
    ensures if deny_second {out == Err(Error::Invalid(()))} else if trail {out == Err(Error::Trailing)} else if extra {out == Err(Error::References)} else {
        out matches Ok(rows) && rows.len() == 2 &&
        rows@[0].key@ == seq![110u8,0u8,97u8] && (rows@[0].value matches ValueSlot::Inline(v) && v@ == seq![42u8]) &&
        rows@[1].key@ == seq![110u8,0u8,98u8] && rows@[1].value == (ValueSlot::Spilled {object:id,length:2048})
    },
{
    let mut bytes = Vec::new();
    let mut refs = Vec::new();
    let a = [110u8,0,97]; let b = [110u8,0,98];
    let mut payload = Vec::new(); payload.push(42u8);
    key::append(&mut bytes,&a);
    let inline = value::append(&mut bytes,&mut refs,0,&ValueSlot::Inline(payload));
    assert(inline is Ok);
    key::append(&mut bytes,&b);
    let spill = value::append(&mut bytes,&mut refs,1,&ValueSlot::Spilled {object:id,length:2048});
    assert(spill is Ok);
    if extra { refs.push(ObjectReference::owns(edge::label(edge::Relation::Value,2).unwrap(),id)); }
    if trail { bytes.push(0); }
    let accept = |k:&[u8]| -> (r:Result<(),()>) ensures (r is Err) == (deny_second && k@ == b@) {
        if deny_second && matches!(crate::encoding::bytewise_cmp(k,&b),std::cmp::Ordering::Equal) {Err(())} else {Ok(())}
    };
    let out = entries::read(&bytes,&refs,0,2,accept);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(0,4) =~= crate::storage_words::word32(3));
        assert(bytes@.subrange(17,21) =~= crate::storage_words::word32(3));
        key::encoded_length(bytes@,0,3); key::encoded_length(bytes@,17,3);
        assert(bytes@.subrange(4,7) =~= a@);
        assert(bytes@.subrange(21,24) =~= b@);
        assert(bytes@.subrange(7,15) =~= vstd::bytes::spec_u64_to_le_bytes(1));
        assert(bytes@.subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(2048));
        assert(bytes@[15] == 0 && bytes@[32] == 1);
        assert(bytes@.subrange(16,17) =~= seq![42u8]);
        assert(refs@[0].fields() == (edge::wire(edge::Relation::Value,1),id,crate::ReferenceKind::Owns));
        if out is Err {
            let e = out->Err_0;
            let (rows,p,s) = choose|rows:Seq<Row>,p:Seq<(usize,usize)>,s:(usize,usize)|
                #[trigger] entries::stopped(bytes@,refs@,0,2,accept,rows,p,s,e);
            if rows.len() > 0 {
                assert(entries::row_at(bytes@,refs@,0,p[0],p[1],rows[0],accept));
                assert(p[1] == (17usize,0usize));
            }
            if rows.len() == 2 {
                assert(entries::row_at(bytes@,refs@,1,p[1],p[2],rows[1],accept));
                assert(s == (33usize,1usize));
            } else {
                assert(rows.len() < 2);
                let end = choose|end:usize| #[trigger] entries::rejected(bytes@,refs@,rows.len() as usize,s,end,accept,e);
                if rows.len() == 0 { assert(s == (0usize,0usize)); } else { assert(s == (17usize,0usize)); }
                assert(rows.len() == 1 && deny_second);
                assert(e matches Error::Invalid(_));
            }
        } else {
            let rows = out->Ok_0;
            let p = choose|p:Seq<(usize,usize)>| #[trigger] entries::layout(bytes@,refs@,0,(bytes.len(),refs.len()),rows@,p,accept);
            assert(entries::row_at(bytes@,refs@,0,p[0],p[1],rows@[0],accept));
            assert(p[1] == (17usize,0usize));
            assert(entries::row_at(bytes@,refs@,1,p[1],p[2],rows@[1],accept));
        }
    }
    out
}
}
