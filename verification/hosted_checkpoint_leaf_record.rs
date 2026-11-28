//! A serialized leaf accepts exactly the quota advertised for its actual key and value bytes.
use crate::{ObjectReference,checkpoint_branch::Header,checkpoint_entries::{self as entries,Row},
    checkpoint_header::{self as header,Kind},checkpoint_key_field as key,checkpoint_leaf_record::{self as record,Error},
    checkpoint_leaf_summary as summary,checkpoint_totals::NodeTotals,checkpoint_value::{self as value,ValueSlot}};
use vstd::prelude::*;

verus! {

#[verifier::rlimit(30)]
fn written(claim:u64) -> (out:Result<record::DecodedLeaf,Error<()>>)
    ensures if claim != 4 { out == Err(Error::Summary(summary::Error::NonCanonical)) }
        else { out matches Ok(leaf) && leaf.entries.len() == 1 && leaf.totals.quota_bytes == 4 &&
            leaf.entries@[0].key@ == seq![110u8,0u8,97u8] &&
            (leaf.entries@[0].value matches ValueSlot::Inline(d) && d@ == seq![42u8]) },
{
    let h = Header {level:0,count:1,totals:NodeTotals {entries:1,logical_bytes:1,quota_bytes:claim}};
    let mut bytes = Vec::new(); let mut refs = Vec::<ObjectReference>::new();
    let ok = header::append(&mut bytes,Kind::Leaf,h); assert(ok);
    let first = bytes.len();
    let k = [110u8,0,97]; let mut v = Vec::new(); v.push(42u8);
    let wrote = key::append(&mut bytes,&k); assert(wrote);
    let wrote = value::append(&mut bytes,&mut refs,0,&ValueSlot::Inline(v)); assert(wrote is Ok);
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let data = bytes.as_slice(); let edges = refs.as_slice();
    let out = record::read(data,edges,accept);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let start = first as int;
        assert(bytes@.take(Kind::Leaf.tag().len() as int) =~= Kind::Leaf.tag());
        assert(bytes@.take(start) =~= header::wire(Kind::Leaf,h));
        assert(bytes@.subrange(start,start+4) =~= crate::storage_words::word32(3));
        key::encoded_length(bytes@,start,3);
        assert(bytes@.subrange(start+4,start+7) =~= k@);
        assert(bytes@.subrange(start+7,start+15) =~= vstd::bytes::spec_u64_to_le_bytes(1));
        assert(bytes@[start+15] == 0 && bytes@.subrange(start+16,start+17) =~= seq![42u8]);
        if out matches Err(Error::Prefix(_)) { assert(false); }
        let (got,s) = choose|got:Header,s:usize| #[trigger] header::present(bytes@,Kind::Leaf,got,s) &&
            record::body(bytes@,refs@,s,got,accept,out);
        assert(header::wire(Kind::Leaf,got).len() == start);
        crate::hosted_checkpoint_header::unique(Kind::Leaf,h,got);
        assert(s==first && got == h);
        if let Err(Error::Entries(e_ref)) = &out {
            let e = *e_ref;
            let (rows,p,end) = choose|rows:Seq<Row>,p:Seq<(usize,usize)>,end:(usize,usize)|
                #[trigger] entries::stopped(bytes@,refs@,first,1,accept,rows,p,end,e);
            if rows.len() == 1 {
                assert(entries::row_at(bytes@,refs@,0,p[0],p[1],rows[0],accept));
                assert(end == (bytes.len(),0usize));
            } else {
                assert(rows.len()==0 && end == (first,0usize));
                let bad = choose|bad:usize| #[trigger] entries::rejected(bytes@,refs@,0,end,bad,accept,e);
                assert(false);
            }
        }
        if let Err(Error::Summary(e_ref)) = &out {
            let e = *e_ref;
            let (rows,p) = choose|rows:Vec<Row>,p:Seq<(usize,usize)>| rows.len()==1 &&
                #[trigger] entries::layout(bytes@,refs@,first,(bytes.len(),0usize),rows@,p,accept) &&
                summary::outcome(rows,h.totals) == Err(e);
            assert(entries::row_at(bytes@,refs@,0,p[0],p[1],rows@[0],accept));
            reveal_with_fuel(summary::usage,2);
            assert(summary::usage(rows@,1) == (1nat,4nat));
        }
        if out is Ok {
            let leaf = out->Ok_0;
            let p = choose|p:Seq<(usize,usize)>| #[trigger] entries::layout(bytes@,refs@,first,(bytes.len(),0usize),leaf.entries@,p,accept);
            assert(entries::row_at(bytes@,refs@,0,p[0],p[1],leaf.entries@[0],accept));
            reveal_with_fuel(summary::usage,2);
            assert(summary::usage(leaf.entries@,1) == (1nat,4nat));
        }
    }
    out
}

fn finish_pair(left:Row,right:Row,claimed:NodeTotals) -> (out:Result<record::DecodedLeaf,summary::Error>)
    ensures ({
        let logical = summary::size(left.value)+summary::size(right.value);
        let quota = logical+left.key.len()+right.key.len();
        if !crate::encoding::below(left.key@,right.key@) { out == Err(summary::Error::NonCanonical) }
        else if logical > u64::MAX || quota > u64::MAX { out == Err(summary::Error::Overflow) }
        else if claimed.entries != 2 || claimed.logical_bytes != logical || claimed.quota_bytes != quota {out == Err(summary::Error::NonCanonical)}
        else {out matches Ok(leaf) && leaf.entries@ == seq![left,right] && leaf.totals == claimed}
    }),
{
    let mut rows = Vec::new(); rows.push(left); rows.push(right);
    proof {
        reveal_with_fuel(summary::usage,3);
        assert(rows@ =~= seq![left,right]);
        assert(summary::ordered(rows@,2) == crate::encoding::below(left.key@,right.key@));
    }
    summary::finish(rows,claimed)
}
}
