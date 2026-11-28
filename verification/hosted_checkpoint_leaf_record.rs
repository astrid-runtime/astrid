//! A serialized leaf accepts exactly the quota advertised for its actual key and value bytes.
use crate::{ObjectReference,checkpoint_branch::Header,checkpoint_entries::{self as entries,Row},
    checkpoint_header::{self as header,Kind},checkpoint_key_field as key,checkpoint_leaf_record::{self as record,Error},
    checkpoint_leaf_summary as summary,checkpoint_totals::NodeTotals,checkpoint_value::{self as value,ValueSlot}};
use vstd::prelude::*;

verus! {

fn read_leaf<F:Fn(&[u8])->Result<(),()>+Copy>(id:crate::ObjectId,object:&crate::ObjectRecord,
    version:crate::ObjectFormatVersion,accept:F,warm:bool) -> (out:Result<record::DecodedLeaf,Error<()>>)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|k:&[u8]| #[trigger] accept.requires((k,)), object.contents().0 == crate::ObjectKind::KvLeaf,
        object.contents().1 == version.number(),object.contents().4 == 0,object.contents().5 == crate::ObjectClass::Metadata,
        object.retained_cost() <= 4096,
    ensures match out {
        Err(Error::Prefix(e)) => header::prefix_error(object.contents().2,Kind::Leaf,e),
        _ => exists|h:Header,s:usize| #[trigger] header::present(object.contents().2,Kind::Leaf,h,s) &&
            record::body(object.contents().2,object.contents().3,s,h,accept,out),
    },
{
    let owner = 31u64;
    let mut cache = crate::checkpoint_cache::Cache::new(&owner);
    let got = if warm {cache.admit(id,object,version,accept)} else {crate::checkpoint_record::read(id,object,version,accept)};
    match got {
        Ok(handle) => {
            assert(handle.object == id);
            if warm {
                let hit = cache.lookup(id,version,|_:&u64,_:crate::ObjectId| -> (r:Result<crate::ObjectRecord,()>)
                    ensures r == Err(()) { Err(()) },accept);
                assert(hit.is_ok() && crate::checkpoint_cache::image(hit->Ok_0) == crate::checkpoint_cache::image(handle));
                assert(crate::checkpoint_record::ordered(hit->Ok_0.node));
            }
            match handle.node {
                crate::checkpoint_page::Node::Leaf(l) => Ok(l),
                crate::checkpoint_page::Node::Branch(_) => { assert(false); unreachable!() },
            }
        },
        Err(crate::checkpoint_record::ReadError::Leaf(e)) => Err(e),
        Err(_) => {
            assert(false); unreachable!()
        },
    }
}

fn cold_read(owner:&u64,id:crate::ObjectId,object:crate::ObjectRecord,version:crate::ObjectFormatVersion)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
{
    use crate::{checkpoint_cache::{Cache,Error},checkpoint_record};
    let mut cache = Cache::new(owner);
    let validate = |_:&[u8]| -> (r:Result<(),u8>) ensures r == Ok(()) {Ok(())};
    let ghost expected = object;
    let fetch = |p:&u64,k:crate::ObjectId| -> (result:Result<crate::ObjectRecord,u8>)
        requires p == owner && k == id, ensures result == Ok(expected), {Ok(object)};
    let got = cache.lookup(id,version,fetch,validate);
    match got {
        Ok(h) => {
            assert(checkpoint_record::parsed(&expected,h.node,validate));
            assert(expected.contents().1 == version.number());
        },
        Err(Error::Decode(e)) => {
            assert(checkpoint_record::refusal(&expected,validate,e));
            assert(cache.contents().is_empty());
        },
        Err(Error::Load(_)) => {assert(false);},
    }
}

// A failed read at another address leaves the warmed page available to its owner.
fn isolated<'a>(owner:&'a u64,id:crate::ObjectId,other:crate::ObjectId,object:&crate::ObjectRecord,
    version:crate::ObjectFormatVersion)
    requires id != other, vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
{
    use crate::checkpoint_cache::{Cache,Error,image};
    let mut cache = Cache::new(owner);
    let accept = |_:&[u8]| -> (r:Result<(),u8>) ensures r == Ok(()) {Ok(())};
    let original = match cache.admit(id,object,version,accept) { Ok(h) => h,Err(_) => return };
    let fail = |p:&u64,k:crate::ObjectId| -> (r:Result<crate::ObjectRecord,u8>)
        requires *p == *owner && k == other, ensures r == Err(7u8), {Err(7)};
    let missing = cache.lookup(other,version,fail,accept);
    assert(missing == Err(Error::Load(7u8)));
    let disabled = |_:&u64,_:crate::ObjectId| -> (r:Result<crate::ObjectRecord,u8>) ensures r == Err(9u8), {Err(9)};
    let hit = cache.lookup(id,version,disabled,accept);
    assert(hit.is_ok() && image(hit->Ok_0) == image(original) && hit->Ok_0.object == id);
}

#[verifier::spinoff_prover]
#[verifier::rlimit(90)]
fn written(claim:u64,id:crate::ObjectId,version:crate::ObjectFormatVersion,integrated:bool,warm:bool) -> (out:Result<record::DecodedLeaf,Error<()>>)
    requires vstd::laws_cmp::obeys_cmp::<crate::ObjectId>(), vstd::laws_cmp::obeys_cmp_concrete_eq::<crate::ObjectId>(),
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
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(h.totals.wire().len() == 24);
        assert(first == 24+2+24);
        assert(bytes.len() == first+17);
        assert(refs.len() == 0);
    }
    let ghost payload = bytes@;
    let ghost links = refs@;
    let object = crate::ObjectRecord::from_fields(crate::ObjectKind::KvLeaf,version,bytes,refs,0,crate::ObjectClass::Metadata).unwrap();
    assert(object.retained_cost() <= 4096) by {reveal_with_fuel(crate::ObjectRecord::reference_charge,1);}
    let bytes = object.canonical_bytes(); let refs = object.references();
    let out = if integrated {read_leaf(id,&object,version,accept,warm)} else {record::read(bytes,refs,accept)};
    assert(bytes@ == payload && refs@ == links);
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
