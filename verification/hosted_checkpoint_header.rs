//! Raw persisted bytes determine the fixed header and the branch released by the decoder.
use crate::{encoding,ObjectId,ObjectReference,checkpoint_branch::{self,Header},checkpoint_header::{self as header,Kind},
    checkpoint_page::Branch,checkpoint_summary,checkpoint_totals::NodeTotals,storage_fields::at};
use vstd::prelude::*;

verus! {

proof fn unique_word(a:u16,b:u16)
    requires header::word(a) == header::word(b),
    ensures a == b,
{
    assert(a == b) by (bit_vector)
        requires (a&255) as u8 == (b&255) as u8, (a>>8) as u8 == (b>>8) as u8;
}

pub(super) proof fn unique(kind:Kind,a:Header,b:Header)
    requires header::wire(kind,a) == header::wire(kind,b), a.count <= u16::MAX,b.count <= u16::MAX,
    ensures a.count == b.count && a.totals == b.totals && (kind is Branch ==> a.level == b.level),
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    let start = kind.tag().len() as int;
    if kind is Branch {
        assert(header::wire(kind,a).subrange(start,start+2) =~= header::word(a.level));
        assert(header::wire(kind,b).subrange(start,start+2) =~= header::word(b.level));
        unique_word(a.level,b.level);
    }
    let pos = if kind is Branch { start+2 } else { start };
    assert(header::wire(kind,a).subrange(pos,pos+2) =~= header::word(a.count as u16));
    assert(header::wire(kind,b).subrange(pos,pos+2) =~= header::word(b.count as u16));
    unique_word(a.count as u16,b.count as u16);
    assert(header::wire(kind,a).subrange(pos+2,pos+26) =~= a.totals.wire());
    assert(header::wire(kind,b).subrange(pos+2,pos+26) =~= b.totals.wire());
    crate::hosted_checkpoint_totals::same(a.totals,b.totals);
}

fn roundtrip(kind:Kind,h:Header,tail:&[u8]) -> (out:Result<(usize,Header),header::Error>)
    requires h.count <= u16::MAX, header::wire(kind,h).len() + tail.len() <= usize::MAX,
    ensures out matches Ok(pair) && pair.0 == header::wire(kind,h).len() && pair.1.count == h.count &&
        pair.1.totals == h.totals && pair.1.level == (if kind is Branch {h.level} else {0u16}),
{
    let mut bytes = Vec::new();
    header::append(&mut bytes,kind,h);
    bytes.extend_from_slice(tail);
    let out = header::read(&bytes,kind);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.take(kind.tag().len() as int) =~= kind.tag());
        if out is Ok {
            let got = out->Ok_0.1;
            assert(header::wire(kind,h).len() == header::wire(kind,got).len());
            assert(bytes@.take(header::wire(kind,h).len() as int) =~= header::wire(kind,h));
            unique(kind,h,got);
        }
    }
    out
}

fn accepted(bytes:&[u8],refs:&[ObjectReference]) -> (out:Result<Branch<ObjectId,NodeTotals>,header::RecordError<()>>)
    ensures out matches Ok(b) ==> ({
        let h = Header {level:b.level,count:b.children.len(),totals:b.totals};
        &&& at(bytes@,0,header::wire(Kind::Branch,h)) && h.valid(refs.len())
        &&& checkpoint_summary::ordered(b.children@,h.count as nat)
        &&& checkpoint_summary::counts(b.children@,h.count as nat) ==
            (h.totals.entries as nat,h.totals.logical_bytes as nat,h.totals.quota_bytes as nat)
        &&& forall|i:int| 0 <= i < refs.len() ==> (#[trigger] b.children@[i]).object == refs@[i].fields().1
    }),
{
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let out = header::branch(bytes,refs,accept);
    proof {
        if out is Ok {
            let b = out->Ok_0;
            let (h,s) = choose|h:Header,s:usize| #[trigger] header::present(bytes@,Kind::Branch,h,s) &&
                h.outcome(bytes,refs,s,accept,Ok(b));
            let p = choose|p:Seq<usize>| #[trigger] checkpoint_branch::layout(bytes@,refs@,s,bytes.len(),h.level,b.children@,p,accept);
            assert forall|i:int| 0 <= i < refs.len() implies (#[trigger] b.children@[i]).object == refs@[i].fields().1 by {
                assert(checkpoint_branch::row_at(bytes@,refs@,i,p[i],p[i+1],h.level,b.children@[i],accept));
            }
        }
    }
    out
}

fn malformed(bytes:&[u8],kind:Kind) -> (out:Result<(usize,Header),header::Error>)
    requires bytes.len() < kind.tag().len() + (if kind is Branch {2int} else {0int}) + 26 ||
        bytes@.take(kind.tag().len() as int) != kind.tag(),
    ensures out == if bytes.len() >= kind.tag().len() && bytes@.take(kind.tag().len() as int) != kind.tag() {
        Err(header::Error::Magic)
    } else { Err(header::Error::Field(crate::storage_fields::ReadError::Truncated)) },
{
    let out = header::read(bytes,kind);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        if out is Ok {
            let h = out->Ok_0.1;
            assert(header::wire(kind,h).take(kind.tag().len() as int) =~= kind.tag());
            crate::storage_fields::subfield(bytes@,0,header::wire(kind,h),0,kind.tag().len() as int);
        }
    }
    out
}
fn read_branch<F:Fn(&[u8])->Result<(),()>+Copy>(id:ObjectId,object:&crate::ObjectRecord,
    version:crate::ObjectFormatVersion,accept:F) -> (out:Result<Branch<ObjectId,NodeTotals>,header::RecordError<()>>)
    requires forall|k:&[u8]| #[trigger] accept.requires((k,)), object.contents().0 == crate::ObjectKind::KvBranch,
        object.contents().1 == version.number(),object.contents().4 == 0,object.contents().5 == crate::ObjectClass::Metadata,
        object.retained_cost() <= 4096,
    ensures match out {
        Err(header::RecordError::Prefix(e)) => header::prefix_error(object.contents().2,Kind::Branch,e),
        Err(header::RecordError::Body(e)) => exists|h:Header,s:usize| #[trigger] header::present(object.contents().2,Kind::Branch,h,s) &&
            h.field_outcome(object.contents().2,object.contents().3,s,accept,Err(e)),
        Ok(b) => exists|h:Header,s:usize| #[trigger] header::present(object.contents().2,Kind::Branch,h,s) &&
            h.field_outcome(object.contents().2,object.contents().3,s,accept,Ok(b)),
    },
{
    match crate::checkpoint_record::read(id,object,version,accept) {
        Ok(h) => { assert(h.object == id); match h.node {
            crate::checkpoint_page::Node::Branch(b) => Ok(b),
            crate::checkpoint_page::Node::Leaf(_) => { assert(false); unreachable!() },
        }},
        Err(crate::checkpoint_record::ReadError::Branch(e)) => Err(e),
        Err(_) => { assert(false); unreachable!() },
    }
}

#[verifier::spinoff_prover]
#[verifier::rlimit(45)]
fn complete(left:ObjectId,right:ObjectId,id:ObjectId,v:crate::ObjectFormatVersion,integrated:bool) -> (out:Result<Branch<ObjectId,NodeTotals>,header::RecordError<()>>)
    ensures out matches Ok(b) && b.children.len() == 2 && b.level == 1 && b.children@[0].object == left &&
        b.children@[1].object == right && b.totals.entries == 2,
{
    use crate::checkpoint_reference::{label,Relation};
    use crate::checkpoint_key_field as key;
    let totals = NodeTotals {entries:1,logical_bytes:8,quota_bytes:11};
    let h = Header {level:1,count:2,totals:NodeTotals {entries:2,logical_bytes:16,quota_bytes:22}};
    let mut bytes = Vec::new();
    let mut refs = Vec::new();
    header::append(&mut bytes,Kind::Branch,h);
    let start = bytes.len();
    let a = [110u8,0,97];
    let b = [110u8,0,98];
    key::append(&mut bytes,&a);
    totals.append(&mut bytes);
    let middle = bytes.len();
    key::append(&mut bytes,&b);
    totals.append(&mut bytes);
    refs.push(ObjectReference::owns(label(Relation::Child,0).unwrap(),left));
    refs.push(ObjectReference::owns(label(Relation::Child,1).unwrap(),right));
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let a = refs@[0].fields().0; let b = refs@[1].fields().0;
        assert(a.take(7) =~= b.take(7));
        assert(a[7] < b[7]);
        assert(crate::ObjectRecord::label_before(a,b));
        assert(crate::ObjectRecord::labels_ordered(refs@));
        assert(h.totals.wire().len() == 24 && totals.wire().len() == 24);
        assert(bytes.len() <= 256);
    }
    let ghost payload = bytes@;
    let ghost links = refs@;
    let object = crate::ObjectRecord::from_fields(crate::ObjectKind::KvBranch,v,bytes,refs,0,crate::ObjectClass::Metadata).unwrap();
    assert(object.retained_cost() <= 4096) by {reveal_with_fuel(crate::ObjectRecord::reference_charge,3);}
    let bytes = object.canonical_bytes(); let refs = object.references();
    assert(bytes@ == payload && refs@ == links);
    let data = bytes; let edges = refs;
    let out = if integrated {read_branch(id,&object,v,accept)} else {header::branch(data,edges,accept)};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let first = start as int; let second = middle as int;
        assert(bytes@.subrange(0,first) =~= header::wire(Kind::Branch,h));
        assert(bytes@.take(Kind::Branch.tag().len() as int) =~= Kind::Branch.tag());
        assert(bytes@.subrange(first,first+4) =~= crate::storage_words::word32(3));
        assert(bytes@.subrange(second,second+4) =~= crate::storage_words::word32(3));
        key::encoded_length(bytes@,first,3); key::encoded_length(bytes@,second,3);
        assert(bytes@.subrange(first+4,first+7) =~= a@);
        assert(bytes@.subrange(second+4,second+7) =~= b@);
        assert(bytes@.subrange(first+7,first+31) =~= totals.wire());
        assert(bytes@.subrange(second+7,second+31) =~= totals.wire());
        reveal_with_fuel(encoding::below,4);
        assert(encoding::below(a@,b@));
        if let Err(header::RecordError::Body(reason)) = &out {
            let (got,s) = choose|got:Header,s:usize| #[trigger] header::present(bytes@,Kind::Branch,got,s) &&
                got.outcome(data,edges,s,accept,Err(*reason));
            assert(header::wire(Kind::Branch,got).len() == first);
            unique(Kind::Branch,h,got);
            assert(s == start && got == h);
            if let checkpoint_branch::DecodeError::Rows(error) = reason {
                let (rows,pos,at,bad) = choose|rows:Seq<crate::checkpoint_range::Child<ObjectId,NodeTotals>>,pos:Seq<usize>,at:usize,bad:usize|
                    rows.len() < 2 && #[trigger] checkpoint_branch::layout(bytes@,refs@,s,at,1,rows,pos,accept) &&
                    #[trigger] checkpoint_branch::rejected_row(bytes@,refs@,rows.len() as usize,at,bad,accept,*error);
                if rows.len() > 0 { assert(checkpoint_branch::row_at(bytes@,refs@,0,pos[0],pos[1],1,rows[0],accept)); }
                assert(at as int == if rows.len()==0 {first} else {second});
                assert(rows.len() == 0 || rows.len() == 1);
                assert(at as int+7+24 <= bytes.len());
                if *error matches checkpoint_branch::RowsError::Child(crate::checkpoint_child::ChildError::Empty) {
                    let empty = choose|t:NodeTotals| t.entries == 0 && crate::storage_fields::at(bytes@,at as int+7,#[trigger] t.wire());
                    crate::hosted_checkpoint_totals::same(empty,totals);
                }
                assert(false);
            }
            if let checkpoint_branch::DecodeError::Finish(error) = reason {
                let (rows,pos,end) = choose|rows:Vec<crate::checkpoint_range::Child<ObjectId,NodeTotals>>,pos:Seq<usize>,end:usize|
                    rows.len() == 2 && #[trigger] checkpoint_branch::layout(bytes@,refs@,s,end,1,rows@,pos,accept) &&
                    checkpoint_summary::finished(end,bytes.len(),1,rows,h.totals) == Err(*error);
                assert(checkpoint_branch::row_at(bytes@,refs@,0,pos[0],pos[1],1,rows@[0],accept));
                assert(checkpoint_branch::row_at(bytes@,refs@,1,pos[1],pos[2],1,rows@[1],accept));
                crate::hosted_checkpoint_totals::same(rows@[0].totals,totals);
                crate::hosted_checkpoint_totals::same(rows@[1].totals,totals);
                reveal_with_fuel(checkpoint_summary::counts,3);
                assert(checkpoint_summary::ordered(rows@,2));
                assert(checkpoint_summary::counts(rows@,2) == (2nat,16nat,22nat));
                assert(end == bytes.len());
                assert(false);
            }
        }
        if out matches Err(header::RecordError::Prefix(_)) { assert(false); }
        if out is Ok {
            let decoded = out->Ok_0;
            let (got,s) = choose|got:Header,s:usize| #[trigger] header::present(bytes@,Kind::Branch,got,s) &&
                got.outcome(data,edges,s,accept,Ok(decoded));
            assert(header::wire(Kind::Branch,got).len() == first);
            unique(Kind::Branch,h,got);
            let pos = choose|p:Seq<usize>| #[trigger] checkpoint_branch::layout(bytes@,refs@,s,bytes.len(),1,decoded.children@,p,accept);
            assert(checkpoint_branch::row_at(bytes@,refs@,0,pos[0],pos[1],1,decoded.children@[0],accept));
            assert(checkpoint_branch::row_at(bytes@,refs@,1,pos[1],pos[2],1,decoded.children@[1],accept));
        }
    }
    out
}
}
