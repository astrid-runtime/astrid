//! A row begins after an arbitrary byte prefix and ends before an arbitrary suffix.
use crate::{ObjectId,ObjectRecord,ObjectReference,ReferenceKind,checkpoint_key_field as key,
    checkpoint_value::{ValueSlot,INLINE_VALUE_MAX},delta_mutation::{self as delta,Mutation,Operation},
    reference_lookup,storage_fields,storage_words};
use vstd::prelude::*;

verus! {

fn roundtrip(row:Mutation,index:usize,bytes:&mut Vec<u8>,refs:&mut Vec<ObjectReference>,tail:&[u8])
    requires row.key.len() <= u32::MAX, index <= u32::MAX,
        old(bytes).len()+row.payload().len()+tail.len() <= usize::MAX,
        match row.value {None => true,Some(ValueSlot::Inline(data)) => data.len() <= INLINE_VALUE_MAX,
            Some(ValueSlot::Spilled {length,..}) => length > INLINE_VALUE_MAX},
        forall|i:int| 0 <= i < old(refs).len() ==> {
            let label = (#[trigger] old(refs)@[i]).fields().0;
            label != delta::label_bytes(index as u32) && ObjectRecord::label_before(label,delta::label_bytes(index as u32))
        },
    ensures final(bytes)@ == old(bytes)@ + row.payload() + tail@,
{
    let start = bytes.len();
    let mut cursor = start;
    let first = refs.len();
    let wrote = row.append(index,bytes,refs);
    assert(wrote.is_ok());
    bytes.extend_from_slice(tail);
    assert(bytes@ =~= old(bytes)@ + row.payload() + tail@);
    let ghost tag = start as int+4+row.key.len();
    assert(bytes@.subrange(start as int,start as int+4) =~= storage_words::word32(row.key.len() as u32));
    assert(storage_fields::at(bytes@,start as int,storage_words::word32(row.key.len() as u32)));
    proof {key::encoded_length(bytes@,start as int,row.key.len() as u32);}
    let read_key = key::read(bytes,&mut cursor);
    assert(read_key matches Ok(k) && k@ == row.key@) by {
        assert(bytes@.subrange(start as int+4,tag) =~= row.key@);
    }
    assert(cursor == tag);
    let decoded = delta::read(bytes,&mut cursor);
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    match &row.value {
        None => {
            assert(bytes@[tag] == 0);
            assert(decoded matches Ok(Operation::Delete));
            assert(refs@ == old(refs)@);
        },
        Some(ValueSlot::Inline(data)) => {
            assert(bytes@[tag] == 1);
            assert(bytes@.subrange(tag+1,tag+9) =~= vstd::bytes::spec_u64_to_le_bytes(data.len() as u64));
            assert(bytes@.subrange(tag+9,tag+9+data.len()) =~= data@);
            assert(decoded matches Ok(Operation::Inline(got)) && got@ == data@);
            assert(refs@ == old(refs)@);
        },
        Some(ValueSlot::Spilled {object,length}) => {
            assert(bytes@[tag] == 2);
            assert(bytes@.subrange(tag+1,tag+9) =~= vstd::bytes::spec_u64_to_le_bytes(*length));
            assert(decoded matches Ok(Operation::Spill(n)) && n == *length);
            let ghost label = delta::label_bytes(index as u32);
            assert(refs@[first as int].fields() == (label,*object,ReferenceKind::Owns));
            assert(reference_lookup::positioned(refs@,label,first as int)) by {
                assert forall|i:int| 0 <= i < first implies (#[trigger] refs@[i]).fields().0 != label &&
                    ObjectRecord::label_before(refs@[i].fields().0,label) by {
                    assert(refs@[i] == refs@.drop_last()[i]);
                }
            }
            let target = delta::spill_object(refs,index);
            assert(target == Ok(*object));
        },
    }
    assert(cursor as int == start as int+row.payload().len());
    let mut consumed = start;
    let parsed = Mutation::decode(bytes,&mut consumed,refs,index,|_:&[u8]| -> (error:Option<()>)
        ensures error == None, {None});
    let Ok(actual) = parsed else {assert(false);return;};
    assert(actual.key@ == row.key@);
    match &row.value {
        None => assert(actual.value.is_none()),
        Some(ValueSlot::Inline(data)) => assert(actual.value matches Some(ValueSlot::Inline(got)) && got@ == data@),
        Some(ValueSlot::Spilled {object,length}) => assert(actual.value == Some(ValueSlot::Spilled {object:*object,length:*length})),
    }
    assert(consumed == cursor);

}

fn malformed_operation(bytes:&[u8],start:usize)
    requires !delta::valid(bytes@,start as int),
{
    let mut cursor = start;
    let decoded = delta::read(bytes,&mut cursor);
    assert(decoded.is_err());
}

/// A rejected key cannot produce a recovered mutation.
fn refused_key(bytes:&[u8],start:usize,refs:&[ObjectReference],index:usize,error:u64)
    requires start as int+4 <= bytes.len() && start as int+4+key::length(bytes@,start as int) <= bytes.len(),
{
    let mut cursor = start;
    let out = Mutation::decode(bytes,&mut cursor,refs,index,|_:&[u8]| -> (decision:Option<u64>)
        ensures decision == Some(error), {Some(error)});
    assert(out matches Err(delta::DecodeError::InvalidKey(e)) && e == error);
}

fn wrong_relation(refs:&[ObjectReference],index:usize)
    requires index <= u32::MAX, forall|i:int| 0 <= i < refs.len() ==>
        (#[trigger] refs@[i]).fields().0 != delta::label_bytes(index as u32) ||
        refs@[i].fields().2 != ReferenceKind::Owns,
{
    let result = delta::spill_object(refs,index);
    if let Ok(id) = result {
        let ghost edge = choose|r:ObjectReference| refs@.contains(r) &&
            #[trigger] r.fields() == (delta::label_bytes(index as u32),id,ReferenceKind::Owns);
        let ghost i = refs@.index_of(edge);
        assert(0 <= i < refs.len() && refs@[i] == edge);
        assert(false);
    }
}

fn label_layout(index:u32) {
    let result = delta::value_label(index as usize);
    let Some(label) = result else {assert(false);return;};
    let encoded = label.into_inner();
    assert(encoded@ =~= seq![b'v',b'a',b'l',b'u',b'e',b'/',(index >> 24) as u8,
        (index >> 16) as u8,(index >> 8) as u8,index as u8]) by {
        assert(((index >> 24) & 255) as u8 == (index >> 24) as u8 &&
            ((index >> 16) & 255) as u8 == (index >> 16) as u8 &&
            ((index >> 8) & 255) as u8 == (index >> 8) as u8 && (index & 255) as u8 == index as u8) by (bit_vector);
    }
}

#[verifier::rlimit(35)]
fn mixed_batch(object:ObjectId,trailing:bool,deny_second:bool) -> (out:Result<Vec<Mutation>,crate::delta_batch::Error<u8>>)
    ensures if deny_second {out == Err(crate::delta_batch::Error::Row(delta::DecodeError::InvalidKey(7u8)))}
        else if trailing {out == Err(crate::delta_batch::Error::Trailing)}
        else {out matches Ok(rows) && rows.len() == 2 && rows@[0].key@ == seq![110u8,0u8,97u8] &&
            (rows@[0].value matches Some(ValueSlot::Inline(v)) && v@ == seq![42u8]) &&
            rows@[1].key@ == seq![110u8,0u8,98u8] && rows@[1].value == Some(ValueSlot::Spilled {object,length:2048})},
{
    use crate::delta_batch::{self as batch,Error};
    let first = Mutation {key:vec![110u8,0,97],value:Some(ValueSlot::Inline(vec![42u8]))};
    let second = Mutation {key:vec![110u8,0,98],value:Some(ValueSlot::Spilled {object,length:2048})};
    let b = [110u8,0,98];
    let mut bytes = vec![1u8];
    let header = crate::delta_header::Header {depth:1,delta_bytes:2055,entries:2,quota_bytes:2055,count:2};
    header.append(&mut bytes);
    let mut refs = Vec::new();
    let one = first.append(0,&mut bytes,&mut refs);
    let two = second.append(1,&mut bytes,&mut refs);
    assert(one.is_ok() && two.is_ok());
    if trailing { bytes.push(0xff); }
    let check = |k:&[u8]| -> (err:Option<u8>) ensures err == if deny_second && k@ == b@ {Some(7u8)} else {None} {
        if deny_second && matches!(crate::encoding::bytewise_cmp(k,&b),std::cmp::Ordering::Equal) {Some(7u8)} else {None}
    };
    let raw = bytes.as_slice();
    let edges = refs.as_slice();
    let got = crate::delta_header::Header::read(raw);
    assert(got.is_ok()) by {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    let Ok((decoded,start)) = got else {unreached() };
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(raw@.subrange(1,37) =~= header.wire());
        assert(decoded.wire().subrange(32,36) =~= storage_words::word32(decoded.count));
        assert(header.wire().subrange(32,36) =~= storage_words::word32(header.count));
        storage_words::unique_word32(decoded.count,header.count);
    }
    let out = batch::read(raw,edges,start,decoded.count as usize,check);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(37,41) =~= storage_words::word32(3));
        assert(bytes@.subrange(54,58) =~= storage_words::word32(3));
        key::encoded_length(bytes@,37,3); key::encoded_length(bytes@,54,3);
        assert(bytes@.subrange(41,44) =~= first.key@);
        assert(bytes@.subrange(58,61) =~= b@);
        assert(bytes@[44] == 1 && bytes@[61] == 2);
        assert(bytes@.subrange(45,53) =~= vstd::bytes::spec_u64_to_le_bytes(1));
        assert(bytes@.subrange(53,54) =~= seq![42u8]);
        assert(bytes@.subrange(62,70) =~= vstd::bytes::spec_u64_to_le_bytes(2048));
        assert(refs.len() == 1 && refs@[0].fields() == (delta::label_bytes(1),object,ReferenceKind::Owns));
        assert(reference_lookup::selected(refs@,delta::label_bytes(1),0,1) == Some(refs@[0]));
        if out is Err {
            let e = out->Err_0;
            let (rows,p,end) = choose|rows:Seq<Mutation>,p:Seq<usize>,end:usize|
                #[trigger] batch::stopped(raw,edges,37,2,check,rows,p,end,e);
            if rows.len() > 0 {
                assert(delta::decoded(raw,p[0] as int,p[1],edges,0,check,Ok(rows[0])));
                assert(p[1] == 54);
            }
            if rows.len() == 2 {
                assert(delta::decoded(raw,p[1] as int,p[2],edges,1,check,Ok(rows[1])));
                assert(end == 70 && !deny_second && trailing && e is Trailing);
            } else {
                assert(rows.len() < 2 && e is Row);
                let finish = choose|finish:usize| #[trigger] delta::decoded(raw,end as int,finish,edges,rows.len() as usize,check,Err(e->Row_0));
                if rows.len() == 0 {assert(end == 37);} else {assert(end == 54);}
                assert(rows.len() == 1 && deny_second && e == Error::Row(delta::DecodeError::InvalidKey(7u8)));
            }
        } else {
            let rows = out->Ok_0;
            let p = choose|p:Seq<usize>| #[trigger] batch::layout(raw,edges,37,bytes.len(),rows@,p,check);
            assert(delta::decoded(raw,p[0] as int,p[1],edges,0,check,Ok(rows@[0])));
            assert(p[1] == 54);
            assert(delta::decoded(raw,p[1] as int,p[2],edges,1,check,Ok(rows@[1])));
        }
    }
    out
}

fn audit_mixed(object:ObjectId,previous:bool,edges:usize,limit:u64,duplicate:bool)
    -> (out:Result<(),crate::delta_batch::AuditError>)
    ensures out == if duplicate || limit < 2055 {Err(crate::delta_batch::AuditError::NonCanonical)}
        else if edges != (if previous {2usize} else {1usize}) {Err(crate::delta_batch::AuditError::References)}
        else {Ok(())},
{
    use crate::delta_batch as batch;
    let left = Mutation {key:vec![110u8,0,97],value:Some(ValueSlot::Inline(vec![42u8]))};
    let right = Mutation {key:vec![110u8,0,if duplicate {97} else {98}],value:Some(ValueSlot::Spilled {object,length:2048})};
    let rows = vec![left,right];
    proof {
        reveal_with_fuel(batch::usage,3);
        reveal_with_fuel(crate::encoding::below,5);
        assert(batch::usage(rows@,2) == (2055nat,1nat));
        assert(crate::encoding::below(rows@[0].key@,rows@[1].key@) == !duplicate);
        assert(batch::ordered(rows@) == !duplicate);
    }
    batch::audit(&rows,limit,previous,edges)
}

fn overflow_priority(object:ObjectId) {
    use crate::delta_batch as batch;
    let row = Mutation {key:vec![110u8,0,97],value:Some(ValueSlot::Spilled {object,length:u64::MAX})};
    let rows = vec![row];
    let verdict = batch::audit(&rows,u64::MAX,false,0);
    proof {reveal_with_fuel(batch::usage,2);}
    assert(verdict == Err(batch::AuditError::Overflow));
}

proof fn header_equal(h:crate::delta_header::Header,read:crate::delta_header::Header)
    requires h.wire() == read.wire(),
    ensures h == read,
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    assert(read.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(read.depth));
    assert(h.wire().subrange(0,8) =~= vstd::bytes::spec_u64_to_le_bytes(h.depth));
    assert(read.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(read.delta_bytes));
    assert(h.wire().subrange(8,16) =~= vstd::bytes::spec_u64_to_le_bytes(h.delta_bytes));
    assert(read.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(read.entries));
    assert(h.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(h.entries));
    assert(read.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(read.quota_bytes));
    assert(h.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(h.quota_bytes));
    assert(read.wire().subrange(32,36) =~= storage_words::word32(read.count));
    assert(h.wire().subrange(32,36) =~= storage_words::word32(h.count));
    storage_words::unique_word32(h.count,read.count);
}

/// The same fixed header is used by the KV delta record writer and the replay reader.
fn header_roundtrip(h:crate::delta_header::Header,tail:&[u8]) {
    use crate::delta_header::Header;
    let mut bytes = vec![1u8];
    h.append(&mut bytes);
    bytes.extend_from_slice(tail);
    let result = Header::read(&bytes);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(1,37) =~= h.wire());
        assert(result.is_ok());
        let (read,start) = result->Ok_0;
        header_equal(h,read);
        assert(read == h && start == 37);
        assert(bytes@.skip(start as int) =~= tail@);
    }
}

fn short_header(bytes:&[u8])
    requires bytes.len() < 37,
{
    let result = crate::delta_header::Header::read(bytes);
    assert(result == Err(storage_fields::ReadError::Truncated));
}

fn predecessor_roundtrip(previous:Option<ObjectId>,spill:ObjectId,kind:ReferenceKind) {
    use crate::delta_header::{self as header,EdgeError};
    let mut refs = header::predecessor_edges(previous);
    let row = Mutation {key:vec![110u8,0,97],value:Some(ValueSlot::Spilled {object:spill,length:2048})};
    let mut bytes = Vec::new();
    let append = row.append(0,&mut bytes,&mut refs);
    assert(append.is_ok());
    let recovered = header::predecessor(&refs);
    proof {
        reveal_with_fuel(reference_lookup::selected,3);
        assert(delta::label_bytes(0)[0] == 118 && header::PREVIOUS@[0] == 112);
        let a = delta::label_bytes(0);
        let b = header::PREVIOUS@;
        assert forall|j:int| 0 <= j < a.len() && j < b.len() && a.take(j) == b.take(j)
            implies !(#[trigger] a[j] < #[trigger] b[j]) by {
            if j > 0 { assert(a.take(j)[0] == a[0] && b.take(j)[0] == b[0]); }
        }
        assert(!ObjectRecord::label_before(a,b));
        assert(recovered == Ok(previous));
    }
    let edge = ObjectReference::new(header::predecessor_label(),spill,kind);
    let labelled = vec![edge];
    let actual = header::predecessor(&labelled);
    assert(actual == if kind is Owns {Ok(Some(spill))} else {Err(EdgeError::NonOwning)});
}

fn reconcile_charge(object:ObjectId,prior:u64,declared:u64,depth:u64,length:u64) {
    use crate::delta_recovery::{counters,CounterError};
    let rows = vec![Mutation {key:vec![110u8,0,97],value:Some(ValueSlot::Spilled {object,length})}];
    let measured = crate::delta_batch::measure(&rows);
    let outcome = counters(7,prior,depth,declared,&rows);
    proof {
        reveal_with_fuel(crate::delta_batch::usage,2);
        let size = 3nat + length as nat;
        assert(measured == if size > u64::MAX {None} else {Some((size as u64,1usize))});
        assert(outcome == if depth != 8 {Err(CounterError::Disagree)}
            else if size > u64::MAX {Err(CounterError::RowOverflow)}
            else if prior as nat + size > u64::MAX {Err(CounterError::ChainOverflow)}
            else if prior as nat + size != declared {Err(CounterError::Disagree)}
            else {Ok(())});
    }
}

fn recover_tombstone(previous:Option<ObjectId>,logical:u64,entries:u64,quota:u64,deny:bool) {
    use crate::{delta_batch as batch,delta_header as header,delta_recovery as recovery};
    let h = header::Header {depth:1,delta_bytes:3,entries,quota_bytes:quota,count:1};
    let mut bytes = vec![1u8];
    h.append(&mut bytes);
    let mut refs = header::predecessor_edges(previous);
    let row = Mutation {key:vec![110u8,0,97],value:None};
    let ok = row.append(0,&mut bytes,&mut refs);
    assert(ok.is_ok());
    let ghost wire = bytes@;
    let ghost links = refs@;
    let record = ObjectRecord::from_fields(crate::ObjectKind::NamespaceMap,crate::ObjectFormatVersion::new(4).unwrap(),
        bytes,refs,logical,crate::ObjectClass::Metadata).unwrap();
    let validate = |_k:&[u8]| -> (e:Option<u8>) ensures e == if deny {Some(7u8)} else {None} {
        if deny {Some(7u8)} else {None}
    };
    let got = recovery::decode(&record,validate);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(wire.subrange(1,37) =~= h.wire());
        assert(wire.subrange(37,41) =~= storage_words::word32(3));
        key::encoded_length(wire,37,3);
        assert(wire.subrange(41,44) =~= row.key@);
        assert(wire[44] == 0 && wire.len() == 45);
        if got is Ok {
            let r = got->Ok_0;
            let (b,l,p) = choose|b:&[u8],l:&[ObjectReference],p:Seq<usize>| #[trigger] recovery::admitted(&record,validate,r,b,l,p);
            let recorded = header::Header {depth:r.depth,delta_bytes:r.delta_bytes,entries:r.totals.entries,
                quota_bytes:r.totals.quota_bytes,count:r.rows.len() as u32};
            header_equal(h,recorded);
            assert(delta::decoded(b,37,p[1],l,0,validate,Ok(r.rows@[0])));
            assert(!deny && r.previous == previous && r.rows.len() == 1 && r.rows@[0].key@ == row.key@ && r.rows@[0].value.is_none());
            assert(r.totals.logical_bytes == logical && r.totals.entries == entries && r.totals.quota_bytes == quota);
        } else {
            let e = got->Err_0;
            assert(!(e is Truncated));
            let (hh,b,l) = choose|hh:header::Header,b:&[u8],l:&[ObjectReference]| b@ == wire && l@ == links &&
                #[trigger] recovery::refused(b,l,validate,hh,e);
            header_equal(h,hh);
            match e {
                recovery::Error::Batch(be) => {
                    let (rs,p,end) = choose|rs:Seq<Mutation>,p:Seq<usize>,end:usize| #[trigger] batch::stopped(b,l,37,1,validate,rs,p,end,be);
                    if rs.len() == 1 {
                        assert(delta::decoded(b,37,p[1],l,0,validate,Ok(rs[0])));
                        assert(end == 45);
                    } else if be is Row {
                        let stop = choose|stop:usize| #[trigger] delta::decoded(b,end as int,stop,l,0,validate,Err(be->Row_0));
                        assert(end == 37 && deny && be->Row_0 == delta::DecodeError::InvalidKey(7u8));
                    }
                    assert(deny && be == batch::Error::Row(delta::DecodeError::InvalidKey(7u8)));
                },
                recovery::Error::Audit(ae) => {
                    let (rs,p) = choose|rs:Seq<Mutation>,p:Seq<usize>| rs.len()==1 &&
                        #[trigger] batch::layout(b,l,37,45,rs,p,validate) && recovery::audit_refusal(rs,3,previous.is_some(),l.len() as nat,ae);
                    assert(delta::decoded(b,37,p[1],l,0,validate,Ok(rs[0])));
                    assert(rs[0].key@ == row.key@ && rs[0].value.is_none());
                    reveal_with_fuel(batch::usage,2);
                    assert(false);
                },
                _ => assert(false),
            }
        }
    }
}
}
