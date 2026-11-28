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
    let header = crate::delta_header::Header {depth:1,delta_bytes:2055,entries:2,quota_bytes:2055,count:2};
    let rows=vec![first,second];
    let totals=crate::checkpoint_totals::NodeTotals{entries:2,logical_bytes:2049,quota_bytes:2055};
    let version=crate::ObjectFormatVersion::new(crate::header_graph::CURRENT_VERSION).unwrap();
    proof {
        reveal_with_fuel(batch::usage,3);
        reveal_with_fuel(crate::encoding::below,5);
        assert(batch::ordered(rows@));
        assert(batch::usage(rows@,2)==(2055nat,1nat));
        assert forall|i:int| 0<=i<rows.len() implies !crate::delta_writer::invalid_row(rows@[i],delta::WriteError::Overflow) &&
            !crate::delta_writer::invalid_row(rows@[i],delta::WriteError::Oversized) &&
            !crate::delta_writer::invalid_row(rows@[i],delta::WriteError::SmallSpill) by {if i!=0 {assert(i==1);}}
    }
    let record=match crate::delta_writer::record(version,None,0,0,&rows,totals) {Ok(r)=>r,Err(_)=>{assert(false);unreached()}};
    let mut bytes=Vec::new();
    bytes.extend_from_slice(record.canonical_bytes());
    let refs=record.references();
    proof {
        reveal_with_fuel(crate::delta_writer::body_prefix,3);
        reveal_with_fuel(crate::delta_writer::edge_prefix,3);
        assert(bytes@ == seq![1u8]+header.wire()+crate::delta_writer::body_prefix(rows@,2));
        assert(refs@.map_values(crate::delta_writer::ref_fields()).len()==refs.len());
        assert(refs@.map_values(crate::delta_writer::ref_fields())[0]==refs@[0].fields());
    }
    if trailing { bytes.push(0xff); }
    let check = |k:&[u8]| -> (err:Option<u8>) ensures err == if deny_second && k@ == b@ {Some(7u8)} else {None} {
        if deny_second && matches!(crate::encoding::bytewise_cmp(k,&b),std::cmp::Ordering::Equal) {Some(7u8)} else {None}
    };
    let raw = bytes.as_slice();
    let edges = refs;
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
        assert(bytes@.subrange(41,44) =~= rows@[0].key@);
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

/// Inspect the serialized one-row write, independent of the recovered row or its decoder.
pub(crate) open spec fn marker_bytes(bytes:Seq<u8>,address:Seq<u8>) -> bool {
    let tag=41+address.len() as int;
    &&& address.len()<=u32::MAX
    &&& bytes.len()==51+address.len()
    &&& bytes[0]==crate::projection_record::DELTA
    &&& bytes.subrange(33,37)==storage_words::word32(1)
    &&& bytes.subrange(37,41)==storage_words::word32(address.len() as u32)
    &&& bytes.subrange(41,tag)==address && bytes[tag]==delta::INLINE
    &&& bytes.subrange(tag+1,tag+9)==vstd::bytes::spec_u64_to_le_bytes(1)
    &&& bytes.subrange(tag+9,bytes.len() as int)==seq![1u8]
}

/// Cursor movement uses the operation tag and skips an inline value's entire payload.
pub(crate) open spec fn row_end(bytes:Seq<u8>,at:usize) -> int {
    let tag=at as int+4+key::length(bytes,at as int);
    if bytes[tag]==delta::DELETE {tag+1} else if bytes[tag]==delta::INLINE {
        tag+9+crate::checkpoint_value::value_length(bytes,tag+1)
    } else {tag+9}
}

pub(crate) open spec fn spans(bytes:Seq<u8>,offsets:Seq<usize>) -> bool {
    &&& offsets.len()>0 && offsets[0]==37 && offsets.last()==bytes.len()
    &&& forall|i:int| 0<=i<offsets.len()-1 ==> offsets[i]<bytes.len() && offsets[i+1]==row_end(bytes,#[trigger] offsets[i])
}

pub(crate) open spec fn untouched_link(record:&ObjectRecord,next:ObjectId,address:Seq<u8>) -> bool {
    let bytes=record.contents().2;
    let refs=record.contents().3;
    &&& bytes.len()>=37 && bytes[0]==crate::projection_record::DELTA
    &&& reference_lookup::selected(refs,crate::delta_header::PREVIOUS@,0,refs.len() as int) matches Some(edge) &&
        edge.fields().1==next && edge.fields().2==ReferenceKind::Owns
    &&& forall|offsets:Seq<usize>,i:int| #[trigger] spans(bytes,offsets) && 0<=i<offsets.len()-1 ==>
        bytes.subrange((#[trigger] offsets[i]) as int+4,offsets[i] as int+4+key::length(bytes,offsets[i] as int))!=address
}

proof fn absent_rows(rows:Seq<Mutation>,n:nat,address:Seq<u8>)
    requires n<=rows.len(),forall|i:int| 0<=i<n ==> (#[trigger] rows[i]).key@!=address,
    ensures crate::overlay_batch::after_rows(rows,n,address,None).is_none(),
    decreases n,
{
    if n>0 {absent_rows(rows,(n-1) as nat,address);}
}

pub(crate) proof fn decoded_link<E,F:Fn(&[u8])->Option<E>>(record:&ObjectRecord,next:ObjectId,address:Seq<u8>,
    v:crate::ObjectFormatVersion,label:&[u8],check:F,head:crate::delta_chain::Head)
    requires untouched_link(record,next,address),crate::projection_record::valid(record,v,label,check,Ok(head)),
    ensures head matches crate::delta_chain::Head::Delta{previous,mutations,..} && previous==Some(next) &&
        crate::overlay_batch::after_rows(mutations@,mutations.len() as nat,address,None).is_none(),
{
    if let crate::delta_chain::Head::Delta{previous,depth,delta_bytes,mutations,totals}=head {
        let saved=crate::delta_recovery::Recovered{previous,depth,delta_bytes,rows:mutations,totals};
        let (bs,rs,path)=choose|bs:&[u8],rs:&[ObjectReference],p:Seq<usize>| #[trigger] crate::delta_recovery::admitted(record,check,saved,bs,rs,p);
        assert forall|i:int| 0<=i<path.len()-1 implies path[i]<bs.len() && path[i+1]==row_end(bs@,#[trigger] path[i]) by {
            assert(delta::decoded(bs,path[i] as int,path[i+1],rs,i as usize,check,Ok(mutations@[i])));
        }
        assert(spans(bs@,path));
        assert forall|i:int| 0<=i<mutations.len() implies (#[trigger] mutations@[i]).key@!=address by {
            assert(delta::decoded(bs,path[i] as int,path[i+1],rs,i as usize,check,Ok(mutations@[i])));
        }
        absent_rows(mutations@,mutations.len() as nat,address);
    }
}

pub(crate) proof fn decoded_marker<E,F:Fn(&[u8])->Option<E>>(record:&ObjectRecord,address:Seq<u8>,
    v:crate::ObjectFormatVersion,label:&[u8],check:F,head:crate::delta_chain::Head)
    requires marker_bytes(record.contents().2,address),crate::projection_record::valid(record,v,label,check,Ok(head)),
    ensures head matches crate::delta_chain::Head::Delta{mutations,..} && mutations.len()==1 &&
        mutations@[0].key@==address && (mutations@[0].value matches Some(ValueSlot::Inline(data)) && data@==seq![1u8]) &&
        crate::overlay_batch::after_rows(mutations@,1,address,None)==Some(true),
{
    use crate::{delta_chain::Head,delta_recovery as recovery,delta_header::Header};
    if let Head::Delta{previous,depth,delta_bytes,mutations,totals}=head {
        let saved=recovery::Recovered{previous,depth,delta_bytes,rows:mutations,totals};
        let (bs,rs,path)=choose|bs:&[u8],rs:&[ObjectReference],p:Seq<usize>| #[trigger] recovery::admitted(record,check,saved,bs,rs,p);
        assert(bs@==record.contents().2 && 0<mutations.len()<=u32::MAX);
        let h=Header{depth,delta_bytes,entries:totals.entries,quota_bytes:totals.quota_bytes,count:mutations.len() as u32};
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(h.wire().subrange(32,36) =~= storage_words::word32(h.count));
        assert(bs@.subrange(33,37) =~= h.wire().subrange(32,36));
        storage_words::unique_word32(h.count,1);
        assert(mutations.len()==1);
        assert(delta::decoded(bs,37,path[1],rs,0,check,Ok(mutations@[0])));
        let n=address.len() as int;
        assert(bs@.subrange(37,41) =~= storage_words::word32(n as u32));
        key::encoded_length(bs@,37,n as u32);
        assert(bs@.subrange(41,41+n) =~= address);
        assert(bs@[41+n]==delta::INLINE && bs@.subrange(42+n,50+n) =~= vstd::bytes::spec_u64_to_le_bytes(1));
        assert(bs@.subrange(50+n,51+n) =~= seq![1u8]);
        assert(mutations@[0].key@==address && (mutations@[0].value matches Some(ValueSlot::Inline(data)) && data@==seq![1u8]));
        reveal_with_fuel(crate::overlay_batch::after_rows,2);
    } else {assert(false);}
}

// Reopen the physical record produced for a single presence marker, including
// the prior component edge. Its address and one-byte value survive the round trip.
#[verifier::spinoff_prover]
#[verifier::rlimit(40)]
pub(super) fn written_marker(key:Vec<u8>,previous:Option<ObjectId>,prior_depth:u64,prior_bytes:u64,totals:crate::checkpoint_totals::NodeTotals) -> (out:(crate::ObjectRecord,crate::delta_chain::Head))
    requires key.len()<=u32::MAX && key.len()+51<=isize::MAX && prior_depth<u64::MAX && prior_bytes+key.len()+1<=u64::MAX,
    ensures previous matches Some(id) ==> (out.0.contents().3.len()==1 &&
        out.0.contents().3[0].fields()==(crate::delta_header::PREVIOUS@,id,ReferenceKind::Owns)),
        marker_bytes(out.0.contents().2,key@), out.1 matches crate::delta_chain::Head::Delta{previous:p,depth,delta_bytes,mutations,totals:t} && p==previous && depth==prior_depth+1 && delta_bytes==prior_bytes+key.len()+1 && t==totals && mutations.len()==1 &&
        mutations@[0].key@==key@ && (mutations@[0].value matches Some(ValueSlot::Inline(v)) && v@==seq![1u8]),
{
    use crate::{delta_recovery as recovery,delta_batch as batch,projection_record as format,delta_chain::Head,delta_header::Header};
    let ghost address=key@;
    let width=key.len();
    let charge=(width as u64).saturating_add(1);

    let rows=vec![Mutation{key,value:Some(ValueSlot::Inline(vec![crate::token_authority::PRESENCE_MARKER[0]]))}];
    let version=crate::ObjectFormatVersion::new(crate::header_graph::CURRENT_VERSION).unwrap();
    proof {
        reveal_with_fuel(batch::usage,2);
        assert(batch::usage(rows@,1)==(charge as nat,0nat));
        assert(batch::ordered(rows@));
    }
    let record=match crate::delta_writer::record(version,previous,prior_depth,prior_bytes,&rows,totals) {Ok(r)=>r,Err(_)=>{assert(false);unreached()}};
    let header=Header{depth:prior_depth.saturating_add(1),delta_bytes:prior_bytes.saturating_add(charge),entries:totals.entries,quota_bytes:totals.quota_bytes,count:1};
    let bytes=record.canonical_bytes();let refs=record.references();
    let check=|_:&[u8]| -> (r:Option<u8>) ensures r.is_none(), {None};
    let decoded=format::decode(&record,version,b"root",check);
    let ghost result=decoded;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        reveal_with_fuel(crate::delta_writer::body_prefix,2);
        reveal_with_fuel(crate::delta_writer::edge_prefix,2);
        assert(bytes@.subrange(1,37) =~= header.wire());
        assert(bytes@.subrange(33,37) =~= storage_words::word32(1));
        assert(bytes@.subrange(37,41) =~= storage_words::word32(width as u32));
        key::encoded_length(bytes@,37,width as u32);
        let tag=41+width;
        assert(bytes@.subrange(41,tag) =~= address);
        assert(bytes@[tag]==delta::INLINE && bytes@.subrange(tag+1,tag+9) =~= vstd::bytes::spec_u64_to_le_bytes(1));
        assert(bytes@.subrange(tag+9,bytes.len() as int) =~= seq![1u8]);
        assert(marker_bytes(record.contents().2,address));
        assert(refs@.map_values(crate::delta_writer::ref_fields()).len()==refs.len());
        if previous.is_some() {
            assert(refs@.map_values(crate::delta_writer::ref_fields())[0]==refs@[0].fields());
            assert(reference_lookup::selected(refs@,crate::delta_header::PREVIOUS@,0,1)==Some(refs@[0]));


        }
        assert forall|bs:&[u8],rs:&[ObjectReference],end:usize,out:Result<Mutation,delta::DecodeError<u8>>|
            bs@==bytes@ && rs@==refs@ && #[trigger] delta::decoded(bs,37,end,rs,0,check,out)
            implies out matches Ok(m) && m.key@==address && (m.value matches Some(ValueSlot::Inline(v)) && v@==seq![1u8]) && end==bytes.len() by {};
        if let Ok(Head::Delta{previous:p,depth,delta_bytes,mutations,totals:n})=result {
            let h=Header{depth,delta_bytes,entries:n.entries,quota_bytes:n.quota_bytes,count:mutations.len() as u32};
            let recovered=recovery::Recovered{previous:p,depth,delta_bytes,rows:mutations,totals:n};
            let (bs,rs,path)=choose|bs:&[u8],rs:&[ObjectReference],path:Seq<usize>| #[trigger] recovery::admitted(&record,check,recovered,bs,rs,path);
            header_equal(header,h);
            assert(delta::decoded(bs,37,path[1],rs,0,check,Ok(mutations@[0])));
        } else if let Err(format::Error::Delta(e))=result {
            let (h,bs,rs)=choose|h:Header,bs:&[u8],rs:&[ObjectReference]| bs@==bytes@ && rs@==refs@ && #[trigger] recovery::refused(bs,rs,check,h,e);
            header_equal(header,h);
            match e {
                recovery::Error::Batch(err)=>{
                    let (done,path,end)=choose|done:Seq<Mutation>,path:Seq<usize>,end:usize| #[trigger] batch::stopped(bs,rs,37,1,check,done,path,end,err);
                    if done.len()>0 {assert(delta::decoded(bs,37,path[1],rs,0,check,Ok(done[0])));}
                },
                recovery::Error::Audit(err)=>{
                    let (done,path)=choose|done:Seq<Mutation>,path:Seq<usize>| done.len()==1 && #[trigger] batch::layout(bs,rs,37,bs.len(),done,path,check) &&
                        recovery::audit_refusal(done,h.delta_bytes,previous.is_some(),rs.len() as nat,err);
                    assert(delta::decoded(bs,37,path[1],rs,0,check,Ok(done[0])));
                    reveal_with_fuel(batch::usage,2);
                    assert(batch::usage(done,1)==(charge as nat,0nat) && batch::ordered(done));
                },
                _=>{},
            }
            assert(false);
        }
    }
    match decoded {Ok(h)=>(record,h),Err(_)=>{assert(false);unreached()}}
}

/// A real one-row record distinguishes a changed key from an unrelated key and
/// its owning predecessor from another object, even when both names exist.
fn link_boundaries(previous:ObjectId,other:ObjectId,totals:crate::checkpoint_totals::NodeTotals)
    requires previous!=other,
{
    let key=vec![97u8,0,98];
    let ghost changed=key@;
    let ghost untouched=seq![97u8,0,99];
    let (record,_)=written_marker(key,Some(previous),0,0,totals);
    let ghost bytes=record.contents().2;
    let ghost path=seq![37usize,54usize];
    proof {
        assert(changed[2]==98 && untouched[2]==99 && changed!=untouched);
        assert(reference_lookup::selected(record.contents().3,crate::delta_header::PREVIOUS@,0,1)==Some(record.contents().3[0]));
        key::encoded_length(bytes,37,3);
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(row_end(bytes,37)==54);
        assert(spans(bytes,path)) by {
            assert forall|i:int| 0<=i<path.len()-1 implies path[i]<bytes.len() && path[i+1]==row_end(bytes,#[trigger] path[i]) by {
                assert(i==0);
            }
        }
        assert forall|offsets:Seq<usize>,i:int| #[trigger] spans(bytes,offsets) && 0<=i<offsets.len()-1 implies
            bytes.subrange((#[trigger] offsets[i]) as int+4,offsets[i] as int+4+key::length(bytes,offsets[i] as int))==changed by {
            assert(offsets[1]==54);
            if offsets.len()>2 {assert(offsets[1]<bytes.len());}
        }
        assert(untouched_link(&record,previous,untouched));
        assert(!untouched_link(&record,previous,changed)) by {
            if untouched_link(&record,previous,changed) {
                assert(bytes.subrange(path[0] as int+4,path[0] as int+4+key::length(bytes,path[0] as int))!=changed);
            }
        }
        assert(!untouched_link(&record,other,untouched));
    }
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

#[verifier::spinoff_prover]
#[verifier::rlimit(35)]
fn recover_tombstone(previous:Option<ObjectId>,logical:u64,entries:u64,quota:u64,deny:bool,via_envelope:bool) {
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
    let version=crate::ObjectFormatVersion::new(crate::header_graph::CURRENT_VERSION).unwrap();
    let record = ObjectRecord::from_fields(crate::ObjectKind::NamespaceMap,version,
        bytes,refs,logical,crate::ObjectClass::Metadata).unwrap();
    let validate = |_k:&[u8]| -> (e:Option<u8>) ensures e == if deny {Some(7u8)} else {None} {
        if deny {Some(7u8)} else {None}
    };
    let got = if via_envelope {
        use crate::{delta_chain::Head,projection_record};
        match projection_record::decode(&record,version,&[],validate) {
            Ok(Head::Delta {previous,depth,delta_bytes,mutations,totals}) =>
                Ok(recovery::Recovered {previous,depth,delta_bytes,rows:mutations,totals}),
            Err(projection_record::Error::Delta(e)) => Err(e),
            _ => unreached(),
        }
    } else {recovery::decode(&record,validate)};
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

fn apply_insert(key:&[u8],data:Vec<u8>,prior:crate::checkpoint_totals::NodeTotals,
    root:&mut Option<std::sync::Arc<crate::traversal::Node>>)
    requires crate::traversal::ordered(*old(root)),prior.entries < u64::MAX,
        prior.logical_bytes as int + data.len() <= u64::MAX,
        prior.quota_bytes as int + key.len() + data.len() <= u64::MAX,
    ensures forall|q:Seq<u8>| #[trigger] crate::traversal::lookup_spec(*final(root),q) ==
        if q == key@ {Some(Some(data))} else {crate::traversal::lookup_spec(*old(root),q)},
{
    let wrote = crate::delta_totals::update(prior,key.len(),None,Some(data.len()));
    let got = crate::delta_totals::prepare(prior,key,None,Some(data));
    assert(got.is_ok());
    let Ok(p) = got else {unreached()};
    let mut totals = prior;
    crate::overlay_update::replay(root,p,&mut totals);
    assert(wrote == Ok(totals));
    assert(totals.entries == prior.entries as int+1 && totals.logical_bytes == prior.logical_bytes as int + data.len() &&
        totals.quota_bytes == prior.quota_bytes as int + key.len() + data.len());
}

fn replay_noop(old:crate::checkpoint_totals::NodeTotals,key:&[u8],before:&[u8],after:Vec<u8>)
    requires before@ == after@,
{
    let out = crate::delta_totals::prepare(old,key,Some(before),Some(after));
    assert(out == Err(crate::delta_totals::ReplayError::Unchanged));
}

fn replay_delete(key:&[u8],prior:&[u8],totals:crate::checkpoint_totals::NodeTotals) {
    use crate::delta_totals::{prepare,ReplayError,Error};
    let out = prepare(totals,key,Some(prior),None);
    proof {
        if totals.entries == 0 {assert(out == Err(ReplayError::Accounting(Error::Entries)));}
        else if totals.logical_bytes < prior.len() {assert(out == Err(ReplayError::Accounting(Error::Logical)));}
        else if totals.quota_bytes < prior.len()+key.len() {assert(out == Err(ReplayError::Accounting(Error::Quota)));}
        else {
            assert(out matches Ok(p) && p.key@ == key@ && p.value.is_none() &&
                p.totals.entries+1 == totals.entries && p.totals.logical_bytes+prior.len() == totals.logical_bytes &&
                p.totals.quota_bytes+key.len()+prior.len() == totals.quota_bytes);
        }
    }
}

/// Both an observed writer row and recovery of the same key take their charge
/// from the selected prior bytes; a shadowing overlay tombstone is authoritative.
fn observed_replay(key:Vec<u8>,root:&mut Option<std::sync::Arc<crate::traversal::Node>>,
    totals:&mut crate::checkpoint_totals::NodeTotals,prior:Option<Vec<u8>>,next:Vec<u8>,shadow:bool)
    requires crate::traversal::ordered(*old(root)),
        crate::traversal::lookup_spec(*old(root),key@) == (if shadow {Some(prior)} else {None}),
{
    use crate::{delta_totals as acc,kv_replacement::{PreviousValue,Replacement},overlay_update, traversal};
    let mut copied = Vec::with_capacity(key.len());
    copied.extend_from_slice(&key);
    let mut data = Vec::with_capacity(next.len());
    data.extend_from_slice(&next);
    assert(copied@ =~= key@ && data@ =~= next@);
    let checkpoint = prior.clone();
    let ghost prior_view = acc::data_bytes(prior);
    let writer = Replacement::observed(copied,prior,Some(data));
    let (address,observation,new) = writer.into_parts();
    let PreviousValue::Loaded {previous_len,unchanged} = observation else {unreached()};
    let declared = acc::admit(*totals,address.len(),previous_len,new.as_ref().map(Vec::len),unchanged);
    let row = Mutation {key,value:Some(ValueSlot::Inline(next))};
    let read = |k:&Vec<u8>,v:&Option<ValueSlot>,need:bool| -> (out:Result<(Option<Vec<u8>>,Option<Vec<u8>>),u8>)
        ensures if k@ == row.key@ && *v == row.value && need == !shadow {
            out matches Ok(pair) && acc::data_bytes(pair.1) == acc::data_bytes(new) &&
                (need ==> acc::data_bytes(pair.0) == prior_view)
        } else {true} {
        Ok((if need {checkpoint} else {Some(vec![0x7fu8])},new))
    };
    let ghost initial = *root;
    let ghost initial_totals = *totals;
    let result = overlay_update::apply(root,totals,&row,read);
    proof {
        assert(overlay_update::applied(initial,*root,&row,initial_totals,*totals,read,result));
        assert(result.is_ok() == declared.is_ok());
        if result.is_ok() {
            assert(declared == Ok(*totals));
            assert(traversal::lookup_spec(*root,row.key@) matches Some(Some(v)) && v@ == next@);
        } else {assert(*root == initial && *totals == initial_totals);}
    }
}

fn replay_lookup_error(root:&mut Option<std::sync::Arc<crate::traversal::Node>>,row:&Mutation,
    totals:&mut crate::checkpoint_totals::NodeTotals)
    requires crate::traversal::ordered(*old(root)),
    ensures *final(root) == *old(root) && *final(totals) == *old(totals),
{
    let fail = |_k:&Vec<u8>,_v:&Option<ValueSlot>,_needs_base:bool| -> (out:Result<(Option<Vec<u8>>,Option<Vec<u8>>),u8>)
        ensures out == Err(7u8) { Err(7u8) };
    let out = crate::overlay_update::apply(root,totals,row,fail);
    assert(out == Err(crate::delta_totals::ApplyError::Load(7u8)));
}

fn absent_delete(t:crate::checkpoint_totals::NodeTotals,key:usize) {
    let raw = crate::delta_totals::update(t,key,None,None);
    let write = crate::delta_totals::admit(t,key,None,None,false);
    assert(raw == Ok(t));
    assert(write == Err(crate::delta_totals::ReplayError::Unchanged));
}
}
