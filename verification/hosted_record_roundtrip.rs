//! Composition of the complete production object-frame writer and reader.
use crate::{ObjectId,ObjectRecord,ObjectReference,ReferenceKind,root_wire::Scheme,verified_record as wire};
use vstd::prelude::*;

verus! {

proof fn reference_rows(bytes:Seq<u8>,start:int,rows:Seq<ObjectReference>,n:nat,scheme:Scheme)
    requires 0 <= start,n <= rows.len(),start+wire::reference_prefix(rows,n,scheme).len() <= bytes.len(),
        scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
        bytes.subrange(start,start+wire::reference_prefix(rows,n,scheme).len()) == wire::reference_prefix(rows,n,scheme),
    ensures wire::position(bytes,start,n) == start+wire::reference_prefix(rows,n,scheme).len(),
        wire::reference_prefix(rows,n,scheme).len() >= 49*n,
        forall|i:nat| i < n ==> wire::complete_reference(bytes,#[trigger] wire::position(bytes,start,i),scheme) &&
            wire::stored_reference(bytes,wire::position(bytes,start,i),rows[i as int]),
    decreases n,
{
    if n > 0 {
        let prev = (n-1) as nat;
        let prefix = wire::reference_prefix(rows,prev,scheme);
        let at = start+prefix.len();
        let r = rows[prev as int];
        let (label,id,kind) = r.fields();
        let code = match kind {ReferenceKind::Owns=>0u8,ReferenceKind::Evidence=>1u8,
            ReferenceKind::Lineage=>2u8,ReferenceKind::Derived=>3u8};
        let whole = wire::reference_prefix(rows,n,scheme);
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        r.label_fits();
        assert(whole == prefix+wire::reference_wire(r,scheme));
        crate::root_wire::subfield(bytes,start,whole,0,prefix.len() as int);
        crate::root_wire::subfield(bytes,start,whole,prefix.len() as int,wire::reference_wire(r,scheme).len() as int);
        assert(bytes.subrange(start,at) =~= prefix);
        reference_rows(bytes,start,rows,prev,scheme);
        assert(bytes.subrange(at,at+49+label.len()) =~= vstd::bytes::spec_u64_to_le_bytes(label.len() as u64)+label+wire::wire(scheme,id.raw())+seq![code]);
        crate::hosted_record_model::written_reference(bytes,at,label,scheme,id.raw(),code);
        assert(wire::stored_reference(bytes,at,r));
        assert forall|i:nat| i < n implies wire::complete_reference(bytes,#[trigger] wire::position(bytes,start,i),scheme) &&
            wire::stored_reference(bytes,wire::position(bytes,start,i),rows[i as int]) by {
            if i >= prev {assert(i == prev);}
        }
    }
}

spec fn same_fields(a:ObjectRecord,b:ObjectRecord) -> bool {
    let x = a.contents();
    let y = b.contents();
    &&& x.0 == y.0 && x.1 == y.1 && x.2 == y.2 && x.4 == y.4 && x.5 == y.5
    &&& x.3.len() == y.3.len()
    &&& forall|i:int| 0 <= i < x.3.len() ==> #[trigger] x.3[i].fields() == y.3[i].fields()
}

proof fn unique_record(bytes:Seq<u8>,scheme:Scheme,a:ObjectRecord,b:ObjectRecord)
    requires wire::record_at(bytes,40,scheme,a),wire::record_at(bytes,40,scheme,b),
    ensures same_fields(a,b),
{
    let refs = 69+wire::u64_field(bytes,53);
    assert forall|i:int| 0 <= i < a.contents().3.len() implies
        #[trigger] a.contents().3[i].fields() == b.contents().3[i].fields() by {
        let ra = a.contents().3[i];
        let rb = b.contents().3[i];
        let at = wire::position(bytes,refs,i as nat);
        assert(wire::stored_reference(bytes,at,ra));
        assert(wire::stored_reference(bytes,at,rb));
        ObjectId::same_digest(ra.fields().1,rb.fields().1);
    }
}

/// An arbitrary canonical production record, including every labelled edge,
/// recovers its original meaning from the complete encoder output.
#[verifier::rlimit(45)]
fn round_trip<H:Fn(&ObjectRecord)->[u8;32]>(source:&ObjectRecord,scheme:Scheme,id:ObjectId,hash:H)
    -> (out:Result<ObjectRecord,wire::Error<wire::BodyError>>)
    requires scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
        ObjectRecord::labels_ordered(source.contents().3),
        forall|r:&ObjectRecord| #[trigger] hash.requires((r,)),
        forall|r:&ObjectRecord,d:[u8;32]| same_fields(*r,*source) && #[trigger] hash.ensures((r,),d) ==> d@ == id.digest(),
    ensures match out {
        Ok(decoded) => same_fields(decoded,*source),
        Err(e) => source.contents().3.len() > 0 && e matches wire::Error::Decode(wire::DecodeError::Record(wire::BodyError::Allocation)),
    },
{
    let Ok(frame) = wire::encode(scheme,id,source) else {assert(false);unreachable!()};
    let version = source.format_version().get();
    let count = source.references().len();
    let length = source.canonical_bytes().len();
    proof {
        let f = source.contents();
        let n = f.3.len();
        let refs = wire::reference_prefix(f.3,n,scheme);
        let start = 69+f.2.len() as int;
        let bytes = frame@;
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert((f.2.len() as u64) as int == f.2.len()) by {assert(length <= usize::MAX);}
        assert(bytes.subrange(0,40) =~= wire::wire(scheme,id.raw()));
        wire::tag_written(bytes,0,scheme,id.raw());
        let h = wire::header_wire(f.0,f.1,f.5);
        let payload = wire::payload_wire(f.4,f.2,count);
        assert(bytes.subrange(40,45) =~= h);
        assert(bytes.subrange(45,start) =~= payload);
        crate::root_wire::subfield(bytes,40,h,0,2);
        crate::root_wire::subfield(bytes,40,h,2,2);
        assert(bytes.subrange(40,42) =~= wire::le16(f.0.wire_code()));
        assert(bytes.subrange(42,44) =~= wire::le16(f.1));
        assert forall|v:u16| (v as u8 as u16) | (((v >> 8) as u8 as u16) << 8) == v by {
            assert((v as u8 as u16) | (((v >> 8) as u8 as u16) << 8) == v) by(bit_vector);
        }
        crate::root_wire::subfield(bytes,45,payload,0,8);
        crate::root_wire::subfield(bytes,45,payload,8,8);
        crate::root_wire::subfield(bytes,45,payload,16,8);
        crate::root_wire::subfield(bytes,45,payload,24,f.2.len() as int);
        assert(bytes.subrange(45,53) =~= vstd::bytes::spec_u64_to_le_bytes(f.4));
        assert(bytes.subrange(53,61) =~= vstd::bytes::spec_u64_to_le_bytes(f.2.len() as u64));
        assert(bytes.subrange(61,69) =~= vstd::bytes::spec_u64_to_le_bytes(count as u64));
        assert(bytes.subrange(69,start) =~= f.2);
        assert(bytes.subrange(start,bytes.len() as int) =~= refs);
        reference_rows(bytes,start,f.3,n,scheme);
        assert forall|i:nat| 0 < i < n implies ObjectRecord::label_before(wire::label_at(bytes,start,(i-1) as nat),#[trigger] wire::label_at(bytes,start,i)) by {
            assert(wire::stored_reference(bytes,wire::position(bytes,start,i),f.3[i as int]));
            assert(wire::stored_reference(bytes,wire::position(bytes,start,(i-1) as nat),f.3[i as int-1]));
            assert(ObjectRecord::label_before(f.3[i as int-1].fields().0,f.3[i as int].fields().0));
        }
        assert(wire::record_at(bytes,40,scheme,*source));
        assert(wire::complete_body(bytes,40,scheme));
        if n == 0 {assert(wire::leaf_body(bytes,40));}
    }
    let result = wire::confirmed(&frame,scheme,id,hash);
    proof {
        if let Err(wire::Error::Identity) = result {
            let (other,digest) = choose|r:ObjectRecord,d:[u8;32]| d@ != id.digest() &&
                wire::record_at(frame@,40,scheme,r) && #[trigger] hash.ensures((&r,),d);
            unique_record(frame@,scheme,other,*source);
            assert(false);
        } else if let Ok(ref r) = result {unique_record(frame@,scheme,*r,*source);}
    }
    result
}


}
