//! Consumers of the production arena name, reference and identity checks.
use crate::{verified_record as record,root_wire::Scheme,reference_kind::ReferenceKind};
use vstd::prelude::*;

verus! {

/// A writer-produced name is accepted exactly when both the embedded name
/// and the identity independently computed on the decoded record match.
fn indexed<R:Copy,H>(scheme:Scheme,embedded:[u8;32],expected:[u8;32],suffix:&[u8],value:R,hash:H,
    Ghost(computed):Ghost<[u8;32]>) -> (out:Result<R,record::Error<()>>)
    where H:FnOnce(&R)->[u8;32],
    requires scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
        forall|r:&R| #[trigger] hash.requires((r,)),
        forall|r:&R,h:[u8;32]| *r == value && #[trigger] hash.ensures((r,),h) ==> h == computed,
    ensures match out {
        Ok(r) => r == value && embedded == expected && computed == expected,
        Err(record::Error::Identifier) => embedded != expected,
        Err(record::Error::Identity) => embedded == expected && computed != expected,
        Err(record::Error::Decode(_)) => false,
    },
{
    let mut frame = Vec::new();
    record::append_identity(&mut frame,scheme,embedded);
    frame.extend_from_slice(suffix);
    assert(frame@.take(40) =~= record::wire(scheme,embedded));
    assert(frame@.skip(40) =~= suffix@);
    proof {record::tag_written(frame@,0,scheme,embedded);}
    let decoder = |bytes:&[u8],start:usize| -> (r:Result<R,()>)
        requires start <= bytes.len(),
        ensures r == if bytes@.skip(start as int) == suffix@ {Ok(value)} else {Err(())},
    {
        if &bytes[start..] == suffix {
            assert(bytes@.skip(start as int) =~= suffix@);
            Ok(value)
        } else {Err(())}
    };
    let input = frame.as_slice();
    let out = record::read(input,scheme,expected,decoder,hash);
    if let Err(record::Error::Identity) = out {
        proof {
            let (v,h) = choose|v:R,h:[u8;32]| h@ != expected@ && decoder.ensures((input,40usize),Ok(v)) &&
                #[trigger] hash.ensures((&v,),h);
            assert(v == value);
        }
    }
    out
}

proof fn written_reference(bytes:Seq<u8>,at:int,label:Seq<u8>,scheme:Scheme,id:[u8;32],code:u8)
    requires at >= 0,at+49+label.len() <= bytes.len(),code <= 3,label.len() <= usize::MAX,
        scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
        bytes.subrange(at,at+49+label.len()) ==
            vstd::bytes::spec_u64_to_le_bytes(label.len() as u64) + label + record::wire(scheme,id) + seq![code],
    ensures record::complete_reference(bytes,at,scheme),record::target_offset(bytes,at) == at+8+label.len(),
        bytes.subrange(at+8,at+8+label.len()) == label,
        bytes.subrange(at+16+label.len(),at+48+label.len()) == id@,
        bytes[at+48+label.len()] == code,
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    let target = at+8+label.len();
    let all = bytes.subrange(at,at+49+label.len());
    crate::root_wire::subfield(bytes,at,all,0,8);
    crate::root_wire::subfield(bytes,at,all,8,label.len() as int);
    crate::root_wire::subfield(bytes,at,all,8+label.len() as int,40);
    assert(all.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(label.len() as int as u64));
    assert(all.subrange(8,8+label.len() as int) =~= label);
    assert(all.subrange(8+label.len() as int,48+label.len() as int) =~= record::wire(scheme,id));
    assert(all[48+label.len() as int] == code);
    record::tag_written(bytes,target,scheme,id);
}

type Row = (Vec<u8>,[u8;32],ReferenceKind);

/// Decode two real reference encodings between arbitrary neighboring fields.
/// Neither an evidence target nor adjacent bytes can become the owning edge.
#[verifier::rlimit(30)]
fn two_references(prefix:&[u8],suffix:&[u8],name:&[u8],other:&[u8],owner:[u8;32],evidence:[u8;32],scheme:Scheme)
    -> (out:Option<Vec<Row>>)
    requires scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
        prefix.len() as int+name.len()+other.len()+suffix.len()+98 <= usize::MAX,
    ensures out matches Some(v) && v.len() == 2 && v@[0].0@ == name@ && v@[0].1 == owner &&
        (v@[0].2 is Owns) && v@[1].0@ == other@ && v@[1].1 == evidence && (v@[1].2 is Evidence),
{
    let mut frame = Vec::new();
    frame.extend_from_slice(prefix);
    let mut cursor = frame.len();
    record::append_reference(&mut frame,name,scheme,owner,ReferenceKind::Owns).ok()?;
    let second = frame.len();
    record::append_reference(&mut frame,other,scheme,evidence,ReferenceKind::Evidence).ok()?;
    let end = frame.len();
    frame.extend_from_slice(suffix);
    proof {
        let p = prefix.len() as int;
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let q = second as int;
        assert(frame@.subrange(p,q) =~= vstd::bytes::spec_u64_to_le_bytes(name.len() as u64)+name@+record::wire(scheme,owner)+seq![0u8]);
        assert(frame@.subrange(q,end as int) =~= vstd::bytes::spec_u64_to_le_bytes(other.len() as u64)+other@+record::wire(scheme,evidence)+seq![1u8]);
        written_reference(frame@,p,name@,scheme,owner,0);
        written_reference(frame@,q,other@,scheme,evidence,1);
        reveal_with_fuel(record::position,3);
        assert(record::position(frame@,p,0) == p);
        assert(record::position(frame@,p,1) == q);
        assert(record::position(frame@,p,2) == end);
        assert forall|i:nat| i < 2 implies record::complete_reference(frame@,#[trigger] record::position(frame@,p,i),scheme) by {
            assert(i == 0 || i == 1);
        }
    }
    let pack = |l:&[u8],id:[u8;32],k:ReferenceKind| -> (r:Row) ensures r.0@ == l@ && r.1 == id && r.2 == k {
        let mut label = Vec::new(); label.extend_from_slice(l); assert(label@ =~= l@); (label,id,k)
    };
    let rows = record::read_many(&frame,&mut cursor,scheme,2,Vec::new(),pack).ok()?;
    proof {
        assert(cursor == end);
        assert(record::entry(frame@,prefix.len() as int,scheme,pack,rows@[0]));
        assert(record::entry(frame@,second as int,scheme,pack,rows@[1]));
        assert(rows@[0].1 =~= owner);
        assert(rows@[1].1 =~= evidence);
    }
    Some(rows)
}

}
