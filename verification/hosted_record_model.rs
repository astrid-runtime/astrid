//! Consumers of the production arena name, reference and identity checks.
use crate::{verified_record as record,root_wire::Scheme,reference_kind::ReferenceKind};
use vstd::prelude::*;

verus! {

/// Every stored kind, including a principal state, retains its semantics and accounting class.
fn header_round_trip(kind:crate::ObjectKind,version:u16,class:crate::ObjectClass) -> (out:Option<()>)
    requires version != 0,
    ensures out.is_some(),
{
    let mut bytes = Vec::new();
    record::append_header(&mut bytes,kind,version,class);
    proof {
        assert forall|n:u16| (n as u8 as u16) | (((n >> 8) as u8 as u16) << 8) == n by {
            assert((n as u8 as u16) | (((n >> 8) as u8 as u16) << 8) == n) by(bit_vector);
        }
        assert(bytes@.subrange(0,2) =~= record::le16(kind.wire_code()));
        assert(bytes@.subrange(2,4) =~= record::le16(version));
    }
    let mut cursor = 0;
    let (k,v,c) = record::header(&bytes,&mut cursor).ok()?;
    assert(k == kind && c == class && v == version && cursor == 5);
    Some(())
}

/// Untrusted media may contain a zero version even when a valid writer never emits one.
fn zero_version(bytes:&[u8],start:usize)
    requires start as int+5 <= bytes.len(), bytes@[start as int+2] == 0,bytes@[start as int+3] == 0,
{
    let mut cursor = start;
    let out = record::header(bytes,&mut cursor);
    assert((0u16 | (0u16 << 8)) == 0) by(bit_vector);
    assert(record::field16(bytes@,start as int+2) == 0);
    assert(out.is_err());
}

/// Reject an overstated canonical length before consuming any reference bytes.
fn truncated_payload(bytes:&[u8],start:usize)
    requires start as int+24 <= bytes.len(),
        start as int+24+vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(start as int+8,start as int+16)) > bytes.len(),
{
    let mut cursor = start;
    let out = record::payload(bytes,&mut cursor);
    assert(out.is_err());
}

/// Any well-formed leaf for which the supplied identity implementation returns
/// the requested name reaches the WAL overlay with its exact physical bytes.
fn pending_leaf<H:Fn(&crate::ObjectRecord)->[u8;32]>(frame:&std::sync::Arc<[u8]>,scheme:Scheme,id:crate::ObjectId,identify:H)
    -> (out:Option<record::PendingFrame<crate::ObjectRecord>>)
    requires record::tag((**frame)@,0,scheme),record::leaf_body((**frame)@,40),
        (**frame)@.subrange(8,40) == id.digest(),forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|r:&crate::ObjectRecord,digest:[u8;32]| record::record_at((**frame)@,40,scheme,*r) &&
            #[trigger] identify.ensures((r,),digest) ==> digest@ == id.digest(),
    ensures out matches Some((name,payload,r)) && name == id && (*payload)@ == (**frame)@ &&
        r.contents().0.wire_code() == record::field16((**frame)@,40) && r.contents().1 == record::field16((**frame)@,42) &&
        r.contents().5.wire_code() == (**frame)@[44] && r.contents().4 == record::u64_field((**frame)@,45) &&
        r.contents().2 == (**frame)@.skip(69) && r.contents().3.len() == 0,
{
    let result = record::pending(frame,scheme,id,identify);
    let Ok((name,payload,r)) = result else {assert(false);return None;};
    assert(r.contents().2 =~= (**frame)@.skip(69));
    Some((name,payload,r))
}

use crate::closure_walk::{self as walk,Edge};

proof fn concrete_children(rows:Seq<crate::ObjectReference>,key:crate::ObjectId)
    ensures walk::children(rows).contains(key) == (exists|i:int| 0 <= i < rows.len() &&
        #[trigger] Edge::target(&rows[i]) == Some(key)),
    decreases rows.len(),
{
    if rows.len() > 0 {
        let tail = rows.skip(1);
        concrete_children(tail,key);
        if exists|i:int| 0 <= i < tail.len() && #[trigger] Edge::target(&tail[i]) == Some(key) {
            let i = choose|i:int| 0 <= i < tail.len() && #[trigger] Edge::target(&tail[i]) == Some(key);
            assert(rows[i+1] == tail[i]);
        }
        if exists|i:int| 0 <= i < rows.len() && #[trigger] Edge::target(&rows[i]) == Some(key) {
            let i = choose|i:int| 0 <= i < rows.len() && #[trigger] Edge::target(&rows[i]) == Some(key);
            if i > 0 {assert(tail[i-1] == rows[i]);}
        }
    }
}

spec fn wire_edge(bytes:Seq<u8>,i:nat,key:crate::ObjectId) -> bool {
    let first = 69+record::u64_field(bytes,53);
    let target = record::target_offset(bytes,record::position(bytes,first,i));
    &&& i < record::u64_field(bytes,61)
    &&& bytes[target+40] == 0
    &&& bytes.subrange(target+8,target+40) == key.digest()
}

spec fn physical_work(bytes:Seq<u8>,actions:Seq<walk::Work<crate::ObjectId>>) -> bool {
    &&& forall|j:int| 0 <= j < actions.len() ==> (#[trigger] actions[j] matches walk::Work::Visit(key) &&
        exists|i:nat| #[trigger] wire_edge(bytes,i,key))
    &&& forall|i:nat,key:crate::ObjectId| #[trigger] wire_edge(bytes,i,key) ==>
        exists|j:int| 0 <= j < actions.len() && #[trigger] actions[j] == walk::Work::Visit(key)
}

/// The worklist of an accepted pending frame contains exactly the owning
/// targets encoded on the wire. A valid named frame can also fail allocation.
fn pending_children<H:Fn(&crate::ObjectRecord)->[u8;32]>(frame:&std::sync::Arc<[u8]>,scheme:Scheme,id:crate::ObjectId,identify:H)
    -> (out:Result<Vec<walk::Work<crate::ObjectId>>,record::Error<record::BodyError>>)
    requires record::tag((**frame)@,0,scheme),record::complete_body((**frame)@,40,scheme),
        (**frame)@.subrange(8,40) == id.digest(),forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|r:&crate::ObjectRecord,digest:[u8;32]| record::record_at((**frame)@,40,scheme,*r) &&
            #[trigger] identify.ensures((r,),digest) ==> digest@ == id.digest(),
    ensures match out {
        Err(e) => e matches record::Error::Decode(record::DecodeError::Record(record::BodyError::Allocation)),
        Ok(actions) => physical_work((**frame)@,actions@),
    },
{
    let (_,_,r) = record::pending(frame,scheme,id,identify)?;
    let refs = r.references();
    let mut stack = Vec::new();
    walk::schedule(refs,&mut stack);
    let ghost bytes = (**frame)@;
    let ghost first = 69+record::u64_field(bytes,53);
    proof {
        assert forall|key:crate::ObjectId| walk::children(refs@).contains(key) <==>
            (exists|i:nat| #[trigger] wire_edge(bytes,i,key)) by {
            concrete_children(refs@,key);
            if walk::children(refs@).contains(key) {
                let i = choose|i:int| 0 <= i < refs.len() && #[trigger] Edge::target(&refs@[i]) == Some(key);
                assert(record::stored_reference(bytes,record::position(bytes,first,i as nat),refs@[i]));
                assert(wire_edge(bytes,i as nat,key));
            } else if exists|i:nat| #[trigger] wire_edge(bytes,i,key) {
                let i = choose|i:nat| #[trigger] wire_edge(bytes,i,key);
                assert(record::stored_reference(bytes,record::position(bytes,first,i),refs@[i as int]));
                crate::ObjectId::same_digest(refs@[i as int].fields().1,key);
                assert(Edge::target(&refs@[i as int]) == Some(key));
            }
        }
        assert(walk::scheduled(Seq::empty(),stack@,walk::children(refs@)));
        assert forall|i:nat,key:crate::ObjectId| #[trigger] wire_edge(bytes,i,key) implies
            exists|j:int| 0 <= j < stack.len() && #[trigger] stack@[j] == walk::Work::Visit(key) by {
            assert(walk::children(refs@).contains(key));
        }
        assert forall|j:int| 0 <= j < stack.len() implies (#[trigger] stack@[j] matches walk::Work::Visit(key) &&
            exists|i:nat| #[trigger] wire_edge(bytes,i,key)) by {
            if let walk::Work::Visit(key) = stack@[j] {assert(walk::children(refs@).contains(key));}
        }
    }
    Ok(stack)
}

/// Repeated labels cannot create two relations for the same name in an admitted object.
fn duplicate_labels(frame:&[u8],scheme:Scheme,start:usize)
    requires start as int+29 <= frame.len(),record::u64_field(frame@,start as int+21) >= 2,
        ({
            let first = start as int+29+record::u64_field(frame@,start as int+13);
            record::label_at(frame@,first,0) == record::label_at(frame@,first,1)
        }),
{
    let out = record::body(frame,start,scheme);
    if let Ok(r) = out {
        let ghost rows = r.contents().3;
        let ghost first = start as int+29+record::u64_field(frame@,start as int+13);
        assert(record::stored_reference(frame@,record::position(frame@,first,0),rows[0]));
        assert(record::stored_reference(frame@,record::position(frame@,first,1),rows[1]));
        assert(crate::ObjectRecord::label_before(rows[0].fields().0,rows[1].fields().0));
        assert(false);
    }
}

/// Replaying a name may add a staged placement if the payload agrees, while
/// retaining the originally decoded record, even when the candidate differs.
fn repeated<R:Copy>(retained:&mut crate::overlay_object::Object<R,u64,u64>,candidate:crate::overlay_object::Object<R,u64,u64>)
    -> (accepted:bool)
    ensures accepted == ((*old(retained).payload)@ == (*candidate.payload)@),
        final(retained).record == old(retained).record && final(retained).payload == old(retained).payload,
        if accepted && old(retained).location.is_none() && candidate.location.is_some() {
            final(retained).location == candidate.location && final(retained).direct == candidate.direct
        } else {*final(retained) == *old(retained)},
{
    retained.merge(candidate).is_ok()
}

/// A record may charge a logical size different from its payload length.
fn payload_round_trip(prefix:&[u8],suffix:&[u8],logical:u64,data:&[u8],count:usize) -> (result:Option<()>)
    requires prefix.len() as int + 24 + data.len() + suffix.len() <= usize::MAX,
    ensures result.is_some(),
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(prefix);
    let mut cursor = bytes.len();
    record::append_payload(&mut bytes,logical,data,count).ok()?;
    let end = bytes.len();
    bytes.extend_from_slice(suffix);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        let at = prefix.len() as int;
        let wire = record::payload_wire(logical,data@,count);
        assert(bytes@.subrange(at,end as int) =~= wire);
        crate::root_wire::subfield(bytes@,at,wire,0,8);
        crate::root_wire::subfield(bytes@,at,wire,8,8);
        crate::root_wire::subfield(bytes@,at,wire,16,8);
        crate::root_wire::subfield(bytes@,at,wire,24,data.len() as int);
        assert(bytes@.subrange(at,at+8) =~= vstd::bytes::spec_u64_to_le_bytes(logical));
        assert(bytes@.subrange(at+8,at+16) =~= vstd::bytes::spec_u64_to_le_bytes(data.len() as u64));
        assert(bytes@.subrange(at+16,at+24) =~= vstd::bytes::spec_u64_to_le_bytes(count as u64));
        assert(bytes@.subrange(at+24,end as int) =~= data@);
    }
    let (decoded,canonical,refs) = record::payload(&bytes,&mut cursor).ok()?;
    assert(decoded == logical && canonical@ == data@ && refs == count && cursor == end);
    Some(())
}

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

pub(super) proof fn written_reference(bytes:Seq<u8>,at:int,label:Seq<u8>,scheme:Scheme,id:[u8;32],code:u8)
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
    let mut actual_cursor = prefix.len();
    let actual = record::read_references(&frame,&mut actual_cursor,scheme,2,Vec::new()).ok()?;
    proof {
        assert(actual_cursor == end);
        assert(record::stored_reference(frame@,prefix.len() as int,actual@[0]));
        assert(record::stored_reference(frame@,second as int,actual@[1]));
        assert(actual@[0].fields().0 =~= name@ && actual@[1].fields().0 =~= other@);
        assert(actual@[0].fields().1.digest() =~= owner@);
        assert(actual@[1].fields().1.digest() =~= evidence@);
        assert(actual@[0].fields().2 is Owns && actual@[1].fields().2 is Evidence);
    }
    let mut actions = Vec::new();
    crate::closure_walk::schedule(&actual,&mut actions);
    proof {
        reveal_with_fuel(crate::closure_walk::reversed_visits,3);
        assert(actual@.skip(1).first() == actual@[1]);
        assert(actions.len() == 1);
        assert(actions@[0] == crate::closure_walk::Work::Visit(actual@[0].fields().1));
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
