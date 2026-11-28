//! Root-journal transitions at restart, from canonical owner and root bytes to the recovered index.
use crate::{RootState, owner_codec::{self, Owner}, root_wire};
use std::collections::BTreeMap;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv,prelude::*};

verus! {
/// Canonical bytes are required even when a decoder can produce a principal.
fn journal_name(saved:&[u8],recoded:Option<Vec<u8>>) -> (owner:Option<Owner>)
    ensures owner.is_some() == ((saved@ == seq![0u8] ||
        (saved.len() == 33 && (saved[0] == 1 || saved[0] == 2))) &&
        (recoded matches Some(v) ==> v@ == saved@)),
        owner matches Some(o) ==> o.bytes() == saved@,
{
    crate::journal_history::principal(saved,owner_codec::decode,|o:&Owner| -> (v:Vec<u8>)
        ensures v@ == (match recoded {Some(other)=>other@,None=>o.bytes()}),
        {match recoded {Some(other)=>other,None=>o.encode()}})
}

/// A canonical journal payload updates only its decoded owner's history and retains the frame offset.
fn journal_transition<K:Ord+Copy,F>(history:&mut BTreeMap<K,(RootState,u64)>,owner:Owner,
    scheme:root_wire::Scheme,expected:Option<RootState>,replacement:RootState,offset:u64,
    key_of:F,keys:Ghost<spec_fn(Seq<u8>)->K>) -> (accepted:bool)
    where F:FnOnce(Owner)->K,
    requires btree_map_inv(old(history)),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        forall|o:Owner| #[trigger] key_of.requires((o,)),
        forall|o:Owner,k:K| #[trigger] key_of.ensures((o,),k) ==> k == (keys@)(o.bytes()),
    ensures ({
        let k = (keys@)(owner.bytes());
        let actual = if old(history)@.contains_key(k) {Some(old(history)@[k].0)} else {None};
        let next = match actual {None => 0int,Some(r) => r.generation.value() as int + 1};
        &&& accepted == (actual == expected && replacement.generation.value() == next)
        &&& final(history)@ == if accepted {old(history)@.insert(k,(replacement,offset))} else {old(history)@}
    }),
{
    use crate::journal_history as journal;
    let name = owner.encode();
    let prior = match expected {Some(r) => Some(journal::to_wire(r)),None => None};
    let next = journal::to_wire(replacement);
    let body = root_wire::encode(&name,scheme,prior,next).unwrap();
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(body@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(name.len() as u64));
    let (saved,mut cursor) = match root_wire::read_owner(&body) {Ok(pair) => pair, Err(_) => {assert(false);return false;}};
    assert(saved@ =~= name@);
    let recovered = journal::principal(saved,owner_codec::decode,|o:&Owner| -> (bytes:Vec<u8>)
        ensures bytes@ == o.bytes(), {o.encode()}).unwrap();
    let k = key_of(recovered);
    let ghost start = cursor as int;
    assert(body@.skip(start) =~= root_wire::prior(prior,scheme) + next.wire(scheme));
    assert(root_wire::tail(body@,start,scheme,prior,next));
    let (e,r) = match root_wire::read_tail(&body,&mut cursor,scheme) {Ok(pair) => pair, Err(_) => {assert(false);return false;}};
    proof {
        root_wire::unique_tail(body@,start,scheme,e,r,prior,next);
        assert(r.generation =~= next.generation); assert(r.commit =~= next.commit);
        if let Some(a) = e {
            assert(a.generation =~= prior.unwrap().generation); assert(a.commit =~= prior.unwrap().commit);
        }
        assert(e == prior && r == next);
    }
    let saved_expected = match e {
        Some(root) => {
            let restored = journal::from_wire(root);
            proof {journal::unique(root,restored,expected.unwrap());}
            Some(restored)
        },
        None => None,
    };
    let saved_next = journal::from_wire(r);
    proof {journal::unique(r,saved_next,replacement);}
    let ghost seen = if history@.contains_key(k) {Some(history@[k].0)} else {None};
    match journal::apply(history,k,saved_expected,saved_next,offset) {
        Ok(()) => true,
        Err(journal::Rejection::Conflict(actual)) => {assert(actual == seen && actual != expected);false},
        Err(journal::Rejection::Overflow) => {assert(seen == expected && seen.unwrap().generation.value() == u64::MAX);false},
        Err(journal::Rejection::Generation) => {assert(seen == expected && (seen matches Some(r) ==> r.generation.value() < u64::MAX));false},
    }
}


/// Decode one row emitted by the snapshot serializer at the running cursor.
fn consume_snapshot_row(payload:&[u8],cursor:&mut usize,expected:&(Vec<u8>,RootState),scheme:root_wire::Scheme)
    -> (row:(Vec<u8>,RootState))
    requires root_wire::at(payload@,*old(cursor) as int,crate::journal_snapshot::row_bytes(*expected,scheme)),
    ensures row.0@ == expected.0@, row.1 == expected.1,
        *final(cursor) as int == *old(cursor) as int + crate::journal_snapshot::row_bytes(*expected,scheme).len(),
{
    use crate::journal_snapshot as snapshot;
    let wire = crate::journal_history::to_wire(expected.1);
    assert(snapshot::row_bytes(*expected,scheme) =~= snapshot::framed(expected.0@,wire,scheme));
    let restored = match snapshot::read_row(payload,cursor,scheme) {
        Ok(r) => r, Err(_) => {assert(false);return (Vec::new(),expected.1);},
    };
    proof {crate::journal_history::unique(wire,restored.1,expected.1);}
    restored
}

/// Restore two distinct principals from a compacted journal, then advance just the fleet root.
/// Use the production snapshot serializer for both the durable payload and the canonical check.
fn compacted_transition(system:RootState, fleet:RootState, replacement:RootState, id:[u8;32],
    scheme:root_wire::Scheme, offset:u64) -> (history:BTreeMap<u8,(RootState,u64)>)
    requires replacement.generation.value() == fleet.generation.value() as int + 1,
    ensures history@.dom() == set![0u8,2u8],
        history@.get(0) == Some((system,0u64)), history@.get(2) == Some((replacement,offset)),
{
    use crate::journal_snapshot as snapshot;
    let mut history = BTreeMap::new();
    let rows = vec![(Owner::System.encode(),system),(Owner::Fleet(id).encode(),fleet)];
    let decode = |name:&Vec<u8>| -> (r:Result<u8,()>)
        ensures r == (if name@ == seq![0u8] {Ok(0u8)}
            else if name.len() == 33 && name[0] == 2 {Ok(2u8)} else {Err(())}),
    {
        match owner_codec::decode(name) {
            Some(Owner::System) => Ok(0),
            Some(Owner::Fleet(key)) => {
                assert((seq![2u8] + key@)[0] == 2 && key@.len() == 32);
                Ok(2)
            },
            Some(Owner::Principal(key)) => {
                assert((seq![1u8] + key@)[0] == 1 && key@.len() == 32);
                Err(())
            },
            None => Err(()),
        }
    };
    assert(rows@[0].0@ == seq![0u8]);
    assert(rows@[1].0.len() == 33 && rows@[1].0[0] == 2);
    assert(crate::byte_order::below(rows@[0].0@,rows@[1].0@));
    assert(snapshot::ordered(rows@)) by {
        assert forall|i:int| 1 <= i < rows.len() implies
            #[trigger] crate::byte_order::below(rows@[i-1].0@,rows@[i].0@) by {assert(i == 1);}
    }
    let writer_accepts = snapshot::strictly_ordered(&rows);
    assert(writer_accepts);
    let payload = snapshot::serialize(&rows,scheme);
    assert(payload@ == snapshot::header(2) + snapshot::row_bytes(rows@[0],scheme) +
        snapshot::row_bytes(rows@[1],scheme)) by {
        reveal_with_fuel(snapshot::prefix,3);
    }
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(snapshot::header(2).len() == 17);
    assert(payload@.take(17) =~= vstd::bytes::spec_u64_to_le_bytes(u64::MAX) + seq![1u8] +
        vstd::bytes::spec_u64_to_le_bytes(2));
    let ghost first = vstd::bytes::spec_u64_to_le_bytes(1) + seq![0u8] +
        vstd::bytes::spec_u64_to_le_bytes(system.generation.value()) + scheme.algorithm@ +
        scheme.construction@ + seq![32u8,0,0,0] + system.commit.digest();
    assert(snapshot::row_bytes(rows@[0],scheme) =~= first);
    let mut cursor = 0usize;
    assert(payload@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(u64::MAX));
    assert(payload@[8] == 1);
    assert(payload@.subrange(9,17) =~= vstd::bytes::spec_u64_to_le_bytes(2));
    let count = match snapshot::read_header(&payload,&mut cursor) {
        Ok(snapshot::JournalHeader::Snapshot(count)) => count,
        _ => {assert(false);return history;},
    };
    assert(count == rows.len());
    assert(cursor == 17);
    let ghost one = snapshot::row_bytes(rows@[0],scheme);
    let ghost two = snapshot::row_bytes(rows@[1],scheme);
    assert(payload@.subrange(17,17int+one.len()) =~= one);
    let ghost middle = (17int + one.len()) as usize;
    assert(payload@.subrange(middle as int,middle as int+two.len()) =~= two);
    let w0 = crate::journal_history::to_wire(system);
    let w1 = crate::journal_history::to_wire(fleet);
    let ghost expected = seq![(rows@[0].0@,w0),(rows@[1].0@,w1)];
    let ghost ends = seq![17usize,middle,payload.len()];
    assert(one =~= snapshot::framed(rows@[0].0@,w0,scheme));
    assert(two =~= snapshot::framed(rows@[1].0@,w1,scheme));
    assert forall|i:int| 0 <= i < count implies {
        let (name,w) = expected[i];
        &&& name.len() <= u64::MAX
        &&& #[trigger] root_wire::at(payload@,ends[i] as int,snapshot::framed(expected[i].0,expected[i].1,scheme))
        &&& ends[i+1] as int == ends[i] as int + snapshot::framed(name,w,scheme).len()
    } by {if i == 0 {} else {assert(i == 1);}}
    assert(snapshot::layout(payload@,17,count,scheme,expected,ends));
    let parsed = match snapshot::read_rows(&payload,&mut cursor,count,scheme,Vec::new()) {
        Ok(v) => v,Err(_) => {assert(false);return history;},
    };
    assert(parsed.len() == count && cursor == payload.len());
    assert(snapshot::row_matches(parsed@[0],expected[0]));
    assert(snapshot::row_matches(parsed@[1],expected[1]));
    proof {
        crate::journal_history::unique(w0,parsed@[0].1,system);
        crate::journal_history::unique(w1,parsed@[1].1,fleet);
    }
    assert(snapshot::row_bytes(parsed@[0],scheme) =~= one);
    assert(snapshot::row_bytes(parsed@[1],scheme) =~= two);
    assert(snapshot::prefix(parsed@,2,scheme) == payload@) by {reveal_with_fuel(snapshot::prefix,3);}
    assert(snapshot::ordered(parsed@)) by {
        assert forall|i:int| 1 <= i < parsed.len() implies
            #[trigger] crate::byte_order::below(parsed@[i-1].0@,parsed@[i].0@) by {assert(i == 1);}
    }
    let finished = snapshot::finish(&parsed,cursor,payload.len());
    assert(finished.is_ok());
    let rows = parsed;
    let encode = |input:&Vec<(Vec<u8>,RootState)>| -> (r:Result<Vec<u8>,()>)
        ensures r matches Ok(w) && w@ == snapshot::prefix(input@,input.len() as nat,scheme),
    { Ok(snapshot::serialize(input,scheme)) };
    match snapshot::restore(&mut history,0,&payload,rows,encode,decode) {
        Ok(()) => {
            let ghost ids = choose|ids:Seq<u8>| ids.len() == rows.len() &&
                snapshot::decoded(rows@,ids,decode) && #[trigger] snapshot::image(rows@,ids,history@);
            assert(decode.ensures((&rows@[0].0,),Ok(ids[0])));
            assert(decode.ensures((&rows@[1].0,),Ok(ids[1])));
            assert(ids =~= seq![0u8,2u8]);
            assert(ids.to_set() =~= set![0u8,2u8]) by {
                assert forall|k:u8| ids.contains(k) implies k == 0 || k == 2 by {
                    let i = ids.index_of(k); assert(ids[i] == k);
                }
            }
            assert(history@.get(ids[0]) == Some((system,0u64)));
            assert(history@.get(ids[1]) == Some((fleet,0u64)));
        },
        Err(snapshot::SnapshotError::Duplicate) => {
            let ghost (i,j,p) = choose|i:int,j:int,p:u8| 0 <= i < j < rows.len() &&
                #[trigger] decode.ensures((&rows@[i].0,),Ok(p)) && #[trigger] decode.ensures((&rows@[j].0,),Ok(p));
            assert(i == 0 && j == 1); assert(false);
        },
        Err(_) => {assert(false);},
    }
    let result = crate::journal_history::apply(&mut history,2,Some(fleet),replacement,offset);
    assert(result.is_ok());
    assert(history@.dom() =~= set![0u8,2u8]);
    history
}


/// Every row in a successful scan occupies a continuous, non-overlapping portion of the payload.
fn scan_snapshot_extent(bytes:&[u8],cursor:&mut usize,count:usize,scheme:root_wire::Scheme)
    -> (rows:Option<Vec<(Vec<u8>,RootState)>>)
    ensures rows matches Some(v) ==> v.len() == count &&
        exists|ends:Seq<usize>| ends.len() == v.len()+1 && ends[0] == *old(cursor) &&
            ends[count as int] == *final(cursor) && forall|i:int| 0 <= i < count ==>
                #[trigger] root_wire::at(bytes@,ends[i] as int,crate::journal_snapshot::row_bytes(v@[i],scheme)) &&
                ends[i+1] as int == ends[i] as int + crate::journal_snapshot::row_bytes(v@[i],scheme).len(),
{
    use crate::journal_snapshot as snapshot;
    let ghost start = *cursor;
    match snapshot::read_rows(bytes,cursor,count,scheme,Vec::new()) {
        Ok(v) => {
            let ghost ends = choose|ends:Seq<usize>| ends[0] == start && ends[count as int] == *cursor &&
                #[trigger] snapshot::spans(bytes@,v@,ends,scheme);
            assert(snapshot::spans(bytes@,v@,ends,scheme));
            Some(v)
        },
        Err(_) => None,
    }
}

/// Preserve the ordering diagnostic even when the payload also has trailing bytes.
fn finish_snapshot(rows:&[(Vec<u8>,RootState)],cursor:usize,len:usize) -> (result:u8)
    ensures result == if !crate::journal_snapshot::ordered(rows@) {1u8}
        else if cursor != len {2u8} else {0u8},
{
    use crate::journal_snapshot::{finish,EndError};
    match finish(rows,cursor,len) {Ok(())=>0,Err(EndError::Order)=>1,Err(EndError::Trailing)=>2}
}

/// A repeated or descending adjacent owner invalidates a compacted snapshot.
fn reject_unordered(rows:&[(Vec<u8>,RootState)],i:usize) -> (rejected:bool)
    requires 0 < i < rows.len(),
        !crate::byte_order::below(rows@[i as int-1].0@,rows@[i as int].0@),
    ensures rejected,
{
    !crate::journal_snapshot::strictly_ordered(rows)
}

/// Normal transition lengths and malformed extension headers cannot select the snapshot path.
fn dispatch_root_header(bytes:&[u8]) -> (selection:Option<(bool,u64,usize)>)
    ensures selection == ({
        let first = vstd::bytes::spec_u64_from_le_bytes(bytes@.take(8));
        let count = vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(9,17));
        if bytes.len() < 8 {None}
        else if first != u64::MAX {Some((false,first,8usize))}
        else if bytes.len() >= 17 && bytes@[8] == 1 && count <= usize::MAX {Some((true,count,17usize))}
        else {None}
    }),
{
    use crate::journal_snapshot::{read_header,JournalHeader};
    let mut cursor = 0usize;
    match read_header(bytes,&mut cursor) {
        Ok(JournalHeader::Transition(n)) => Some((false,n,cursor)),
        Ok(JournalHeader::Snapshot(n)) => Some((true,n as u64,cursor)),
        Err(_) => None,
    }
}

/// A rejected snapshot cannot overwrite any previously recovered owner, even if rejection is late.
fn restore_or_keep<P:Ord,E,C,D>(history:&mut BTreeMap<P,(RootState,u64)>, offset:u64,
    payload:&[u8], rows:Vec<(Vec<u8>,RootState)>, encode:C,decode:D) -> (accepted:bool)
    where C:FnOnce(&Vec<(Vec<u8>,RootState)>)->Result<Vec<u8>,E>, D:Fn(&Vec<u8>)->Result<P,E>,
    requires btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        encode.requires((&rows,)),forall|i:int| 0 <= i < rows.len() ==> decode.requires((&rows@[i].0,)),
    ensures !accepted ==> final(history)@ == old(history)@,
        accepted ==> offset == 0 && old(history)@.is_empty() &&
            exists|wire:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(wire)) && wire@ == payload@,
{
    crate::journal_snapshot::restore(history,offset,payload,rows,encode,decode).is_ok()
}

}
