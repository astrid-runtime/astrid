//! Seed replay history only after every compacted root has been accepted.
use super::{RootState, journal_history, root_wire};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{btree::btree_map_inv, iter::IteratorSpec},
};

const _: () = assert!(usize::BITS <= u64::BITS);

verus! {
type Row = (Vec<u8>,RootState);
pub(super) const SENTINEL:u64 = u64::MAX;
pub(super) const RECORD:u8 = 1;

pub(super) open spec fn header(count:u64) -> Seq<u8> {
    vstd::bytes::spec_u64_to_le_bytes(SENTINEL) + seq![RECORD] + vstd::bytes::spec_u64_to_le_bytes(count)
}

pub(super) open spec fn ordered(rows:Seq<Row>) -> bool {
    forall|i:int| 1 <= i < rows.len() ==> #[trigger] crate::byte_order::below(rows[i-1].0@, rows[i].0@)
}

/// Check the same strict owner ordering on both sides of the snapshot format.
pub(super) fn strictly_ordered(rows:&[Row]) -> (valid:bool)
    ensures valid == ordered(rows@),
{
    let mut i = 1usize;
    while i < rows.len()
        invariant 1 <= i, forall|j:int| 1 <= j < i ==> #[trigger] crate::byte_order::below(rows@[j-1].0@,rows@[j].0@),
        decreases rows.len() - i,
    {
        if !crate::byte_order::bytewise_less(&rows[i.saturating_sub(1)].0,&rows[i].0) {return false;}
        i = i.saturating_add(1);
    }
    true
}

pub(super) enum JournalHeader {
    Transition(u64),
    Snapshot(usize),
}
pub(super) enum HeaderError { Read(root_wire::ReadError), UnknownRecord, Length }

/// Distinguish transition owner lengths from the reserved compaction header.
pub(super) fn read_header(bytes:&[u8],cursor:&mut usize) -> (out:Result<JournalHeader,HeaderError>)
    requires *old(cursor) == 0,
    ensures ({
        let first = vstd::bytes::spec_u64_from_le_bytes(bytes@.take(8));
        let count = vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(9,17));
        let transition = bytes.len() >= 8 && first != SENTINEL;
        let snapshot = bytes.len() >= 17 && first == SENTINEL && bytes@[8] == RECORD && count <= usize::MAX;
        match out {
            Ok(JournalHeader::Transition(length)) => transition && length == first && *final(cursor) == 8,
            Ok(JournalHeader::Snapshot(n)) => snapshot && n == count && *final(cursor) == 17
                && bytes@.take(17) == header(n as u64),
            Err(HeaderError::UnknownRecord) => bytes.len() >= 9 && first == SENTINEL && bytes@[8] != RECORD,
            Err(HeaderError::Length) => bytes.len() >= 17 && first == SENTINEL && bytes@[8] == RECORD && count > usize::MAX,
            Err(HeaderError::Read(_)) => bytes.len() < 8 || (first == SENTINEL && (bytes.len() < 9 ||
                (bytes@[8] == RECORD && bytes.len() < 17))),
        }
    }),
{
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    let first = match root_wire::fixed::<8>(bytes,cursor) {Ok(v) => u64::from_le_bytes(v),Err(e) => return Err(HeaderError::Read(e))};
    if first != SENTINEL {return Ok(JournalHeader::Transition(first));}
    let tag = match root_wire::fixed::<1>(bytes,cursor) {Ok(v) => v,Err(e) => return Err(HeaderError::Read(e))};
    if tag[0] != RECORD {return Err(HeaderError::UnknownRecord);}
    let count = match root_wire::fixed::<8>(bytes,cursor) {Ok(v) => u64::from_le_bytes(v),Err(e) => return Err(HeaderError::Read(e))};
    let Ok(n) = usize::try_from(count) else {return Err(HeaderError::Length);};
    assert(bytes@.take(17) =~= header(count));
    Ok(JournalHeader::Snapshot(n))
}

pub(super) open spec fn row_bytes(row:Row, scheme:root_wire::Scheme) -> Seq<u8> {
    vstd::bytes::spec_u64_to_le_bytes(row.0.len() as u64) + row.0@ +
        vstd::bytes::spec_u64_to_le_bytes(row.1.generation.value()) + scheme.algorithm@ +
        scheme.construction@ + seq![32u8,0,0,0] + row.1.commit.digest()
}

pub(super) open spec fn prefix(rows:Seq<Row>,n:nat,scheme:root_wire::Scheme) -> Seq<u8>
    decreases n,
{
    if n == 0 {header(rows.len() as u64)}
    else {prefix(rows,(n-1) as nat,scheme) + row_bytes(rows[n-1],scheme)}
}

/// The caller checks strict owner ordering before serializing.
pub(super) fn serialize(rows:&[Row],scheme:root_wire::Scheme) -> (bytes:Vec<u8>)
    ensures bytes@ == prefix(rows@,rows.len() as nat,scheme),
{
    let count = rows.len() as u64;
    let mut bytes = vstd::bytes::u64_to_le_bytes(SENTINEL);
    bytes.push(RECORD);
    bytes.extend_from_slice(&root_wire::little_endian(count));
    assert(bytes@ =~= header(count));
    let mut i = 0usize;
    while i < rows.len()
        invariant i <= rows.len(), bytes@ == prefix(rows@,i as nat,scheme),
        decreases rows.len() - i,
    {
        let (principal,root) = &rows[i];
        let length = principal.len() as u64;
        let ghost before = bytes@;
        bytes.extend_from_slice(&root_wire::little_endian(length));
        bytes.extend_from_slice(principal);
        let wire = journal_history::to_wire(*root);
        wire.append(&mut bytes,scheme);
        assert(bytes@ =~= before + row_bytes(rows@[i as int],scheme));
        i = i.saturating_add(1);
    }
    bytes
}

pub(super) enum RowError { Read(root_wire::ReadError), Length, Root(root_wire::RootError) }

pub(super) open spec fn framed(name:Seq<u8>, w:root_wire::Root, scheme:root_wire::Scheme) -> Seq<u8> {
    vstd::bytes::spec_u64_to_le_bytes(name.len() as u64) + name + w.wire(scheme)
}

/// Read one length-prefixed owner and its fixed-width root from the snapshot cursor.
pub(super) fn read_row(bytes:&[u8], cursor:&mut usize, scheme:root_wire::Scheme) -> (out:Result<Row,RowError>)
    ensures out matches Ok(row) ==> root_wire::at(bytes@,*old(cursor) as int,row_bytes(row,scheme))
        && *final(cursor) as int == *old(cursor) as int + row_bytes(row,scheme).len(),
        forall|name:Seq<u8>,w:root_wire::Root| name.len() <= u64::MAX &&
            #[trigger] root_wire::at(bytes@,*old(cursor) as int,framed(name,w,scheme)) ==>
            (out matches Ok(r) && r.0@ == name && journal_history::represents(w,r.1)),
{
    let ghost start = *cursor as int;
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert forall|name:Seq<u8>,w:root_wire::Root| name.len() <= u64::MAX && #[trigger] root_wire::at(bytes@,start,framed(name,w,scheme)) implies
            bytes@.subrange(start,start+8) == vstd::bytes::spec_u64_to_le_bytes(name.len() as u64)
            && bytes@.subrange(start+8,start+8+name.len() as int) == name
            && root_wire::at(bytes@,start+8+name.len() as int,w.wire(scheme)) by {
            let frame = framed(name,w,scheme);
            root_wire::subfield(bytes@,start,frame,0,8);
            root_wire::subfield(bytes@,start,frame,8,name.len() as int);
            root_wire::subfield(bytes@,start,frame,8+name.len() as int,48);
            assert(frame.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(name.len() as u64));
            assert(frame.subrange(8,8+name.len() as int) =~= name);
            assert(frame.subrange(8+name.len() as int,8+name.len() as int+48) =~= w.wire(scheme));
        }
    }
    let field = match root_wire::fixed::<8>(bytes,cursor) {Ok(v) => v, Err(e) => return Err(RowError::Read(e))};
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    let Ok(len) = usize::try_from(u64::from_le_bytes(field)) else {return Err(RowError::Length);};
    let name = match root_wire::take(bytes,cursor,len) {Ok(v) => {let mut name = Vec::with_capacity(len); name.extend_from_slice(v); name},Err(e) => return Err(RowError::Read(e))};
    let ghost pos = *cursor as int;
    let wire = match root_wire::read_root(bytes,cursor,scheme) {Ok(r) => r,Err(e) => return Err(RowError::Root(e))};
    let root = journal_history::from_wire(wire);
    let row = (name,root);
    assert(row_bytes(row,scheme) =~= field@ + row.0@ + wire.wire(scheme));
    assert(bytes@.subrange(start,*cursor as int) =~= row_bytes(row,scheme)) by {
        assert forall|i:int| 0 <= i < *cursor as int - start implies
            bytes@[start+i] == #[trigger] row_bytes(row,scheme)[i] by {
            if i < 8 {assert(field@[i] == bytes@[start+i]);}
            else if start+i < pos {assert(row.0@[i-8] == bytes@[start+i]);}
            else {assert(wire.wire(scheme)[start+i-pos] == bytes@[start+i]);}
        }
    }
    assert forall|n:Seq<u8>,w:root_wire::Root| n.len() <= u64::MAX && #[trigger] root_wire::at(bytes@,start,framed(n,w,scheme)) implies
        row.0@ == n && journal_history::represents(w,row.1) by {
        assert(n.len() == len);
        assert(w.wire(scheme) == wire.wire(scheme));
        assert(w.wire(scheme).take(8) =~= w.generation@);
        assert(wire.wire(scheme).take(8) =~= wire.generation@);
        assert(w.wire(scheme).skip(16) =~= w.commit@);
        assert(wire.wire(scheme).skip(16) =~= wire.commit@);
        assert(w.generation@ =~= wire.generation@);
        assert(w.commit@ =~= wire.commit@);
    }
    Ok(row)
}

pub(super) open spec fn spans(bytes:Seq<u8>,rows:Seq<Row>,ends:Seq<usize>,scheme:root_wire::Scheme) -> bool {
    &&& ends.len() == rows.len() + 1
    &&& forall|i:int| 0 <= i < rows.len() ==> {
        &&& #[trigger] root_wire::at(bytes,ends[i] as int,row_bytes(rows[i],scheme))
        &&& ends[i+1] as int == ends[i] as int + row_bytes(rows[i],scheme).len()
    }
}

#[cfg(verus_keep_ghost)]
pub(super) type WireRows = Seq<(Seq<u8>,root_wire::Root)>;
pub(super) open spec fn layout(bytes:Seq<u8>,start:usize,count:usize,scheme:root_wire::Scheme,
    expected:WireRows,ends:Seq<usize>) -> bool {
    &&& expected.len() == count && ends.len() == count as int + 1 && ends[0] == start
    &&& forall|i:int| 0 <= i < count ==> {
        let frame = framed(expected[i].0,expected[i].1,scheme);
        &&& expected[i].0.len() <= u64::MAX
        &&& #[trigger] root_wire::at(bytes,ends[i] as int,framed(expected[i].0,expected[i].1,scheme))
        &&& ends[i+1] as int == ends[i] as int + frame.len()
    }
}

pub(super) open spec fn row_matches(row:Row, expected:(Seq<u8>,root_wire::Root)) -> bool {
    row.0@ == expected.0 && journal_history::represents(expected.1,row.1)
}

pub(super) open spec fn matches_rows(rows:Seq<Row>,expected:WireRows) -> bool {
    forall|i:int| 0 <= i < rows.len() ==> #[trigger] row_matches(rows[i],expected[i])
}

/// Consume exactly the declared number of contiguous rows using the caller's reserved storage.
pub(super) fn read_rows(bytes:&[u8],cursor:&mut usize,count:usize,scheme:root_wire::Scheme,mut rows:Vec<Row>)
    -> (result:Result<Vec<Row>,RowError>)
    requires rows.len() == 0,
    ensures result matches Ok(v) ==> v.len() == count && exists|ends:Seq<usize>|
        ends[0] == *old(cursor) && ends[count as int] == *final(cursor) && #[trigger] spans(bytes@,v@,ends,scheme),
        forall|expected:WireRows,ends:Seq<usize>| #[trigger] layout(bytes@,*old(cursor),count,scheme,expected,ends)
            ==> (result matches Ok(v) && matches_rows(v@,expected) && *final(cursor) == ends[count as int]),
{
    let ghost start = *cursor;
    let ghost mut positions = seq![start];
    while rows.len() < count
        invariant start == *old(cursor), rows.len() <= count, positions[0] == start,
            positions[rows.len() as int] == *cursor, spans(bytes@,rows@,positions,scheme),
            forall|expected:WireRows,ends:Seq<usize>| #[trigger] layout(bytes@,start,count,scheme,expected,ends)
                ==> matches_rows(rows@,expected) && *cursor == ends[rows.len() as int],
        decreases count - rows.len(),
    {
        let ghost n = rows.len() as int;
        let ghost before = rows@;
        let ghost pos = *cursor;
        let next = read_row(bytes,cursor,scheme);
        assert forall|expected:WireRows,ends:Seq<usize>| #[trigger] layout(bytes@,start,count,scheme,expected,ends)
            implies (next matches Ok(row) && row.0@ == expected[n].0 && journal_history::represents(expected[n].1,row.1)
                && *cursor == ends[n+1]) by {
            let (name,w) = expected[n];
            assert(root_wire::at(bytes@,pos as int,framed(name,w,scheme)));
            if let Ok(row) = next {assert(row_bytes(row,scheme) =~= framed(name,w,scheme));}
        }
        let row = next?;
        rows.push(row);
        proof {
            let old_positions = positions;
            positions = positions.push(*cursor);
            assert forall|i:int| 0 <= i < rows.len() implies
                #[trigger] root_wire::at(bytes@,positions[i] as int,row_bytes(rows@[i],scheme)) &&
                positions[i+1] as int == positions[i] as int + row_bytes(rows@[i],scheme).len() by {
                if i < n {assert(root_wire::at(bytes@,old_positions[i] as int,row_bytes(before[i],scheme)));}
            }
            assert forall|expected:WireRows,ends:Seq<usize>| #[trigger] layout(bytes@,start,count,scheme,expected,ends)
                implies matches_rows(rows@,expected) && *cursor == ends[rows.len() as int] by {
                assert(*cursor == ends[n+1]);
                assert(journal_history::represents(expected[n].1,row.1));
                assert forall|i:int| 0 <= i < rows@.len() implies #[trigger] row_matches(rows@[i],expected[i]) by {
                    if i < n {assert(row_matches(before[i],expected[i]));}
                }
                assert(matches_rows(rows@,expected));
                assert(*cursor == ends[rows.len() as int]);
            }
        };
    }
    assert(positions[0] == *old(cursor) && positions[count as int] == *cursor);
    assert(exists|ends:Seq<usize>| ends[0] == *old(cursor) && ends[count as int] == *cursor && #[trigger] spans(bytes@,rows@,ends,scheme));
    Ok(rows)
}

pub(super) enum EndError { Order, Trailing }

pub(super) fn finish(rows:&[Row],cursor:usize,payload_len:usize) -> (out:Result<(),EndError>)
    ensures out.is_ok() == (ordered(rows@) && cursor == payload_len),
        (out matches Err(EndError::Order)) == !ordered(rows@),
        (out matches Err(EndError::Trailing)) == (ordered(rows@) && cursor != payload_len),
{
    if !strictly_ordered(rows) {return Err(EndError::Order);}
    if cursor != payload_len {return Err(EndError::Trailing);}
    Ok(())
}

pub(super) enum SnapshotError<E> { Position, Noncanonical, Duplicate, Codec(E) }

pub(super) open spec fn decoded<P,E,D:Fn(&Vec<u8>)->Result<P,E>>(rows:Seq<Row>,ids:Seq<P>,decode:D) -> bool {
    forall|i:int| 0 <= i < ids.len() ==> #[trigger] decode.ensures((&rows[i].0,),Ok(ids[i]))
}
pub(super) open spec fn image<P>(rows:Seq<Row>,ids:Seq<P>,history:Map<P,(RootState,u64)>) -> bool {
    &&& ids.no_duplicates()
    &&& history.dom() == ids.to_set()
    &&& forall|i:int| 0 <= i < ids.len() ==> #[trigger] history.get(ids[i]) == Some((rows[i].1,0u64))
}

pub(super) fn restore<P:Ord,E,C,D>(history:&mut BTreeMap<P,(RootState,u64)>,offset:u64,payload:&[u8],
    rows:Vec<Row>,encode:C,decode:D) -> (out:Result<(),SnapshotError<E>>)
    where C:FnOnce(&Vec<Row>)->Result<Vec<u8>,E>, D:Fn(&Vec<u8>)->Result<P,E>,
    requires btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        encode.requires((&rows,)),forall|i:int| 0 <= i < rows.len() ==> decode.requires((&rows@[i].0,)),
    ensures btree_map_inv(final(history)),out.is_err() ==> final(history)@ == old(history)@,
        (out matches Err(SnapshotError::Position)) == (offset != 0 || !old(history)@.is_empty()),
        match out {
            Ok(()) => (exists|wire:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(wire)) && wire@ == payload@) &&
                exists|ids:Seq<P>| ids.len() == rows.len() && decoded(rows@,ids,decode) && #[trigger] image(rows@,ids,final(history)@),
            Err(SnapshotError::Noncanonical) => exists|wire:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(wire)) && wire@ != payload@,
            Err(SnapshotError::Codec(e)) => encode.ensures((&rows,),Err(e)) ||
                exists|i:int| 0 <= i < rows.len() && #[trigger] decode.ensures((&rows@[i].0,),Err(e)),
            Err(SnapshotError::Duplicate) => exists|i:int,j:int,p:P| 0 <= i < j < rows.len() &&
                #[trigger] decode.ensures((&rows@[i].0,),Ok(p)) && #[trigger] decode.ensures((&rows@[j].0,),Ok(p)),
            Err(SnapshotError::Position) => true,
        },
{
    if offset != 0 || !history.is_empty() {return Err(SnapshotError::Position);}
    {
        let wire = match encode(&rows) {Ok(w) => w, Err(e) => return Err(SnapshotError::Codec(e))};
        if wire.as_slice() != payload {return Err(SnapshotError::Noncanonical);}
        assert(exists|w:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(w)) && w@ == payload@);
    }
    let mut restored = BTreeMap::new();
    let mut iter = rows.into_iter();
    let ghost mut ids = Seq::<P>::empty();
    assert(restored@.dom() =~= ids.to_set());
    loop
        invariant offset == 0, history@ == old(history)@, history@.is_empty(), btree_map_inv(history),
            exists|w:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(w)) && w@ == payload@,
            ids.len() <= rows.len(),iter.remaining() == rows@.skip(ids.len() as int),
            btree_map_inv(&restored),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            decoded(rows@,ids,decode),image(rows@,ids,restored@),
            forall|i:int| 0 <= i < rows.len() ==> decode.requires((&rows@[i].0,)),
        ensures ids.len() == rows.len(), decoded(rows@,ids,decode), image(rows@,ids,restored@), btree_map_inv(&restored),
        decreases rows.len() - ids.len(),
    {
        let ghost n = ids.len() as int;
        let Some((name,root)) = iter.next() else {assert(ids.len() == rows.len()); break;};
        assert((name,root) == rows@[n]);
        assert(iter.remaining() =~= rows@.skip(n+1));
        let owner = match decode(&name) {Ok(p) => p, Err(e) => return Err(SnapshotError::Codec(e))};
        let ghost prior = restored@;
        if restored.insert(owner,(root,0)).is_some() {
            let ghost i = ids.index_of(owner);
            assert(decode.ensures((&rows@[i].0,),Ok(owner)));
            assert(decode.ensures((&rows@[n].0,),Ok(owner)));
            return Err(SnapshotError::Duplicate);
        }
        proof {
            assert forall|k:P| ids.push(owner).to_set().contains(k) == ids.to_set().insert(owner).contains(k) by {
                assert(ids.push(owner)[n] == owner);
                if ids.push(owner).contains(k) {
                    let i = ids.push(owner).index_of(k);
                    assert(ids.push(owner)[i] == k);
                    if i < n {assert(ids[i] == k);}
                } else if ids.contains(k) {let i = ids.index_of(k); assert(ids.push(owner)[i] == k);}
            }
            assert(ids.push(owner).to_set() =~= ids.to_set().insert(owner));
            assert(ids.push(owner).no_duplicates());
            assert forall|i:int| 0 <= i < n+1 implies #[trigger] restored@.get(ids.push(owner)[i]) == Some((rows@[i].1,0u64)) by {
                if i < n {assert(prior.get(ids[i]) == Some((rows@[i].1,0u64)));}
            }
            assert forall|i:int| 0 <= i < n+1 implies #[trigger] decode.ensures((&rows@[i].0,),Ok(ids.push(owner)[i])) by {
                if i < n {assert(decode.ensures((&rows@[i].0,),Ok(ids[i])));}
            }
            ids = ids.push(owner);
        };
    }
    *history = restored;
    assert(ids.len() == rows.len());
    assert(decoded(rows@,ids,decode));
    assert(image(rows@,ids,history@));
    assert(exists|xs:Seq<P>| xs.len() == rows.len() && decoded(rows@,xs,decode) && #[trigger] image(rows@,xs,history@));
    Ok(())
}
}
