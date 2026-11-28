//! Root-journal transitions at restart, from canonical owner and root bytes to the recovered index.
use crate::closure_walk::Source;
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


/// Commit one journal frame behind a prefix, then offer its physical payload
/// to startup with independently supplied decoded fields and principal codec.
fn replay_framed_transition<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(history:&mut BTreeMap<u8,(RootState,u64)>, mut batch:Vec<u8>,base:u64,magic:[u8;8],version:u16,hash:H,
    scheme:root_wire::Scheme,record:crate::journal_transition::Record,observed_name:&[u8],
    observed_expected:Option<RootState>,observed_next:RootState,decoded:Option<u8>,recoded:Vec<u8>)
    requires btree_map_inv(old(history)),observed_name.len() < u64::MAX,
        base as int + batch.len() <= u64::MAX,
        batch.len() as int + 52 + crate::journal_transition::wire(observed_name@,scheme,observed_expected,observed_next).len() <= isize::MAX,
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
{
    use crate::journal_transition as transition;
    let payload = transition::encode(observed_name,scheme,observed_expected,observed_next).unwrap();
    let prefix = batch.len();
    let frame = crate::arena_frame::extend_batch(&mut batch,base,magic,version,&payload,hash).unwrap();
    proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
    assert(crate::arena_frame::header_bytes(magic,version,frame.payload_len,frame.checksum).len() == 52);
    let start = (frame.offset-base) as usize;
    assert(start == prefix && batch.len() == start + 52 + payload.len());
    let body = &batch[start+52..];
    assert(body@ =~= payload@);
    let ghost expected_image = transition::wire(record.principal@,scheme,record.expected,record.replacement);
    let ghost observed_image = transition::wire(observed_name@,scheme,observed_expected,observed_next);
    let ghost before = history@;
    let decode = |name:&[u8]| -> (o:Option<u8>) requires name@ == record.principal@, ensures o == decoded, {decoded};
    let recode = |_:&u8| -> (b:Vec<u8>) ensures b@ == recoded@, {recoded};
    let result = record.replay(history,scheme,frame.offset,body,decode,recode);
    proof {
        if record.principal.len() >= u64::MAX {assert(result matches Err(transition::Error::Length));}
        else if observed_image != expected_image {assert(result matches Err(transition::Error::Noncanonical));}
        else if decoded.is_none() || recoded@ != record.principal@ {assert(result matches Err(transition::Error::Principal));}
        else {
            let p = decoded.unwrap();
            let actual = if before.contains_key(p) {Some(before[p].0)} else {None};
            let next = match actual {Some(r)=>r.generation.value() as int + 1,None=>0int};
            assert(result.is_ok() == (actual == record.expected && record.replacement.generation.value() == next));
            if result.is_ok() {assert(history@ == before.insert(p,(record.replacement,(base as int + prefix) as u64)));}
        }
        if result.is_err() {assert(history@ == before);}
    }
}

/// Replay the canonical first root and validate exactly the owning closure
/// reached through its commit. A reachable reference never authorizes unrelated
/// preload entries, and a failed walk retains the root's physical frame offset.
fn replay_then_validate(table:&BTreeMap<crate::ObjectId,crate::ObjectRecord>,owner:u8,root:RootState,
    scheme:root_wire::Scheme,offset:u64,child:crate::ObjectId,scope:Ghost<Set<crate::ObjectId>>)
    requires crate::closure_load::Preload(table).valid(),root.generation.value() == 0,
        crate::closure_walk::closed(root.commit,Set::empty(),crate::closure_load::Preload(table).edges(),scope@),
{
    use crate::{journal_transition as tr,journal_closure as gate,closure_load::Preload,closure_walk::{self as walk,Source}};
    let record = tr::Record {principal:vec![owner],expected:None,replacement:root};
    assert(record.principal@ =~= seq![owner]);
    let bytes = tr::encode(&record.principal,scheme,None,root).unwrap();
    let mut history = BTreeMap::new();
    let decoded = |name:&[u8]| -> (p:Option<u8>)
        requires name@ == seq![owner], ensures p == Some(owner), {Some(name[0])};
    let encoded = |p:&u8| -> (v:Vec<u8>) ensures v@ == seq![*p], {let v = vec![*p]; assert(v@ =~= seq![*p]); v};
    let r = record.replay(&mut history,scheme,offset,&bytes,decoded,encoded);
    assert(r.is_ok());
    assert(history@ == Map::<u8,(RootState,u64)>::empty().insert(owner,(root,offset)));
    assert(history@.contains_key(owner) && history@[owner] == (root,offset));
    let ghost graph = Preload(table).edges();
    match gate::validate(&history,table) {
        Ok(known)=>{
            assert(exists|s:Set<crate::ObjectId>| #[trigger] gate::admitted(table,history@[owner].0.commit,s) && s.subset_of(known@));
            let ghost nodes = choose|s:Set<crate::ObjectId>| #[trigger] gate::admitted(table,root.commit,s) && s.subset_of(known@);
            assert(table@.contains_key(root.commit) && table@[root.commit].contents().0 is Commit);
            assert(known@.contains(root.commit));
            assert(graph[root.commit].contains(child) ==> known@.contains(child));
            assert forall|k:crate::ObjectId| #[trigger] known@.contains(k) implies nodes.contains(k) by {
                let (p,s) = choose|p:u8,s:Set<crate::ObjectId>| history@.contains_key(p) &&
                    #[trigger] gate::admitted(table,history@[p].0.commit,s) && s.contains(k);
                assert(p == owner && s.subset_of(nodes));
            }
            assert(known@ =~= nodes);
            assert(known@.subset_of(scope@) && known@.subset_of(table@.dom()));
            assert(exists|rank:Map<crate::ObjectId,nat>| rank.dom() == known@ && #[trigger] walk::ranked(graph,Set::empty(),rank));
        },
        Err(e)=>{
            assert(gate::refused(table,root.commit,offset,e));
            match e {
                gate::Failure::Walk(pos,walk::Failure::Cycle(id))=>{
                    assert(pos == offset && scope@.contains(id) && walk::reaches(graph,Set::empty(),id,id));
                },
                gate::Failure::Walk(pos,walk::Failure::Source(id,missing))=>{
                    assert(pos == offset && missing == id && scope@.contains(id) && !table@.contains_key(id));
                },
                gate::Failure::Commit(pos,id,crate::closure_load::CommitError::WrongKind(k))=>{
                    assert(pos == offset && id == root.commit && table@[id].contents().0 == k && !(k is Commit));
                },
                _=>{assert(false);},
            }
        },
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

type PreloadTable = BTreeMap<crate::ObjectId,crate::ObjectRecord>;
type PendingIds = std::collections::BTreeSet<crate::ObjectId>;
type ReadRow = (crate::ObjectId,crate::ArenaLocation);

/// Install the next new ID using the production callback. The callback's
/// before/after maps and scheduled children imply the aggregate wave law.
proof fn extend_wave(start:Map<crate::ObjectId,crate::ObjectRecord>,seen:Set<crate::ObjectId>,
    before:Map<crate::ObjectId,crate::ObjectRecord>,pending:Set<crate::ObjectId>,id:crate::ObjectId,
    record:crate::ObjectRecord)
    requires crate::journal_preload::wave(start,seen,before,pending),!before.contains_key(id),
    ensures crate::journal_preload::wave(start,seen.insert(id),before.insert(id,record),
        pending.union(crate::closure_walk::children(record.contents().3).difference(before.dom()))),
{
    use crate::journal_preload::outgoing;
    let after = before.insert(id,record);
    let added = crate::closure_walk::children(record.contents().3).difference(before.dom());
    let next = pending.union(added);
    assert(after.dom() =~= start.dom().union(seen.insert(id)));
    assert forall|k:crate::ObjectId| seen.insert(id).contains(k) implies
        #[trigger] outgoing(after,k).subset_of(after.dom().union(next)) by {
        if k == id { assert(after[k] == record); }
        else { assert(outgoing(before,k).subset_of(before.dom().union(pending))); }
    }
    assert forall|c:crate::ObjectId| #[trigger] next.contains(c) implies exists|k:crate::ObjectId|
        seen.insert(id).contains(k) && #[trigger] outgoing(after,k).contains(c) by {
        if added.contains(c) {assert(outgoing(after,id).contains(c));}
        else {
            let k = choose|k:crate::ObjectId| seen.contains(k) && #[trigger] outgoing(before,k).contains(c);
            assert(k != id && outgoing(after,k).contains(c));
        }
    }
}

/// Reordering complete rows preserves distinct frontier IDs, including when
/// two different IDs name the same physical offset.
proof fn permute_frontier(input:Seq<ReadRow>,output:Seq<ReadRow>)
    requires input.to_multiset() == output.to_multiset(), input.map(|_,r:ReadRow|r.0).no_duplicates(),
    ensures output.map(|_,r:ReadRow|r.0).no_duplicates(),
        crate::journal_preload::selected(output) == crate::journal_preload::selected(input),
{
    let old = input.map(|_,r:ReadRow|r.0);
    let new = output.map(|_,r:ReadRow|r.0);
    assert(input.no_duplicates()) by {
        assert forall|i:int,j:int| 0 <= i < input.len() && 0 <= j < input.len() && i!=j implies
            #[trigger] input[i] != #[trigger] input[j] by {assert(old[i] != old[j]);}
    }
    input.lemma_multiset_has_no_duplicates();
    output.lemma_multiset_has_no_duplicates_conv();
    input.to_multiset_ensures();
    output.to_multiset_ensures();
    assert forall|i:int| 0 <= i < output.len() implies input.contains(#[trigger] output[i]) by {
        assert(output.contains(output[i]));
        assert(output.to_multiset().count(output[i])>0);
    }
    assert forall|i:int,j:int| 0 <= i < output.len() && 0 <= j < output.len() && i!=j implies
        #[trigger] new[i] != #[trigger] new[j] by {
        let a = choose|a:int| 0 <= a < input.len() && input[a]==output[i];
        let b = choose|b:int| 0 <= b < input.len() && input[b]==output[j];
        assert(output[i]!=output[j] && a!=b);
        assert(old[a]!=old[b]);
    }
    old.to_set_ensures();
    new.to_set_ensures();
    assert forall|k:crate::ObjectId| new.to_set().contains(k) == old.to_set().contains(k) by {
        if new.contains(k) {
            let i = choose|i:int| 0 <= i < new.len() && new[i]==k;
            assert(output[i].0==k && input.contains(output[i]));
            let a = choose|a:int| 0 <= a < input.len() && input[a]==output[i];
            assert(old[a]==k);
            assert(old[a]==k && old.contains(k));
        } else if old.contains(k) {
            let a = choose|a:int| 0 <= a < old.len() && old[a]==k;
            assert(input.contains(input[a]) && input.to_multiset().count(input[a])>0);
            assert(output.contains(input[a]));
            let i = choose|i:int| 0 <= i < output.len() && output[i]==input[a];
            assert(input[a].0==k && output[i].0==k);
            assert(new[i]==k);
            assert(new.contains(k));
        }
    }
    assert(old.to_set() =~= new.to_set());
}

type WaveState = (PreloadTable,PendingIds);
type Decoded<'a> = Result<(crate::ObjectRecord,&'a [u8]),()>;

spec fn installed(s:WaveState,id:crate::ObjectId,r:crate::ObjectRecord,t:WaveState) -> bool {
    &&& btree_map_inv(&t.0) && vstd::std_specs::btree::btree_set_inv(&t.1)
    &&& t.0@ == s.0@.insert(id,r)
    &&& t.1@ == s.1@.union(crate::closure_walk::children(r.contents().3).difference(s.0@.dom()))
}

spec fn decoded_at<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>>(
    row:ReadRow,state:WaveState,decode:D) -> bool {
    state.0@.contains_key(row.0) && exists|p:&'a [u8]| #[trigger] decode.ensures((row.0,row.1),Ok((state.0@[row.0],p)))
}

/// A delivered record remains at its requested ID after later rows in the
/// same span. The decoder relation also retains the original location.
proof fn delivery_record<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>,
    A:Fn(WaveState,crate::ObjectId,crate::ArenaLocation,crate::ObjectRecord,&'a [u8])->Result<WaveState,()>>(
    rows:Seq<ReadRow>,states:Seq<WaveState>,decode:D,accept:A,j:int,end:int)
    requires 0 <= j < end <= rows.len(), crate::indexed_frame::delivered(rows,states,decode,accept),
        rows.map(|_,r:ReadRow|r.0).no_duplicates(),
        forall|s:WaveState,id,loc,r,p,t| #[trigger] accept.ensures((s,id,loc,r,p),Ok(t)) ==> installed(s,id,r,t),
    ensures decoded_at(rows[j],states[end],decode),
    decreases end,
{
    let i = end-1;
    let (id,loc) = rows[i];
    assert(crate::indexed_frame::sent(rows[i],states[i],states[end],decode,accept));
    let (record,payload) = choose|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((id,loc),Ok((r,p))) &&
        accept.ensures((states[i],id,loc,r,p),Ok(states[end]));
    assert(installed(states[i],id,record,states[end]));
    if j < i {
        delivery_record(rows,states,decode,accept,j,i);
        let ids = rows.map(|_,r:ReadRow|r.0);
        assert(ids[j]!=ids[i]);
        assert(id!=rows[j].0);
        let previous = choose|p:&'a [u8]| #[trigger] decode.ensures((rows[j].0,rows[j].1),Ok((states[i].0@[rows[j].0],p)));
        assert(states[end].0@[rows[j].0] == states[i].0@[rows[j].0]);
        assert(decode.ensures((rows[j].0,rows[j].1),Ok((states[end].0@[rows[j].0],previous))));
    } else {
        assert(states[end].0@[id]==record && rows[j]==(id,loc));
        assert(decode.ensures((rows[j].0,rows[j].1),Ok((states[end].0@[rows[j].0],payload))));
    }
}

proof fn delivery_preserves<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>,
    A:Fn(WaveState,crate::ObjectId,crate::ArenaLocation,crate::ObjectRecord,&'a [u8])->Result<WaveState,()>>(
    rows:Seq<ReadRow>,states:Seq<WaveState>,decode:D,accept:A,end:int)
    requires 0 <= end <= rows.len(),crate::indexed_frame::delivered(rows,states,decode,accept),
        states.first().0@.dom().disjoint(crate::journal_preload::selected(rows)),
        forall|s:WaveState,id,loc,r,p,t| #[trigger] accept.ensures((s,id,loc,r,p),Ok(t)) ==> installed(s,id,r,t),
    ensures states.first().0@.submap_of(states[end].0@),
    decreases end,
{
    if end == 0 { return; }
    let i = end-1;
    delivery_preserves(rows,states,decode,accept,i);
    let (id,loc) = rows[i];
    let ids = rows.map(|_,row:ReadRow|row.0);
    ids.to_set_ensures();
    assert(ids[i]==id && ids.contains(id));
    assert(crate::indexed_frame::sent(rows[i],states[i],states[end],decode,accept));
    let (r,p) = choose|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((id,loc),Ok((r,p))) &&
        accept.ensures((states[i],id,loc,r,p),Ok(states[end]));
    assert(installed(states[i],id,r,states[end]));
}

/// Interpret the successful prefix exposed by the production delivery loop.
proof fn delivery_wave<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>,
    A:Fn(WaveState,crate::ObjectId,crate::ArenaLocation,crate::ObjectRecord,&'a [u8])->Result<WaveState,()>>(
    rows:Seq<ReadRow>,states:Seq<WaveState>,decode:D,accept:A,end:int,
    initial:Map<crate::ObjectId,crate::ObjectRecord>,seen:Set<crate::ObjectId>)
    requires 0 <= end <= rows.len(), crate::indexed_frame::delivered(rows,states,decode,accept),
        rows.map(|_,r:ReadRow|r.0).no_duplicates(),
        states.first().0@.dom().disjoint(crate::journal_preload::selected(rows)),
        btree_map_inv(&states.first().0),vstd::std_specs::btree::btree_set_inv(&states.first().1),
        crate::journal_preload::wave(initial,seen,states.first().0@,states.first().1@),
        forall|s:WaveState,id,loc,r,p,t| #[trigger] accept.ensures((s,id,loc,r,p),Ok(t)) ==> installed(s,id,r,t),
    ensures btree_map_inv(&states[end].0),vstd::std_specs::btree::btree_set_inv(&states[end].1),
        crate::journal_preload::wave(initial,seen.union(crate::journal_preload::selected(rows.take(end))),states[end].0@,states[end].1@),
    decreases end,
{
    use crate::journal_preload::{wave,selected};
    let ids = rows.map(|_,r:ReadRow|r.0);
    ids.to_set_ensures();
    if end == 0 {
        assert(selected(rows.take(0)) =~= Set::empty());
        assert(seen.union(Set::empty()) =~= seen);
    } else {
        let i = end - 1;
        delivery_wave(rows,states,decode,accept,i,initial,seen);
        let (id,loc) = rows[i];
        let prior = rows.take(i).map(|_,r:ReadRow|r.0);
        prior.to_set_ensures();
        assert(!prior.contains(id)) by {
            if prior.contains(id) {
                let j = choose|j:int| 0 <= j < prior.len() && prior[j]==id;
                assert(ids[j]==ids[i] && j<i);
            }
        }
        assert(0 <= i < ids.len());
        assert(ids[i]==id);
        assert(ids.contains(id));
        assert(!states.first().0@.contains_key(id));
        assert(!seen.contains(id));
        assert(crate::indexed_frame::sent(rows[i],states[i],states[i+1],decode,accept));
        let (r,p) = choose|r:crate::ObjectRecord,p:&'a [u8]| #[trigger] decode.ensures((id,loc),Ok((r,p))) &&
            accept.ensures((states[i],id,loc,r,p),Ok(states[i+1]));
        assert(selected(rows.take(i)) == prior.to_set());
        assert(!states[i].0@.contains_key(id));
        extend_wave(initial,seen.union(prior.to_set()),states[i].0@,states[i].1@,id,r);
        assert(rows.take(i+1).map(|_,r:ReadRow|r.0) =~= prior.push(id));
        prior.push(id).to_set_ensures();
        assert forall|k:crate::ObjectId| prior.push(id).to_set().contains(k) == prior.to_set().insert(id).contains(k) by {
            vstd::seq_lib::lemma_seq_contains_after_push(prior,id,k);
        }
        assert(prior.push(id).to_set() =~= prior.to_set().insert(id));
        assert(seen.union(prior.to_set().insert(id)) =~= seen.union(prior.to_set()).insert(id));
    }

}

spec fn decoded_rows<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>>(
    rows:Seq<ReadRow>,state:WaveState,decode:D) -> bool {
    forall|j:int| 0 <= j < rows.len() ==> decoded_at(#[trigger] rows[j],state,decode)
}

fn read_wave<'a,D:Fn(crate::ObjectId,crate::ArenaLocation)->Decoded<'a>>(
    start:WaveState,rows:&[ReadRow],decode:D,
    Ghost(initial):Ghost<Map<crate::ObjectId,crate::ObjectRecord>>,Ghost(seen):Ghost<Set<crate::ObjectId>>) -> (out:Result<WaveState,()>)
    requires crate::journal_preload::wave(initial,seen,start.0@,start.1@),
        vstd::std_specs::btree::btree_set_inv(&start.1),start.0@.dom().disjoint(crate::journal_preload::selected(rows@)),
        rows@.map(|_,row:ReadRow|row.0).no_duplicates(),btree_map_inv(&start.0),obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|id:crate::ObjectId,loc:crate::ArenaLocation| #[trigger] decode.requires((id,loc)),
    ensures out matches Ok((t,n)) ==> btree_map_inv(&t) && vstd::std_specs::btree::btree_set_inv(&n) &&
        crate::journal_preload::wave(initial,seen.union(crate::journal_preload::selected(rows@)),t@,n@),
        out matches Ok(v) ==> decoded_rows(rows@,v,decode) && start.0@.submap_of(v.0@),
{
    let accept = |s:WaveState,id:crate::ObjectId,_loc:crate::ArenaLocation,r:crate::ObjectRecord,_p:&'a [u8]| -> (out:Result<WaveState,()>)
        requires btree_map_inv(&s.0),vstd::std_specs::btree::btree_set_inv(&s.1),
        ensures out matches Ok(t) && installed(s,id,r,t),
    {
        let (mut table,mut next) = s;
        crate::journal_preload::accept(&mut table,&mut next,id,r);
        Ok((table,next))
    };
    assert forall|i:int,states:Seq<WaveState>,r:crate::ObjectRecord,p:&'a [u8]| 0 <= i < rows.len() &&
        states.first()==start && #[trigger] crate::indexed_frame::delivered(rows@.take(i),states,decode,accept) &&
        #[trigger] decode.ensures((rows@[i].0,rows@[i].1),Ok((r,p))) implies
        accept.requires((states.last(),rows@[i].0,rows@[i].1,r,p)) by {
        let prefix = rows@.take(i);
        let ids = rows@.map(|_,r:ReadRow|r.0);
        let keys = prefix.map(|_,r:ReadRow|r.0);
        assert(keys =~= ids.take(i));
        ids.to_set_ensures();
        keys.to_set_ensures();
        assert forall|k:crate::ObjectId| keys.contains(k) implies ids.contains(k) by {
            let j = choose|j:int| 0 <= j < keys.len() && keys[j]==k;
            assert(ids[j]==k);
        }
        delivery_wave(prefix,states,decode,accept,i,initial,seen);
    }
    let out = crate::indexed_frame::deliver(rows,start,decode,accept);
    if let Ok(t) = &out { proof {
        let states = choose|states:Seq<WaveState>| #[trigger] crate::indexed_frame::delivered(rows@,states,decode,accept) &&
            states.first()==start && states.last()==*t;
        delivery_wave(rows@,states,decode,accept,rows.len() as int,initial,seen);
        assert forall|j:int| 0 <= j < rows.len() implies decoded_at(#[trigger] rows@[j],*t,decode) by { delivery_record(rows@,states,decode,accept,j,rows.len() as int); }
        assert(decoded_rows(rows@,*t,decode));
        delivery_preserves(rows@,states,decode,accept,rows.len() as int);
        assert(rows@.take(rows.len() as int) =~= rows@);
    }}
    out
}

/// The two pieces of a disjoint index interval contain exactly the IDs
/// in that interval, even when distinct IDs have the same physical offset.
proof fn split_ids(rows:Seq<ReadRow>,lo:int,hi:int)
    requires 0 <= lo <= hi <= rows.len(), rows.map(|_,r:ReadRow|r.0).no_duplicates(),
    ensures crate::journal_preload::selected(rows.take(hi)) ==
            crate::journal_preload::selected(rows.take(lo)).union(crate::journal_preload::selected(rows.subrange(lo,hi))),
        crate::journal_preload::selected(rows.take(lo)).disjoint(crate::journal_preload::selected(rows.subrange(lo,hi))),
        crate::journal_preload::selected(rows.take(hi)).subset_of(crate::journal_preload::selected(rows)),
        rows.subrange(lo,hi).map(|_,r:ReadRow|r.0).no_duplicates(),
{
    let ids = rows.map(|_,r:ReadRow|r.0);
    let left = rows.take(lo).map(|_,r:ReadRow|r.0);
    let right = rows.subrange(lo,hi).map(|_,r:ReadRow|r.0);
    let all = rows.take(hi).map(|_,r:ReadRow|r.0);
    assert(left =~= ids.take(lo));
    assert(right =~= ids.subrange(lo,hi));
    assert(all =~= left + right);
    left.to_set_ensures(); right.to_set_ensures(); all.to_set_ensures(); ids.to_set_ensures();
    assert forall|k:crate::ObjectId| left.contains(k) implies !right.contains(k) by {
        if right.contains(k) {
            let i = choose|i:int| 0 <= i < left.len() && left[i]==k;
            let j = choose|j:int| 0 <= j < right.len() && right[j]==k;
            assert(ids[i]==ids[lo+j] && i<lo+j);
        }
    }
    assert forall|k:crate::ObjectId| all.contains(k) implies ids.contains(k) by {
        let i = choose|i:int| 0 <= i < all.len() && all[i]==k;
        assert(ids[i]==k);
    }
    assert forall|k:crate::ObjectId| all.contains(k) == (left.contains(k) || right.contains(k)) by {
        if all.contains(k) {
            let i = choose|i:int| 0 <= i < all.len() && all[i]==k;
            if i<lo { assert(left[i]==k); } else { assert(right[i-lo]==k); }
        } else if left.contains(k) {
            let i = choose|i:int| 0 <= i < left.len() && left[i]==k;
            assert(all[i]==k);
        } else if right.contains(k) {
            let j = choose|j:int| 0 <= j < right.len() && right[j]==k;
            assert(all[lo+j]==k);
        }
    }
    assert(all.to_set() =~= left.to_set().union(right.to_set()));
}

spec fn span_state(start:Map<crate::ObjectId,crate::ObjectRecord>,keys:Set<crate::ObjectId>,s:WaveState) -> bool {
    btree_map_inv(&s.0) && vstd::std_specs::btree::btree_set_inv(&s.1) &&
        crate::journal_preload::wave(start,keys,s.0@,s.1@)
}

proof fn dispatched_wave<V:Fn(WaveState,&[ReadRow],u64,u64)->Result<WaveState,()>>(
    rows:Seq<ReadRow>,end:int,start:WaveState,state:WaveState,limit:u64,visit:V)
    requires 0 <= end <= rows.len(),crate::indexed_frame::dispatched(rows,end,start,state,limit,visit),
        rows.map(|_,r:ReadRow|r.0).no_duplicates(),start.0@.dom().disjoint(crate::journal_preload::selected(rows)),
        span_state(start.0@,Set::empty(),start),
        forall|s:WaveState,p:&[ReadRow],base:u64,n:u64,t:WaveState| #[trigger] visit.ensures((s,p,base,n),Ok(t)) ==>
            span_state(start.0@,s.0@.dom().difference(start.0@.dom()).union(crate::journal_preload::selected(p@)),t),
    ensures span_state(start.0@,crate::journal_preload::selected(rows.take(end)),state),
    decreases end,
{
    use crate::indexed_frame::{batch,frame_end,dispatched};
    use crate::journal_preload::selected;
    if end==0 { assert(selected(rows.take(0)) =~= Set::empty()); return; }
    let (lo,prior,part,size) = choose|lo:int,prior:WaveState,part:&[ReadRow],size:u64|
        batch(rows,lo,end,limit) && part@ == rows.subrange(lo,end) &&
        size as int == frame_end(rows[end-1].1)-rows[lo].1.offset &&
        #[trigger] visit.ensures((prior,part,rows[lo].1.offset,size),Ok(state)) &&
        dispatched(rows,lo,start,prior,limit,visit);
    dispatched_wave(rows,lo,start,prior,limit,visit);
    split_ids(rows,lo,end);
    assert(prior.0@.dom().difference(start.0@.dom()) =~= selected(rows.take(lo)));
}

spec fn media_record(image:Seq<u8>,row:ReadRow,scheme:root_wire::Scheme,r:crate::ObjectRecord) -> bool {
    let at = row.1.offset as int + 52;
    let body = image.subrange(at,at+row.1.payload_len);
    &&& 40 <= row.1.payload_len && at+row.1.payload_len <= image.len()
    &&& crate::verified_record::record_at(body,40,scheme,r)
    &&& row.0.digest()==body.subrange(8,40)
}

/// Later spans preserve earlier installations, so the media relation established
/// in the selected span still holds after the last positional read.
proof fn dispatched_record<V:Fn(WaveState,&[ReadRow],u64,u64)->Result<WaveState,()>>(
    rows:Seq<ReadRow>,j:int,end:int,start:WaveState,state:WaveState,limit:u64,visit:V,image:Seq<u8>,scheme:root_wire::Scheme)
    requires 0 <= j < end <= rows.len(),crate::indexed_frame::dispatched(rows,end,start,state,limit,visit),
        forall|s:WaveState,p:&[ReadRow],base:u64,n:u64,t:WaveState| #[trigger] visit.ensures((s,p,base,n),Ok(t)) ==>
            s.0@.submap_of(t.0@) && forall|i:int| 0 <= i < p.len() ==> {
                let row = #[trigger] p@[i];
                t.0@.contains_key(row.0) && media_record(image,row,scheme,t.0@[row.0])
            },
    ensures state.0@.contains_key(rows[j].0) && media_record(image,rows[j],scheme,state.0@[rows[j].0]),
    decreases end,
{
    use crate::indexed_frame::{batch,frame_end,dispatched};
    let (lo,prior,part,size) = choose|lo:int,prior:WaveState,part:&[ReadRow],size:u64|
        batch(rows,lo,end,limit) && part@ == rows.subrange(lo,end) &&
        size as int == frame_end(rows[end-1].1)-rows[lo].1.offset &&
        #[trigger] visit.ensures((prior,part,rows[lo].1.offset,size),Ok(state)) &&
        dispatched(rows,lo,start,prior,limit,visit);
    if j < lo {
        dispatched_record(rows,j,lo,start,prior,limit,visit,image,scheme);
        assert(prior.0@.submap_of(state.0@));
        assert(prior.0@.contains_key(rows[j].0));
        assert(state.0@.contains_key(rows[j].0));
        assert(prior.0@[rows[j].0] == state.0@[rows[j].0]);
    } else {
        assert(part@[j-lo]==rows[j]);
    }
}

/// Interpret the buffer while its borrow is live. Only owned records escape.
fn install_buffer<'a,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&crate::ObjectRecord)->[u8;32]+Copy>(
    s:WaveState,rows:&[ReadRow],span:&'a [u8],base:u64,format:crate::indexed_frame::Format,
    hash:H,identify:I,origin:Ghost<Map<crate::ObjectId,crate::ObjectRecord>>,image:Ghost<Seq<u8>>)
    -> (out:Result<WaveState,()>)
    requires span_state(origin@,s.0@.dom().difference(origin@.dom()),s),
        s.0@.dom().disjoint(crate::journal_preload::selected(rows@)),rows@.map(|_,r:ReadRow|r.0).no_duplicates(),
        span.len()>0 ==> base as int + span.len() <= image@.len() && span@ == image@.subrange(base as int,base as int+span.len()),
        obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
    ensures out matches Ok(v) ==> span_state(origin@,s.0@.dom().difference(origin@.dom()).union(crate::journal_preload::selected(rows@)),v) && s.0@.submap_of(v.0@) &&
        forall|j:int| 0 <= j < rows.len() ==> { let row = #[trigger] rows@[j]; v.0@.contains_key(row.0) && media_record(image@,row,format.scheme,v.0@[row.0]) },
{
    let decode = |id:crate::ObjectId,loc:crate::ArenaLocation| -> (out:Decoded<'a>)
        ensures out matches Ok((r,_)) ==> media_record(image@,(id,loc),format.scheme,r),
    {
        match crate::indexed_frame::read(span,base,loc,id,format,hash,identify) {
            Ok((r,p)) => {
                let ghost at = loc.offset as int + 52;
                assert(crate::indexed_frame::fits(span@,base,loc));
                assert(p@ =~= image@.subrange(at,at+loc.payload_len));
                assert(crate::verified_record::tag(p@,0,format.scheme));
                assert(40 <= loc.payload_len);
                assert(crate::verified_record::record_at(p@,40,format.scheme,r));
                assert(id.digest()==p@.subrange(8,40));
                Ok((r,p))
            },
            Err(_) => Err(()),
        }
    };
    let out = read_wave(s,rows,decode,origin,Ghost(s.0@.dom().difference(origin@.dom())));
    if let Ok(v) = &out { proof {
        assert forall|j:int| 0 <= j < rows.len() implies media_record(image@,#[trigger] rows@[j],format.scheme,v.0@[rows@[j].0]) by {
            let (id,loc) = rows@[j];
            let p = choose|p:&'a [u8]| #[trigger] decode.ensures((id,loc),Ok((v.0@[id],p)));
        }
    }}
    out
}

fn preload_closure<M:crate::positional_read::Media,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,I:Fn(&crate::ObjectRecord)->[u8;32]+Copy>(
    index:&BTreeMap<crate::ObjectId,crate::ArenaLocation>,roots:PendingIds,media:&M,target:u64,format:crate::indexed_frame::Format,hash:H,identify:I)
    requires btree_map_inv(index),vstd::std_specs::btree::btree_set_inv(&roots),
        obeys_cmp::<crate::ObjectId>(),obeys_cmp_concrete_eq::<crate::ObjectId>(),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash.requires((m,n,p)),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
{
    use crate::journal_preload::{preload,closed_on,selected,wave,outgoing,Error};
    let limit = format.limit;
    let read = |t:PreloadTable,r:&[ReadRow]| -> (out:Result<(PreloadTable,PendingIds),()>)
        requires btree_map_inv(&t), t@.dom().disjoint(selected(r@)),r@.map(|_,row:ReadRow|row.0).no_duplicates(),
        ensures out matches Ok((u,n)) ==> btree_map_inv(&u) && vstd::std_specs::btree::btree_set_inv(&n) &&
            wave(t@,selected(r@),u@,n@) &&
            forall|j:int| 0 <= j < r.len() ==> media_record(media.image(),#[trigger] r@[j],format.scheme,u@[r@[j].0]),
    {
        let ordered = crate::indexed_frame::ordered(r);
        proof { permute_frontier(r@,ordered@); }
        let next = PendingIds::new();
        assert(next@ =~= Set::empty());
        assert(t@.dom().union(Set::empty()) =~= t@.dom());
        assert(t@.submap_of(t@));
        assert(Set::empty().union(selected(ordered@)) =~= selected(ordered@));
        let origin = Ghost(t@);
        let start = (t,next);
        assert(span_state(origin@,Set::empty(),start));
        let visit = |s:WaveState,p:&[ReadRow],base:u64,len:u64| -> (out:Result<WaveState,()>)
            requires span_state(origin@,s.0@.dom().difference(origin@.dom()),s),
                s.0@.dom().disjoint(selected(p@)),p@.map(|_,r:ReadRow|r.0).no_duplicates(),
            ensures out matches Ok(v) ==> span_state(origin@,s.0@.dom().difference(origin@.dom()).union(selected(p@)),v) && s.0@.submap_of(v.0@) &&
                forall|j:int| 0 <= j < p.len() ==> { let row = #[trigger] p@[j]; v.0@.contains_key(row.0) && media_record(media.image(),row,format.scheme,v.0@[row.0]) },
        {
            let consume = |span:&[u8],at:u64| -> (out:Result<WaveState,()>)
                requires at == base,crate::positional_read::interval(media,base,len,span),
                ensures out matches Ok(v) ==> span_state(origin@,s.0@.dom().difference(origin@.dom()).union(selected(p@)),v) && s.0@.submap_of(v.0@) &&
                    forall|j:int| 0 <= j < p.len() ==> { let row = #[trigger] p@[j]; v.0@.contains_key(row.0) && media_record(media.image(),row,format.scheme,v.0@[row.0]) },
            { install_buffer(s,p,span,at,format,hash,identify,origin,Ghost(media.image())) };
            match crate::positional_read::with_span(media,base,len,consume) {
                Ok(v) => {
                    proof {
                        let bytes = choose|bytes:&[u8]| crate::positional_read::interval(media,base,len,bytes) &&
                            #[trigger] consume.ensures((bytes,base),Ok(v));
                    }
                    Ok(v)
                },
                Err(_) => Err(()),
            }
        };
        assert forall|lo:int,hi:int,s:WaveState,p:&[ReadRow],n:u64| #[trigger] crate::indexed_frame::batch(ordered@,lo,hi,limit) &&
            #[trigger] crate::indexed_frame::dispatched(ordered@,lo,start,s,limit,visit) && p@ == ordered@.subrange(lo,hi) &&
            n as int == crate::indexed_frame::frame_end(ordered@[hi-1].1)-ordered@[lo].1.offset implies
            #[trigger] visit.requires((s,p,ordered@[lo].1.offset,n)) by {
            dispatched_wave(ordered@,lo,start,s,limit,visit);
            split_ids(ordered@,lo,hi);
            assert(s.0@.dom().difference(t@.dom()) =~= selected(ordered@.take(lo)));
        }
        match crate::indexed_frame::dispatch(&ordered,target,limit,start,visit) {
            Ok(v) => {
                proof { dispatched_wave(ordered@,ordered.len() as int,start,v,limit,visit); }
                assert(ordered@.take(ordered.len() as int) =~= ordered@);
                proof {
                    r@.to_multiset_ensures();
                    ordered@.to_multiset_ensures();
                    assert forall|j:int| 0 <= j < r.len() implies media_record(media.image(),#[trigger] r@[j],format.scheme,v.0@[r@[j].0]) by {
                        let row = r@[j];
                        assert(r@.contains(row));
                        assert(ordered@.to_multiset().count(row)>0);
                        assert(ordered@.contains(row));
                        let i = choose|i:int| 0 <= i < ordered.len() && ordered@[i]==row;
                        dispatched_record(ordered@,i,ordered.len() as int,start,v,limit,visit,media.image(),format.scheme);
                    }
                }
                Ok(v)
            },
            Err(_) => Err(()),
        }
    };
    match preload(index,roots,read) {
        Ok(table) => {
            assert(table@.dom().union(Set::empty()) =~= table@.dom());
            assert(crate::journal_preload::covered(roots@,table@,Set::empty()));
            assert forall|k:crate::ObjectId| table@.contains_key(k) implies
                #[trigger] media_record(media.image(),(k,index@[k]),format.scheme,table@[k]) by {
                assert(crate::journal_preload::read_record((k,index@[k]),table@[k],read));
                let (prior,batch,after,next,j) = choose|prior:PreloadTable,batch:&[ReadRow],after:PreloadTable,next:PendingIds,j:int|
                    0 <= j < batch.len() && #[trigger] batch@[j] == (k,index@[k]) && after@.contains_key(k) && after@[k]==table@[k] &&
                    #[trigger] read.ensures((prior,batch),Ok((after,next)));
                assert(media_record(media.image(),batch@[j],format.scheme,after@[k]));
            }
            assert(roots@.subset_of(table@.dom()));
            assert(table@.dom().subset_of(index@.dom()));
            assert forall|k:crate::ObjectId| table@.contains_key(k) implies #[trigger] outgoing(table@,k).subset_of(table@.dom()) by {};
            assert forall|scope:Set<crate::ObjectId>| roots@.subset_of(scope) && #[trigger] closed_on(table@,scope)
                implies table@.dom().subset_of(scope) by {};
        },
        Err(Error::Missing(id)) => { proof {
            assert(!index@.contains_key(id));
            assert(exists|t:Map<crate::ObjectId,crate::ObjectRecord>,f:Set<crate::ObjectId>|
                #[trigger] crate::journal_preload::pending_failure(roots@,index@,t,f) &&
                f.contains(id) && !t.contains_key(id) && (roots@.contains(id) ||
                    exists|parent:crate::ObjectId| t.contains_key(parent) && #[trigger] outgoing(t,parent).contains(id)));
        }},
        Err(Error::Read(e)) => {
            assert(crate::journal_preload::read_failure(roots@,index@,read,e));
            assert(exists|t:PreloadTable,r:&[ReadRow]| r.len()>0 &&
                (forall|i:int| 0 <= i < r.len() ==> index@.contains_key(#[trigger] r@[i].0) &&
                    index@[r@[i].0] == r@[i].1) && #[trigger] read.ensures((t,r),Err(e)));
        },
    }
}

}
