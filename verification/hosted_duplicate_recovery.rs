//! Recover from checksum-validated physical frames, including redundant copies.
use crate::{ArenaLocation,ObjectId,checkpoint_admission as admission,duplicates::{self,Media},root_wire::Scheme,verified_record};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {

/// Each occupied offset supplies the payload and checksum from a bounded,
/// authenticated frame read. Empty offsets are not frame starts.
struct Frames<'a> { slots:&'a [Option<(&'a [u8],[u8;32])>] }

impl Media for Frames<'_> {
    closed spec fn frames(&self) -> vstd::imap::IMap<u64,Seq<u8>> {
        vstd::imap::IMap::new(|at:u64| at < self.slots.len() && self.slots@[at as int].is_some(),
            |at:u64| self.slots@[at as int].unwrap().0@)
    }
    closed spec fn dependable(&self) -> bool {true}
    fn bounded(&mut self,at:u64,end:u64) -> (out:Option<Vec<u8>>) {
        let index = usize::try_from(at).ok()?;
        let (data,_) = self.slots.get(index)?.as_ref()?;
        let body = at.checked_add(52)?;
        if body.checked_add(data.len() as u64)? > end {return None;}
        let mut payload = Vec::new();
        payload.extend_from_slice(data);
        Some(payload)
    }
}

pub(super) open spec fn gaps(frames:vstd::imap::IMap<u64,Seq<u8>>,map:Map<ObjectId,ArenaLocation>,scheme:Scheme) -> vstd::iset::ISet<(int,int)> {
    vstd::iset::ISet::new(|r:(int,int)| 0 <= r.0 < r.1 <= u64::MAX &&
        duplicates::tiled(frames,map,scheme,r.0 as u64,r.1 as u64))
}

struct Arena<'a> { media:Frames<'a>,scheme:Scheme,tail:ArenaLocation }

impl admission::Arena for Arena<'_> {
    closed spec fn gaps(&self,map:Map<ObjectId,ArenaLocation>) -> vstd::iset::ISet<(int,int)> {
        gaps(self.media.frames(),map,self.scheme)
    }
    closed spec fn entries(&self) -> vstd::iset::ISet<(ObjectId,ArenaLocation)> {
        vstd::iset::ISet::new(|p:(ObjectId,ArenaLocation)| {
            let at = p.1.offset;
            &&& self.media.frames().contains_key(at)
            &&& self.media.frames()[at].len() == p.1.payload_len
            &&& self.media.slots@[at as int].unwrap().1 == p.1.checksum
            &&& duplicates::named(self.media.frames()[at],self.scheme,p.0)
        })
    }
    closed spec fn tails(&self) -> Set<ArenaLocation> {Set::empty().insert(self.tail)}
    closed spec fn reliable(&self) -> bool {true}
    fn gap(&mut self,map:&BTreeMap<ObjectId,ArenaLocation>,at:u64,end:u64) -> bool {
        duplicates::check(&mut Frames{slots:self.media.slots},map,self.scheme,at,end)
    }
    fn entry(&mut self,id:ObjectId,loc:ArenaLocation) -> bool {
        let Ok(at) = usize::try_from(loc.offset) else {return false;};
        let Some(Some((data,sum))) = self.media.slots.get(at) else {return false;};
        if sum.as_slice() != loc.checksum.as_slice() || data.len() as u64 != loc.payload_len {return false;}
        assert(*sum =~= loc.checksum);
        let mut pos = 0;
        let Ok(digest) = verified_record::identity(data,&mut pos,self.scheme) else {return false;};
        if digest.as_slice() != id.as_bytes().as_slice() {return false;}
        assert(digest@ =~= id.digest());
        true
    }
    fn tail(&mut self,loc:ArenaLocation) -> bool {
        if self.tail.offset != loc.offset || self.tail.payload_len != loc.payload_len ||
            self.tail.checksum.as_slice() != loc.checksum.as_slice() {return false;}
        assert(self.tail.checksum =~= loc.checksum);
        true
    }
}

type Walk = Seq<(ObjectId,u64)>;
type Rows = Seq<(ObjectId,ArenaLocation)>;
type Contents = vstd::imap::IMap<u64,Seq<u8>>;

pub(super) open spec fn next_row(rows:Rows,j:int,end:u64) -> u64 {
    if j == rows.len() {end} else {rows[j].1.offset}
}

#[verifier::opaque]
pub(super) open spec fn valid_walk(w:Walk,frames:Contents,scheme:Scheme,end:u64) -> bool {
    forall|i:int| 0 <= i < w.len() ==> {
        let (id,at) = #[trigger] w[i];
        &&& if i == 0 {at == 0} else {at == w[i-1].1 as int+52+frames[w[i-1].1].len()}
        &&& duplicates::fits(frames,at,end) && duplicates::named(frames[at],scheme,id)
    }
}

proof fn walk_at(w:Walk,frames:Contents,scheme:Scheme,end:u64,i:int)
    requires valid_walk(w,frames,scheme,end), 0 <= i < w.len(),
    ensures duplicates::fits(frames,w[i].1,end), duplicates::named(frames[w[i].1],scheme,w[i].0),
        i == 0 ==> w[i].1 == 0, i > 0 ==> w[i].1 == w[i-1].1 as int + 52 + frames[w[i-1].1].len(),
{ reveal(valid_walk); }

#[verifier::opaque]
pub(super) open spec fn layout(rows:Rows,map:Map<ObjectId,ArenaLocation>,frames:Contents,scheme:Scheme,end:u64) -> bool {
    &&& admission::ordered(rows,map) && admission::spanned(rows,end,gaps(frames,map,scheme))
    &&& forall|k:int| 0 <= k < rows.len() ==> {
        let (id,loc) = #[trigger] rows[k];
        &&& frames.contains_key(loc.offset) && loc.payload_len == frames[loc.offset].len()
        &&& duplicates::named(frames[loc.offset],scheme,id)
    }
}

proof fn retained_at(rows:Rows,map:Map<ObjectId,ArenaLocation>,frames:Contents,scheme:Scheme,end:u64,j:int)
    requires layout(rows,map,frames,scheme,end), 0 <= j < rows.len(),
    ensures ({
        let (key,loc) = rows[j];
        &&& frames.contains_key(loc.offset) && loc.payload_len == frames[loc.offset].len()
        &&& duplicates::named(frames[loc.offset],scheme,key) && map.contains_key(key) && map[key] == loc
        &&& admission::bridges(gaps(frames,map,scheme),admission::frontier(rows,j+1),next_row(rows,j+1,end) as int)
    }),
{
    reveal(layout);
    rows.to_set_ensures();
    assert(map.kv_pairs().contains(rows[j]));
    if j+1 < rows.len() {assert(next_row(rows,j+1,end) == rows[j+1].1.offset);}
}

pub(super) open spec fn represented(map:Map<ObjectId,ArenaLocation>,frames:Contents,scheme:Scheme,p:(ObjectId,u64)) -> bool {
    map.contains_key(p.0) && (map[p.0].offset == p.1 || duplicates::copy_of(frames,map,scheme,p.1,p.0))
}

/// Consume either the next retained frame or one complete copy before it.
/// At the physical end the walk has no remaining frame.
#[verifier::rlimit(16)]
proof fn trace(rows:Rows,map:Map<ObjectId,ArenaLocation>,frames:Contents,scheme:Scheme,end:u64,
    walk:Walk,i:int,j:int,cursor:u64)
    requires 0 <= i <= walk.len(),0 <= j <= rows.len(),
        i < walk.len() ==> walk[i].1 == cursor,
        valid_walk(walk,frames,scheme,end),
        layout(rows,map,frames,scheme,end),
        duplicates::tiled(frames,map,scheme,cursor,next_row(rows,j,end)),
    ensures forall|k:int| i <= k < walk.len() ==> represented(map,frames,scheme,#[trigger] walk[k]),
    decreases walk.len()-i,
{
    if i == walk.len() {return;}
    walk_at(walk,frames,scheme,end,i);
    let (id,at) = walk[i];
    let hi = next_row(rows,j,end);
    let after = (at as int+52+frames[at].len()) as u64;
    assert(duplicates::fits(frames,at,end));
    assert(after == at as int+52+frames[at].len());
    if i+1 < walk.len() {walk_at(walk,frames,scheme,end,i+1); assert(walk[i+1].1 == after);}
    if j < rows.len() {retained_at(rows,map,frames,scheme,end,j);}
    let next_index = step(rows,map,frames,scheme,end,id,at,j,after);
    trace(rows,map,frames,scheme,end,walk,i+1,next_index,after);
}

proof fn step(rows:Rows,map:Map<ObjectId,ArenaLocation>,frames:Contents,scheme:Scheme,end:u64,
    id:ObjectId,at:u64,j:int,after:u64) -> (next_j:int)
    requires 0 <= j <= rows.len(),duplicates::fits(frames,at,end),duplicates::named(frames[at],scheme,id),
        after == at as int+52+frames[at].len(),
        duplicates::tiled(frames,map,scheme,at,next_row(rows,j,end)),
        j < rows.len() ==> {
            let (key,loc) = rows[j];
            &&& frames.contains_key(loc.offset) && loc.payload_len == frames[loc.offset].len()
            &&& duplicates::named(frames[loc.offset],scheme,key)
            &&& map.contains_key(key) && map[key] == loc
            &&& admission::bridges(gaps(frames,map,scheme),admission::frontier(rows,j+1),next_row(rows,j+1,end) as int)
        },
    ensures 0 <= next_j <= rows.len(),represented(map,frames,scheme,(id,at)),
        duplicates::tiled(frames,map,scheme,after,next_row(rows,next_j,end)),
{
    let hi = next_row(rows,j,end);
    let mut next_index = j;
    assert(at <= hi);
    if at < hi {
        assert(exists|key:ObjectId| #[trigger] duplicates::copy_of(frames,map,scheme,at,key));
        let key = choose|key:ObjectId| #[trigger] duplicates::copy_of(frames,map,scheme,at,key);
        ObjectId::same_digest(key,id);
        assert(represented(map,frames,scheme,(id,at)));
        assert(duplicates::tiled(frames,map,scheme,after,hi));

    } else {
        assert(at == hi && j < rows.len());
        let (key,loc) = rows[j];
        assert(duplicates::named(frames[at],scheme,key));
        ObjectId::same_digest(key,id);
        assert(map.contains_key(key) && map[key] == loc);
        assert(admission::frontier(rows,j+1) == after);
        let next = next_row(rows,j+1,end);
        assert(admission::bridges(gaps(frames,map,scheme),after as int,next as int));
        assert(represented(map,frames,scheme,(id,at)));
        assert(duplicates::tiled(frames,map,scheme,after,next));
        next_index = j+1;
    }
    assert(represented(map,frames,scheme,(id,at)));
    next_index
}

fn admit(candidate:admission::IndexState,complete:bool,measured:u64,arena:&mut Arena,
    Ghost(walk):Ghost<Walk>) -> (out:Option<admission::IndexState>)
    requires btree_map_inv(&candidate.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        valid_walk(walk,old(arena).media.frames(),old(arena).scheme,measured),
    ensures out matches Some(s) ==> forall|i:int| 0 <= i < walk.len() ==>
        represented(s.objects@,old(arena).media.frames(),old(arena).scheme,#[trigger] walk[i]),
{
    let ghost frames = arena.media.frames();
    let ghost scheme = arena.scheme;
    let result = admission::IndexState::validated(Some(candidate),complete,measured,arena);
    proof {if let Some(s) = &result {
        let map = s.objects@;
        let rows = choose|r:Rows| #[trigger] admission::ordered(r,map) && admission::spanned(r,measured,gaps(frames,map,scheme));
        rows.to_set_ensures();
        assert forall|k:int| 0 <= k < rows.len() implies ({
            let (id,loc) = #[trigger] rows[k];
            &&& frames.contains_key(loc.offset) && loc.payload_len == frames[loc.offset].len()
            &&& duplicates::named(frames[loc.offset],scheme,id)
        }) by {assert(map.kv_pairs().contains(rows[k]));}
        assert(admission::bridges(gaps(frames,map,scheme),0,next_row(rows,0,measured) as int));
        assert(layout(rows,map,frames,scheme,measured)) by {reveal(layout);}
        if walk.len()>0 {walk_at(walk,frames,scheme,measured,0);}
        trace(rows,map,frames,scheme,measured,walk,0,0,0);
    }}
    result
}

/// With one retained object and two complete physical frames, cache admission
/// succeeds exactly for equal payloads. A tagged conflict must take fallback.
fn twins(candidate:admission::IndexState,arena:&mut Arena,id:ObjectId,first:ArenaLocation,
    second:u64,measured:u64) -> (out:Option<admission::IndexState>)
    requires btree_map_inv(&candidate.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        candidate.objects@ == Map::empty().insert(id,first), first.offset == 0,
        candidate.arena_len == measured, candidate.arena_tail == Some(old(arena).tail),
        old(arena).tail.offset == second, old(arena).tail.payload_len == first.payload_len,
        second == 52 + first.payload_len as int, measured == second as int + 52 + first.payload_len,
        old(arena).media.frames().contains_key(0),old(arena).media.frames().contains_key(second),
        old(arena).media.frames()[0].len() == first.payload_len,
        old(arena).media.frames()[second].len() == first.payload_len,
        duplicates::named(old(arena).media.frames()[0],old(arena).scheme,id),
        old(arena).media.slots@[0].unwrap().1 == first.checksum,
    ensures out == if old(arena).media.frames()[0] == old(arena).media.frames()[second] {Some(candidate)} else {None},
{
    let ghost map = candidate.objects@;
    let ghost frames = arena.media.frames();
    let ghost scheme = arena.scheme;
    let ghost witness = seq![(id,first)];
    let ghost intervals = gaps(frames,map,scheme);
    proof {
        witness.to_set_ensures();
        assert forall|p:(ObjectId,ArenaLocation)| #[trigger] witness.to_set().contains(p) == map.kv_pairs().contains(p) by {
            if witness.to_set().contains(p) {
                let k = choose|k:int| 0 <= k < witness.len() && #[trigger] witness[k] == p;
                assert(k == 0 && witness[0] == (id,first));
            } else if p == (id,first) {
                assert(witness[0] == p);
            }
            assert(map.kv_pairs().contains(p) == (map.contains_key(p.0) && map[p.0] == p.1));
        }
        assert(witness.to_set() =~= map.kv_pairs());
        assert(admission::ordered(witness,map));
        if frames[0] == frames[second] {
            assert(duplicates::copy_of(frames,map,scheme,second,id));
            reveal_with_fuel(duplicates::tiled,2);
            assert(duplicates::tiled(frames,map,scheme,measured,measured));
            assert(duplicates::tiled(frames,map,scheme,second,measured));
            assert(admission::spanned(witness,measured,intervals));
            assert(admission::covered_with(map,measured,intervals));
        } else if admission::covered_with(map,measured,intervals) {
            let rows = choose|r:Rows| #[trigger] admission::ordered(r,map) && admission::spanned(r,measured,intervals);
            rows.to_set_ensures();
            assert(rows.len() == 1);
            assert(map.kv_pairs().contains(rows[0]));
            assert(rows =~= witness);
            assert(duplicates::tiled(frames,map,scheme,second,measured));
            let other = choose|k:ObjectId| #[trigger] duplicates::copy_of(frames,map,scheme,second,k);
            assert(other == id);
            assert(false);
        }
    }
    admission::IndexState::validated(Some(candidate),true,measured,arena)
}

}
