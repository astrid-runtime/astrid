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

/// Specialize both directions of the duplicate reader contract to a stable
/// physical frame table before feeding the result to map admission.
fn checked_gap(media:&Frames,map:&BTreeMap<ObjectId,ArenaLocation>,scheme:Scheme,at:u64,end:u64) -> (ok:bool)
    requires btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures ok == duplicates::tiled(media.frames(),map@,scheme,at,end),
{
    duplicates::check(&mut Frames{slots:media.slots},map,scheme,at,end)
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
    closed spec fn tails(&self) -> vstd::iset::ISet<ArenaLocation> {vstd::iset::ISet::empty().insert(self.tail)}
    closed spec fn reliable(&self) -> bool {true}
    fn gap(&mut self,map:&BTreeMap<ObjectId,ArenaLocation>,at:u64,end:u64) -> bool {
        checked_gap(&self.media,map,self.scheme,at,end)
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

/// The digest implementation is a host dependency. Both copies are still
/// compared byte for byte by the production duplicate walker.
trait FrameDigest {
    spec fn digest(&self,magic:[u8;8],length:u64,data:Seq<u8>) -> [u8;32];
    fn calculate(&self,magic:[u8;8],length:u64,data:&[u8]) -> (sum:[u8;32])
        ensures sum==self.digest(magic,length,data@);
}

struct Physical<'a,M:crate::positional_read::Media,H:FrameDigest> {
    media:&'a M, hash:&'a H, magic:[u8;8], version:u16, limit:u64,
}

impl<M:crate::positional_read::Media,H:FrameDigest> Physical<'_,M,H> {
    spec fn size(&self,at:u64) -> u64 {
        vstd::bytes::spec_u64_from_le_bytes(self.media.image().subrange(at as int+12,at as int+20))
    }

    spec fn body(&self,at:u64) -> Seq<u8> {
        self.media.image().subrange(at as int+52,at as int+52+self.size(at))
    }

    spec fn valid(&self,at:u64) -> bool {
        let n=self.size(at);
        let sum=self.hash.digest(self.magic,n,self.body(at));
        &&& at as int+52+n<=self.media.image().len() && n<=self.limit
        &&& crate::checkpoint_reader::header_matches(self.media.image().subrange(at as int,at as int+52),
            self.magic,self.version,ArenaLocation{offset:at,payload_len:n,checksum:sum})
    }
}

impl<M:crate::positional_read::Media,H:FrameDigest> Media for Physical<'_,M,H> {
    closed spec fn frames(&self) -> Contents {
        vstd::imap::IMap::new(|at:u64| self.valid(at),|at:u64| self.body(at))
    }
    closed spec fn dependable(&self) -> bool {false}

    fn bounded(&mut self,at:u64,end:u64) -> (out:Option<Vec<u8>>) {
        let media=self.media;
        let hash=self.hash;
        let magic=self.magic;
        let version=self.version;
        let limit=self.limit;
        let start=crate::positional_read::extent(at,52,end).ok()?;
        let decode=|h:&[u8;52]| -> (d:Result<crate::arena_frame::DecodedFrameHeader,()>)
            ensures d matches Ok(v) ==> start as int+v.payload_len<=end && v.payload_len<=limit &&
                crate::checkpoint_reader::header_matches(h@,magic,version,ArenaLocation{offset:at,payload_len:v.payload_len,checksum:v.checksum}),
        {
            let d=crate::arena_frame::positioned_header(h,magic,version,limit).map_err(|_| ())?;
            crate::positional_read::extent(start,d.payload_len,end).map_err(|_| ())?;
            Ok(d)
        };
        let validate=|d:crate::arena_frame::DecodedFrameHeader,p:&[u8]| -> (r:Result<[u8;32],()>)
            ensures r matches Ok(sum) ==> p.len()==d.payload_len && sum==d.checksum && sum==hash.digest(magic,d.payload_len,p@),
        {
            let calc=|m:[u8;8],n:u64,b:&[u8]| -> (s:[u8;32]) ensures s==hash.digest(m,n,b@), {hash.calculate(m,n,b)};
            crate::arena_frame::check_payload(d,magic,p,calc).map_err(|_| ())
        };
        let (p,sum)=crate::positional_read::frame(media,at,decode,validate).ok()?;
        proof {
            let image=media.image();
            let header=image.subrange(at as int,at as int+52);
            assert(header.subrange(12,20) =~= image.subrange(at as int+12,at as int+20));
            assert(self.size(at)==p.len());
            assert(self.body(at)==p@);
            assert(self.valid(at));
        }
        Some(p)
    }
}

/// Each admitted gap is tiled by authenticated frames on the one arena image.
/// At each step the map's earlier physical payload equals the duplicate.
fn physical_gap<M:crate::positional_read::Media,H:FrameDigest>(media:&M,hash:&H,magic:[u8;8],version:u16,
    limit:u64,map:&BTreeMap<ObjectId,ArenaLocation>,scheme:Scheme,start:u64,end:u64) -> (ok:bool)
    requires btree_map_inv(map),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures ok ==> duplicates::tiled((Physical{media,hash,magic,version,limit}).frames(),map@,scheme,start,end),
{
    duplicates::check(&mut Physical{media,hash,magic,version,limit},map,scheme,start,end)
}

struct CachedArena<'a,M:crate::positional_read::Media,H:FrameDigest,R:crate::checkpoint_reader::Input> {
    source:Physical<'a,M,H>, entries:R, scheme:Scheme,
}

impl<M:crate::positional_read::Media,H:FrameDigest,R:crate::checkpoint_reader::Input>
    admission::Arena for CachedArena<'_,M,H,R> {
    closed spec fn gaps(&self,map:Map<ObjectId,ArenaLocation>) -> vstd::iset::ISet<(int,int)> {
        gaps(self.source.frames(),map,self.scheme)
    }
    closed spec fn entries(&self) -> vstd::iset::ISet<(ObjectId,ArenaLocation)> {
        vstd::iset::ISet::new(|p:(ObjectId,ArenaLocation)| crate::checkpoint_reader::matches(self.entries.image(),
            self.source.magic,self.source.version,p.1,self.scheme,p.0,self.source.limit))
    }
    closed spec fn tails(&self) -> vstd::iset::ISet<ArenaLocation> {
        vstd::iset::ISet::new(|loc:ArenaLocation| self.source.valid(loc.offset) && self.source.size(loc.offset)==loc.payload_len &&
            self.source.hash.digest(self.source.magic,loc.payload_len,self.source.body(loc.offset))==loc.checksum)
    }
    closed spec fn reliable(&self) -> bool {false}

    fn gap(&mut self,map:&BTreeMap<ObjectId,ArenaLocation>,at:u64,end:u64) -> bool {
        let s=&self.source;
        physical_gap(s.media,s.hash,s.magic,s.version,s.limit,map,self.scheme,at,end)
    }
    fn entry(&mut self,id:ObjectId,loc:ArenaLocation) -> bool {
        crate::checkpoint_reader::check(&mut self.entries,self.source.magic,self.source.version,loc,self.scheme,id,self.source.limit).is_ok()
    }
    fn tail(&mut self,loc:ArenaLocation) -> bool {
        let s=&self.source;
        let hash=s.hash;
        let calc=|m:[u8;8],n:u64,p:&[u8]| -> (out:[u8;32]) ensures out==hash.digest(m,n,p@), {hash.calculate(m,n,p)};
        let ok=crate::hosted_checkpoint_recovery::physical_tail(s.media,loc,s.magic,s.version,s.limit,calc);
        proof {if ok {
            let start=loc.offset as int;
            let header=s.media.image().subrange(start,start+52);
            assert(header.subrange(12,20) =~= s.media.image().subrange(start+12,start+20));
            assert(s.size(loc.offset)==loc.payload_len);
            assert(s.valid(loc.offset));
        }}
        ok
    }
}

spec fn admitted_state<M:crate::positional_read::Media,H:FrameDigest>(
    s:admission::IndexState,physical:Physical<M,H>,scheme:Scheme,measured:u64) -> bool {
    &&& s.arena_len==measured
    &&& admission::covered_with(s.objects@,measured,gaps(physical.frames(),s.objects@,scheme))
    &&& forall|pair:(ObjectId,ArenaLocation)| #[trigger] s.objects@.kv_pairs().contains(pair) ==>
        crate::checkpoint_reader::matches(physical.media.image(),physical.magic,physical.version,pair.1,scheme,pair.0,physical.limit)
    &&& match s.arena_tail {
        Some(loc)=>physical.valid(loc.offset) && physical.size(loc.offset)==loc.payload_len &&
            physical.hash.digest(physical.magic,loc.payload_len,physical.body(loc.offset))==loc.checksum,
        None=>measured==0,
    }
}

fn admit_cached<M:crate::positional_read::Media,H:FrameDigest,R:crate::checkpoint_reader::Input>(
    candidate:Option<admission::IndexState>,complete:bool,measured:u64,arena:&mut CachedArena<M,H,R>)
    -> (out:Option<admission::IndexState>)
    requires candidate matches Some(c) ==> btree_map_inv(&c.objects),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        old(arena).entries.image()==old(arena).source.media.image(),measured==old(arena).entries.image().len(),
    ensures out matches Some(s) ==> candidate==Some(s) && complete &&
        admitted_state(s,old(arena).source,old(arena).scheme,measured),
{
    admission::IndexState::validated(candidate,complete,measured,arena)
}

/// Cache-hit recovery retains the index actually admitted by the production
/// validator and the journal fence, then rereads every reachable object.
#[verifier::spinoff_prover]
fn reopen_cached<A:crate::positional_read::Media,H:FrameDigest,T:crate::checkpoint_reader::Input,
    R:crate::frame_repair::FrameReader,M:crate::frame_repair::Medium,V:crate::frontier::JournalContainer,
    P:Ord,D,C,G,I,F,O>(candidate:Option<admission::IndexState>,complete:bool,measured:u64,arena:&A,entries:T,hash:&H,
    reader:&mut R,journal:&mut M,capture:O,end:u64,protected:u64,batch:u64,limit:u64,scheme:Scheme,
    decode:D,recode:C,hash_frame:G,identify:I,project:F)
    -> (out:Option<(crate::hosted_recovered_roots::Loaded<P>,admission::IndexState,Option<V>)>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,G:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
        I:Fn(&crate::ObjectRecord)->[u8;32]+Copy,F:FnOnce(&BTreeMap<P,(crate::RootState,u64)>)->BTreeMap<P,crate::RootState>,
        O:FnOnce(&M)->V,
    requires candidate matches Some(s) ==> btree_map_inv(&s.objects),
        entries.image()==arena.image(),measured==arena.image().len(),
        old(reader).target()==old(journal).target(),arena.target().0==old(reader).target().0,arena.target().1!=old(reader).target().1,
        !old(journal).syncs_file(),old(reader).image()==old(journal).durable(),old(journal).durable()==old(journal).bytes(),
        old(reader).position()==0,protected<=end==old(reader).image().len(),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|m:&M| m.target()==old(journal).target() && !m.syncs_file() ==> #[trigger] capture.requires((m,)),
        forall|m:&M,v:V| #[trigger] capture.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|m:[u8;8],n:u64,p:&[u8]| #[trigger] hash_frame.requires((m,n,p)),
        forall|m:[u8;8],n:u64,p:&[u8],sum:[u8;32]| #[trigger] hash_frame.ensures((m,n,p),sum) ==> sum==hash.digest(m,n,p@),
        forall|r:&crate::ObjectRecord| #[trigger] identify.requires((r,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>| #[trigger] project.requires((h,)),
        forall|h:&BTreeMap<P,(crate::RootState,u64)>,t:BTreeMap<P,crate::RootState>| #[trigger] project.ensures((h,),t) ==> btree_map_inv(&t),
    ensures out matches Some((v,s,fence)) ==> {
        let physical=Physical{media:arena,hash,magic:crate::arena_frame::ARENA_MAGIC,version:crate::arena_frame::FRAME_VERSION,limit};
        &&& complete && candidate==Some(s) && admitted_state(s,physical,scheme,measured)
        &&& final(journal).target()==old(reader).target() && protected<=v.end<=end
        &&& final(journal).bytes()==old(reader).image().take(v.end as int)
        &&& match fence {
            Some(f)=>v.end<end && (f.container_id(),f.region_id())==final(journal).target() && f.durable_image()==final(journal).bytes(),
            None=>v.end==end && final(journal).durable()==final(journal).bytes(),
        }
        &&& crate::hosted_journal_scan::recovered(v.history@,final(journal).bytes(),v.end,limit,scheme,decode,recode,hash_frame)
        &&& crate::hosted_recovered_roots::retained(&v,arena.image(),s.objects@,scheme)
    },
{
    use crate::hosted_journal_scan::{recover_volume,VolumeRecovery};
    let source=Physical{media:arena,hash,magic:crate::arena_frame::ARENA_MAGIC,version:crate::arena_frame::FRAME_VERSION,limit};
    let mut cache=CachedArena{source,entries,scheme};
    let state=admit_cached(candidate,complete,measured,&mut cache)?;
    let (at,history,fence)=match recover_volume(reader,journal,end,protected,limit,scheme,decode,recode,hash_frame,capture) {
        VolumeRecovery::Unmodified(h)=>{assert(journal.bytes().take(end as int) =~= journal.bytes());(end,h,None)},
        VolumeRecovery::Persisted(at,h,v)=>(at,h,Some(v)),
        _=>return None,
    };
    let loaded=crate::hosted_recovered_roots::load_history(history,at,arena,&state.objects,batch,limit,scheme,hash_frame,identify,project)?;
    Some((loaded,state,fence))
}

}
