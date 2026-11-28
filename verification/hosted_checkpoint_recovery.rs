//! Reconcile checkpoint admission and replacement with a stable arena image.
use crate::{arena_frame as frame, checkpoint_admission as admission, checkpoint_reader as reader,
    checkpoint_rebuild, root_wire::Scheme, verified_record as record, ObjectId, ArenaLocation};
use crate::checkpoint_reader::Input;
use admission::IndexState;
use vstd::prelude::*;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {

struct Image<'a> { bytes:&'a [u8], cursor:u64 }

impl Input for Image<'_> {
    type Error = ();
    closed spec fn image(&self) -> Seq<u8> {self.bytes@}
    closed spec fn position(&self) -> int {self.cursor as int}
    closed spec fn reliable(&self) -> bool {true}

    fn length(&self) -> Result<u64,()> { Ok(self.bytes.len() as u64) }
    fn seek(&mut self, at:u64) -> Result<(),()> { self.cursor = at; Ok(()) }
    fn read<const N:usize>(&mut self) -> Result<[u8;N],()> {
        let length = self.bytes.len();
        let Ok(start) = usize::try_from(self.cursor) else {return Err(());};
        let Some(end) = start.checked_add(N) else {return Err(());};
        if end > length {return Err(());}
        let mut field = [0;N];
        field.copy_from_slice(&self.bytes[start..end]);
        self.cursor = end as u64;
        Ok(field)
    }
}

/// The positional tail read has already authenticated this frame. Ordinary
/// entries still have to match the header and tagged identity in the image.
struct Candidate<'a> {
    media:Image<'a>, magic:[u8;8], version:u16, scheme:Scheme, limit:u64,
    checked_tail:ArenaLocation,
}

impl admission::Arena for Candidate<'_> {
    closed spec fn gaps(&self,_map:Map<ObjectId,ArenaLocation>) -> vstd::iset::ISet<(int,int)> {vstd::iset::ISet::empty()}
    fn gap(&mut self,_map:&std::collections::BTreeMap<ObjectId,ArenaLocation>,at:u64,end:u64) -> bool {at == end}
    closed spec fn entries(&self) -> vstd::iset::ISet<(ObjectId,ArenaLocation)> {
        vstd::iset::ISet::new(|p:(ObjectId,ArenaLocation)| reader::matches(self.media.image(),self.magic,self.version,p.1,self.scheme,p.0,self.limit))
    }
    closed spec fn tails(&self) -> Set<ArenaLocation> { Set::empty().insert(self.checked_tail) }
    closed spec fn reliable(&self) -> bool {true}

    fn entry(&mut self, id:ObjectId, loc:ArenaLocation) -> bool {
        reader::check(&mut self.media,self.magic,self.version,loc,self.scheme,id,self.limit).is_ok()
    }
    fn tail(&mut self, loc:ArenaLocation) -> bool {
        if loc.offset != self.checked_tail.offset || loc.payload_len != self.checked_tail.payload_len ||
            loc.checksum.as_slice() != self.checked_tail.checksum.as_slice() {return false;}
        assert(loc.checksum@ =~= self.checked_tail.checksum@);
        assert(loc.checksum == self.checked_tail.checksum);
        true
    }
}

/// Accept the candidate exactly when the length, every mapping and the
/// tail agree. Rebuild refusal preserves its original scan or publication error.
fn recover(candidate:IndexState, complete:bool, bytes:&[u8],checked_tail:ArenaLocation,
    magic:[u8;8],version:u16,scheme:Scheme,limit:u64,scanned:IndexState,scan_error:Option<u8>,write_error:Option<u8>)
    -> (out:Result<IndexState,u8>)
    requires btree_map_inv(&candidate.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
    ensures ({
        let valid = complete && candidate.arena_len == bytes.len() &&
            (forall|p:(ObjectId,ArenaLocation)| #[trigger] candidate.objects@.kv_pairs().contains(p) ==>
                reader::matches(bytes@,magic,version,p.1,scheme,p.0,limit)) &&
            (match candidate.arena_tail {Some(loc) => loc == checked_tail, None => candidate.arena_len == 0});
        out == if valid && admission::can_cover(candidate.objects@,bytes.len() as u64) {Ok(candidate)} else {
            match scan_error {Some(e) => Err(e), None => match write_error {Some(e) => Err(e),None => Ok(scanned)}}
        }
    }),
{
    let mut arena = Candidate {media:Image {bytes,cursor:0},magic,version,scheme,limit,checked_tail};
    let cached = IndexState::validated(Some(candidate),complete,bytes.len() as u64,&mut arena);
    let expected_len = scanned.arena_len;
    checkpoint_rebuild::select(cached,move || -> (r:Result<IndexState,u8>)
        ensures r == match scan_error {Some(e) => Err(e),None => Ok(scanned)}
        {match scan_error {Some(e) => Err(e),None => Ok(scanned)}},
        |value:&IndexState| -> (r:Result<(),u8>)
            ensures match write_error {Some(e) => r == Err(e), None => if value.arena_len == expected_len {r.is_ok()} else {r == Err(99u8)}}
        {match write_error {Some(e) => Err(e),None => if value.arena_len == expected_len {Ok(())} else {Err(99)}}})
}

/// A walk starting at byte zero and following the lengths in the actual frame
/// headers cannot find a tagged object omitted by an accepted checkpoint.
proof fn physical_prefix(bytes:Seq<u8>, rows:Seq<(ObjectId,ArenaLocation)>,
    walk:Seq<(ObjectId,ArenaLocation)>, n:int, magic:[u8;8],version:u16,scheme:Scheme,limit:u64)
    requires 0 <= n <= walk.len(), bytes.len() <= u64::MAX,
        admission::partition(rows,bytes.len() as u64),
        forall|i:int| 0 <= i < rows.len() ==> reader::matches(bytes,magic,version,(#[trigger] rows[i]).1,scheme,rows[i].0,limit),
        forall|i:int| 0 <= i < walk.len() ==> {
            &&& (#[trigger] walk[i]).1.offset == admission::frontier(walk,i)
            &&& reader::matches(bytes,magic,version,walk[i].1,scheme,walk[i].0,limit)
        },
    ensures n <= rows.len(), forall|i:int| 0 <= i < n ==> #[trigger] walk[i] == rows[i],
    decreases n,
{
    assert forall|k:int| 0 <= k < rows.len() implies (#[trigger] rows[k]).1.offset == admission::frontier(rows,k) by {
        assert(admission::bridges(vstd::iset::ISet::empty(),admission::frontier(rows,k),rows[k].1.offset as int));
    }
    assert(admission::frontier(rows,rows.len() as int) == bytes.len());
    if n > 0 {
        let i = n-1;
        physical_prefix(bytes,rows,walk,i,magic,version,scheme,limit);
        if i > 0 {assert(walk[i-1] == rows[i-1]);}
        assert(admission::frontier(rows,i) == admission::frontier(walk,i));
        if i == rows.len() {assert(admission::frontier(rows,i) == bytes.len());}
        if i < rows.len() {assert(rows[i].1.offset == admission::frontier(rows,i));}
        let (id,loc) = walk[i];
        assert(reader::matches(bytes,magic,version,loc,scheme,id,limit));
        assert(i < rows.len());
        let (cached,at) = rows[i];
        assert(at.offset == loc.offset);
        assert(reader::matches(bytes,magic,version,at,scheme,cached,limit));
        assert(at.checksum =~= loc.checksum);
        ObjectId::same_digest(cached,id);
        assert(walk[i] == rows[i]);
    }
}

proof fn includes_physical_objects(bytes:Seq<u8>, map:Map<ObjectId,ArenaLocation>,
    walk:Seq<(ObjectId,ArenaLocation)>,magic:[u8;8],version:u16,scheme:Scheme,limit:u64)
    requires bytes.len() <= u64::MAX, admission::can_cover(map,bytes.len() as u64),
        forall|p:(ObjectId,ArenaLocation)| #[trigger] map.kv_pairs().contains(p) ==> reader::matches(bytes,magic,version,p.1,scheme,p.0,limit),
        forall|i:int| 0 <= i < walk.len() ==> {
            &&& (#[trigger] walk[i]).1.offset == admission::frontier(walk,i)
            &&& reader::matches(bytes,magic,version,walk[i].1,scheme,walk[i].0,limit)
        },
    ensures forall|i:int| 0 <= i < walk.len() ==> map.kv_pairs().contains(#[trigger] walk[i]),
{
    let rows = choose|s:Seq<(ObjectId,ArenaLocation)>| #[trigger] admission::ordered(s,map) && admission::partition(s,bytes.len() as u64);
    rows.to_set_ensures();
    assert forall|i:int| 0 <= i < rows.len() implies reader::matches(bytes,magic,version,(#[trigger] rows[i]).1,scheme,rows[i].0,limit) by {
        assert(rows.to_set().contains(rows[i]));
    }
    physical_prefix(bytes,rows,walk,walk.len() as int,magic,version,scheme,limit);
    assert forall|i:int| 0 <= i < walk.len() implies map.kv_pairs().contains(#[trigger] walk[i]) by {
        assert(rows.to_set().contains(rows[i]));
    }
}

/// Bind reverse coverage to production admission on the same stable bytes.
fn admitted_objects(candidate:IndexState, complete:bool, bytes:&[u8], checked_tail:ArenaLocation,
    magic:[u8;8],version:u16,scheme:Scheme,limit:u64, Ghost(walk):Ghost<Seq<(ObjectId,ArenaLocation)>>)
    -> (out:Option<IndexState>)
    requires btree_map_inv(&candidate.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|i:int| 0 <= i < walk.len() ==> {
            &&& (#[trigger] walk[i]).1.offset == admission::frontier(walk,i)
            &&& reader::matches(bytes@,magic,version,walk[i].1,scheme,walk[i].0,limit)
        },
    ensures out matches Some(s) ==> s==candidate && complete && s.arena_len==bytes.len() &&
        (forall|i:int| 0 <= i < walk.len() ==> s.objects@.kv_pairs().contains(#[trigger] walk[i])),
{
    let mut arena = Candidate {media:Image {bytes,cursor:0},magic,version,scheme,limit,checked_tail};
    let out = IndexState::validated(Some(candidate),complete,bytes.len() as u64,&mut arena);
    proof {if let Some(s) = &out {
        includes_physical_objects(bytes@,s.objects@,walk,magic,version,scheme,limit);
    }}
    out
}

/// A non-empty, contiguous cached index and the positional tail witness must
/// describe the same arena bytes. The walk can name any prefix of those bytes.
fn admit_physical_tail<M:crate::positional_read::Media,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    media:&M,bytes:&[u8],candidate:IndexState,complete:bool,magic:[u8;8],version:u16,scheme:Scheme,
    limit:u64,hash:H,Ghost(walk):Ghost<Seq<(ObjectId,ArenaLocation)>>) -> (out:Option<IndexState>)
    requires media.image()==bytes@,btree_map_inv(&candidate.objects),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
        forall|i:int| 0<=i<walk.len() ==> {
            &&& (#[trigger] walk[i]).1.offset==admission::frontier(walk,i)
            &&& reader::matches(bytes@,magic,version,walk[i].1,scheme,walk[i].0,limit)
        },
    ensures out matches Some(s) ==> {
        &&& s==candidate && complete && s.arena_len==bytes.len()
        &&& forall|i:int| 0<=i<walk.len() ==> s.objects@.kv_pairs().contains(#[trigger] walk[i])
        &&& s.arena_tail matches Some(loc) && {
            let start=loc.offset as int;
            let end=start+52+loc.payload_len;
            &&& end<=media.image().len() && loc.payload_len<=limit
            &&& reader::header_matches(bytes@.subrange(start,start+52),magic,version,loc)
            &&& frame::hashed(hash,magic,bytes@.subrange(start+52,end),loc.checksum)
        }
    },
{
    let tail=candidate.arena_tail?;
    if !physical_tail(media,tail,magic,version,limit,hash) {return None;}
    admitted_objects(candidate,complete,bytes,tail,magic,version,scheme,limit,Ghost(walk))
}

/// At a nonzero offset, check the name and placement written by the arena
/// encoder. The short case has following bytes but ends at the header.
fn written(id:ObjectId, expected:ObjectId, magic:[u8;8], version:u16, scheme:Scheme, sum:[u8;32],short:bool)
    -> (ok:bool)
    requires scheme.algorithm@ != seq![0u8,0u8],scheme.construction@ != seq![0u8,0u8],
    ensures ok == (!short && expected == id),
{
    let size = if short {39u64} else {40u64};
    let loc = ArenaLocation {offset:1,payload_len:size,checksum:sum};
    let header = frame::header(magic,version,size,sum);
    let mut bytes = Vec::new();
    bytes.push(9);
    bytes.extend_from_slice(&header);
    let raw = *id.as_bytes();
    record::append_identity(&mut bytes,scheme,raw);
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.subrange(1,53) =~= header@);
        assert(header@.take(8) =~= magic@);
        assert(header@.subrange(8,10) =~= seq![version as u8,(version >> 8) as u8]);
        assert(header@.subrange(12,20) =~= vstd::bytes::spec_u64_to_le_bytes(size));
        assert(header@.subrange(20,52) =~= sum@);
        assert(bytes@.subrange(53,93) =~= record::wire(scheme,raw));
        let name = bytes@.subrange(53,93);
        assert(name.subrange(0,40) =~= record::wire(scheme,raw));
        record::tag_written(name,0,scheme,raw);
        if id.digest() == expected.digest() {ObjectId::same_digest(id,expected);}
    }
    let mut media = Image {bytes:bytes.as_slice(),cursor:0};
    let verdict = reader::check(&mut media,magic,version,loc,scheme,expected,40);
    if short {
        assert(verdict matches Err(reader::Error::Short));
        assert(media.position() == 53);
    } else if verdict.is_ok() {
        assert(media.position() == 93);
    }
    verdict.is_ok()
}
/// The same positional frame driver used by the cache tail validator. A successful
/// tail read binds the placement, header and digest to bytes on this handle.
fn physical_tail<M:crate::positional_read::Media,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    media:&M,loc:ArenaLocation,magic:[u8;8],version:u16,limit:u64,hash:H) -> (ok:bool)
    requires forall|n:u64,p:&[u8]| #[trigger] hash.requires((magic,n,p)),
    ensures ok ==> {
        let start=loc.offset as int;
        let end=start+52+loc.payload_len;
        &&& end<=media.image().len() && loc.payload_len<=limit
        &&& reader::header_matches(media.image().subrange(start,start+52),magic,version,loc)
        &&& frame::hashed(hash,magic,media.image().subrange(start+52,end),loc.checksum)
    },
{
    let decode=|h:&[u8;52]| -> (d:Result<frame::DecodedFrameHeader,()>)
        ensures d matches Ok(v) ==> v.payload_len<=limit &&
            reader::header_matches(h@,magic,version,ArenaLocation{offset:loc.offset,payload_len:v.payload_len,checksum:v.checksum}),
    {
        frame::positioned_header(h,magic,version,limit).map_err(|_| ())
    };
    let validate=|d:frame::DecodedFrameHeader,p:&[u8]| -> (r:Result<[u8;32],()>)
        ensures r matches Ok(sum) ==> sum==d.checksum && p.len()==d.payload_len && hash.ensures((magic,d.payload_len,p),sum),
    {frame::check_payload(d,magic,p,hash).map_err(|_| ())};
    let read=|at:u64| -> (r:Result<(Vec<u8>,[u8;32]),()>)
        ensures r matches Ok((p,sum)) ==> {
            let start=at as int;
            &&& start+52+p.len()<=media.image().len() && p.len()<=limit
            &&& p@==media.image().subrange(start+52,start+52+p.len())
            &&& reader::header_matches(media.image().subrange(start,start+52),magic,version,
                ArenaLocation{offset:at,payload_len:p.len() as u64,checksum:sum})
            &&& frame::hashed(hash,magic,p@,sum)
        },
    {
        crate::positional_read::frame(media,at,decode,validate).map_err(|_| ())
    };
    crate::arena_span::at_location(loc.offset,loc.payload_len,loc.checksum,read).is_ok()
}


}
