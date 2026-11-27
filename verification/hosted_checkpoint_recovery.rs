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
        out == if valid {Ok(candidate)} else {
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

}
