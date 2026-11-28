//! Validate a cached location against the addressed arena header and identity.
use super::{ArenaLocation, ObjectId, root_wire::Scheme, verified_record};
use vstd::prelude::*;

verus! {

pub(super) trait Input {
    type Error;
    spec fn image(&self) -> Seq<u8>;
    spec fn position(&self) -> int;
    spec fn reliable(&self) -> bool;

    fn length(&self) -> (out:Result<u64,Self::Error>)
        ensures self.reliable() ==> out.is_ok(), out matches Ok(n) ==> n == self.image().len();

    fn seek(&mut self, at:u64) -> (out:Result<(),Self::Error>)
        ensures final(self).image() == old(self).image(),final(self).reliable() == old(self).reliable(),
            old(self).reliable() ==> out.is_ok(),out.is_ok() ==> final(self).position() == at;

    fn read<const N:usize>(&mut self) -> (out:Result<[u8;N],Self::Error>)
        ensures final(self).image() == old(self).image(),final(self).reliable() == old(self).reliable(),
            old(self).reliable() && 0 <= old(self).position() && old(self).position()+N <= old(self).image().len() ==> out.is_ok(),
            out matches Ok(data) ==> 0 <= old(self).position() && final(self).position() == old(self).position()+N &&
                final(self).position() <= old(self).image().len() && data@ == old(self).image().subrange(old(self).position(),final(self).position());
}

pub(super) enum Error<E> { Length(E), Seek(E), HeaderRead(E), IdentityRead(E), Overflow, Extent, Header,
    Limit(u64), Placement, Short, Tag(verified_record::TagError), Name }

pub(super) open spec fn header_matches(h:Seq<u8>, magic:[u8;8], version:u16, loc:ArenaLocation) -> bool {
    &&& h.len() == 52 && h.take(8) == magic@
    &&& h.subrange(8,10) == seq![version as u8,(version >> 8) as u8] && h[10] == 0 && h[11] == 0
    &&& vstd::bytes::spec_u64_from_le_bytes(h.subrange(12,20)) == loc.payload_len
    &&& h.subrange(20,52) == loc.checksum@
}

pub(super) open spec fn matches(image:Seq<u8>, magic:[u8;8], version:u16, loc:ArenaLocation,
    scheme:Scheme, expected:ObjectId, limit:u64) -> bool {
    let at = loc.offset as int;
    let name = image.subrange(at+52,at+92);
    &&& at+52+loc.payload_len <= image.len() && at+52+loc.payload_len <= u64::MAX
    &&& 40 <= loc.payload_len <= limit && header_matches(image.subrange(at,at+52),magic,version,loc)
    &&& verified_record::tag(name,0,scheme) && name.subrange(8,40) == expected.digest()
}

pub(super) fn check<M:Input>(media:&mut M, magic:[u8;8], version:u16, loc:ArenaLocation,
    scheme:Scheme, expected:ObjectId, limit:u64) -> (out:Result<(),Error<M::Error>>)
    ensures final(media).image() == old(media).image(),
        out.is_ok() ==> matches(old(media).image(),magic,version,loc,scheme,expected,limit) &&
            final(media).position() == loc.offset as int + 92,
        old(media).reliable() && matches(old(media).image(),magic,version,loc,scheme,expected,limit) ==> out.is_ok(),
        old(media).reliable() && loc.payload_len < 40 && loc.payload_len <= limit &&
            loc.offset as int + 52 + loc.payload_len <= old(media).image().len() &&
            loc.offset as int + 52 + loc.payload_len <= u64::MAX &&
            header_matches(old(media).image().subrange(loc.offset as int,loc.offset as int+52),magic,version,loc) ==>
            out matches Err(Error::Short),
        out matches Err(Error::Short) ==> loc.payload_len < 40 && final(media).position() == loc.offset as int+52,
{
    let length = match media.length() { Ok(n) => n, Err(e) => return Err(Error::Length(e)) };
    let Some(end) = loc.end() else {return Err(Error::Overflow);};
    if end > length {return Err(Error::Extent);}
    if let Err(e) = media.seek(loc.offset) {return Err(Error::Seek(e));}
    let h = match media.read::<52>() { Ok(h) => h, Err(e) => return Err(Error::HeaderRead(e)) };
    let v = [(version & 255) as u8,(version >> 8) as u8];
    proof {
        assert((version & 255) as u8 == version as u8) by(bit_vector);
        assert(h@.take(8) =~= h@.subrange(0,8));
    }
    if h[..8] != magic[..] || h[8..10] != v[..] || h[10] != 0 || h[11] != 0 {return Err(Error::Header);}
    assert(h@.take(8) =~= magic@);
    assert(h@.subrange(8,10) =~= v@);
    let mut size = [0;8];
    size.copy_from_slice(&h[12..20]);
    let declared = u64::from_le_bytes(size);
    if declared > limit {return Err(Error::Limit(declared));}
    if declared != loc.payload_len || h[20..] != loc.checksum[..] {return Err(Error::Placement);}
    assert(h@.subrange(20,52) =~= loc.checksum@);
    if declared < 40 {return Err(Error::Short);}
    let bytes = match media.read::<40>() { Ok(bytes) => bytes, Err(e) => return Err(Error::IdentityRead(e)) };
    let mut cursor = 0;
    let digest = match verified_record::identity(&bytes,&mut cursor,scheme) {Ok(d) => d, Err(e) => return Err(Error::Tag(e))};
    if digest.as_slice() != expected.as_bytes().as_slice() {return Err(Error::Name);}
    assert(digest@ =~= expected.digest());
    Ok(())
}

}
