//! Assemble a frame buffer across short reads from one stable source.
use super::physical_wire::Envelope;
#[cfg(verus_keep_ghost)]
use super::physical_wire::MAGIC;
use vstd::prelude::*;

verus! {

/// One successful read supplies the next bytes at the cursor. A zero count
/// on a nonempty request means the stable source is exhausted.
pub(super) trait Source {
    type Error;
    spec fn image(&self) -> Seq<u8>;
    spec fn remaining(&self) -> Seq<u8>;
    spec fn failed(remaining:Seq<u8>,error:Self::Error) -> bool;

    fn read_part(&mut self, destination:&mut [u8]) -> (out:Result<usize,Self::Error>)
        ensures final(destination).len() == old(destination).len(),
            out matches Err(e) ==> Self::failed(old(self).remaining(),e),
            out matches Ok(n) ==> {
                &&& final(self).image() == old(self).image()
                &&& n <= old(destination).len() && n <= old(self).remaining().len()
                &&& (n == 0) == (old(destination).len() == 0 || old(self).remaining().len() == 0)
                &&& final(destination)@.take(n as int) == old(self).remaining().take(n as int)
                &&& final(self).remaining() == old(self).remaining().skip(n as int)
            };
}

/// Return the number of initialized bytes, including a short buffer at EOF.
/// I/O errors propagate before the caller can consume a partial frame.
pub(super) fn fill<S:Source>(source:&mut S,destination:&mut [u8]) -> (out:Result<usize,S::Error>)
    ensures final(destination).len() == old(destination).len(),
        out matches Err(e) ==> exists|at:int| 0 <= at < old(destination).len() && at <= old(source).remaining().len() &&
            final(destination)@.take(at) == old(source).remaining().take(at) &&
            #[trigger] S::failed(old(source).remaining().skip(at),e),
        out matches Ok(n) ==> {
            let input = old(source).remaining();
            &&& final(source).image() == old(source).image()
            &&& n as int == if input.len() < old(destination).len() {input.len() as int} else {old(destination).len() as int}
            &&& final(destination)@.take(n as int) == input.take(n as int)
            &&& final(source).remaining() == input.skip(n as int)
        },
{
    let ghost input = source.remaining();
    let mut filled = 0usize;
    while filled < destination.len()
        invariant source.image() == old(source).image(), input == old(source).remaining(), filled <= destination.len() == old(destination).len(), filled <= input.len(),
            destination@.take(filled as int) == input.take(filled as int),
            source.remaining() == input.skip(filled as int),
        decreases destination.len() - filled,
    {
        let ghost before = destination@;
        let part = &mut destination[filled..];
        let n = match source.read_part(part) {
            Ok(n) => n,
            Err(error) => {
                assert(S::failed(input.skip(filled as int),error));
                assert(destination@.take(filled as int) =~= before.take(filled as int));
                return Err(error);
            },
        };
        assert(part@.take(n as int) == input.skip(filled as int).take(n as int));
        let ghost received = part@;
        assert(destination@.skip(filled as int) =~= received);
        assert(input.skip(filled as int).take(n as int) =~= input.subrange(filled as int,filled as int+n));
        proof {
            assert(destination@.take(filled as int) =~= before.take(filled as int));
            assert(destination@.subrange(filled as int,filled as int+n) =~= input.subrange(filled as int,filled as int+n));
            assert(destination@.take(filled as int+n) =~= input.take(filled as int+n));
            assert(source.remaining() =~= input.skip(filled as int+n));
        }
        if n == 0 {
            assert(filled == input.len());
            return Ok(filled);
        }
        filled = filled.saturating_add(n);
    }
    Ok(filled)
}

pub(super) enum Payload { Complete, Short, BadChecksum }

/// Check exactly the buffer that was filled from this source. A short read
/// cannot become a checksum match, even when the untouched bytes match.
pub(super) fn read_payload<S:Source,H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    source:&mut S,destination:&mut [u8],envelope:Envelope,hash:H,
) -> (out:Result<Payload,S::Error>)
    requires forall|size:u64,p:&[u8]| #[trigger] hash.requires((MAGIC,size,p)),
    ensures final(destination).len() == old(destination).len(),
        out matches Err(e) ==> exists|at:int| 0 <= at < old(destination).len() && at <= old(source).remaining().len() &&
            #[trigger] S::failed(old(source).remaining().skip(at),e),
        out.is_ok() ==> ({
            let n = if old(destination).len() > old(source).remaining().len() {old(source).remaining().len() as int} else {old(destination).len() as int};
            &&& final(source).image() == old(source).image()
            &&& final(destination)@.take(n) == old(source).remaining().take(n)
            &&& final(source).remaining() == old(source).remaining().skip(n)
            &&& (out matches Ok(Payload::Short)) == (n < old(destination).len())
        }),
        out matches Ok(Payload::Complete) ==> final(destination).len() == envelope.size &&
            exists|p:&[u8]| p@ == final(destination)@ && #[trigger] hash.ensures((MAGIC,envelope.size,p),envelope.checksum),
        out matches Ok(Payload::BadChecksum) ==> final(destination).len() != envelope.size ||
            exists|p:&[u8],sum:[u8;32]| p@ == final(destination)@ && sum@ != envelope.checksum@ &&
                #[trigger] hash.ensures((MAGIC,envelope.size,p),sum),
{
    let n = fill(source,destination)?;
    if n < destination.len() {return Ok(Payload::Short);}
    let p:&[u8] = &*destination;
    if envelope.validates(p,hash) {Ok(Payload::Complete)} else {Ok(Payload::BadChecksum)}
}

pub(super) trait Positioned: Source {
    type SeekError;
    spec fn seek_failed(image:Seq<u8>,start:Option<u64>,error:Self::SeekError) -> bool;

    fn seek_end(&mut self) -> (out:Result<u64,Self::SeekError>)
        ensures out matches Err(e) ==> Self::seek_failed(old(self).image(),None,e),
            out matches Ok(length) ==> final(self).image() == old(self).image() &&
            length == old(self).image().len() && final(self).remaining().len() == 0;

    fn seek_start(&mut self,offset:u64) -> (out:Result<(),Self::SeekError>)
        ensures out matches Err(e) ==> Self::seek_failed(old(self).image(),Some(offset),e),
            out.is_ok() ==> final(self).image() == old(self).image() &&
            final(self).remaining() == (if offset <= old(self).image().len() {old(self).image().skip(offset as int)} else {Seq::empty()});
}

pub(super) enum LengthError<E> { End(E), Restore(E) }

/// The cursor after a successful length probe addresses the requested payload
/// in the very image whose length was returned.
pub(super) fn length_at<S:Positioned>(source:&mut S,restore:u64) -> (out:Result<u64,LengthError<S::SeekError>>)
    ensures out matches Err(LengthError::End(e)) ==> S::seek_failed(old(source).image(),None,e),
        out matches Err(LengthError::Restore(e)) ==> S::seek_failed(old(source).image(),Some(restore),e),
        out matches Ok(length) ==> length == old(source).image().len() &&
        final(source).image() == old(source).image() && final(source).remaining() ==
            (if restore <= length {old(source).image().skip(restore as int)} else {Seq::empty()}),
{
    let length = match source.seek_end() {Ok(n)=>n,Err(e)=>return Err(LengthError::End(e))};
    match source.seek_start(restore) {Ok(())=>Ok(length),Err(e)=>Err(LengthError::Restore(e))}
}

}
