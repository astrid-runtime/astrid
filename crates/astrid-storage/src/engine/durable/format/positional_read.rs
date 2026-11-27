//! Fill a positional buffer across short reads from a stable media image.
use vstd::prelude::*;

verus! {

pub(super) trait Media {
    type Error;
    spec fn image(&self) -> Seq<u8>;
    spec fn io_error(&self, offset:u64, error:Self::Error) -> bool;

    fn read_at(&self, offset:u64, buffer:&mut [u8]) -> (out: Result<usize,Self::Error>)
        ensures final(buffer).len() == old(buffer).len(),
            out matches Err(e) ==> self.io_error(offset,e),
            out matches Ok(n) ==> {
                &&& n <= old(buffer).len()
                &&& n == 0 || offset as int + n <= self.image().len()
                &&& (n == 0) == (old(buffer).len() == 0 || offset >= self.image().len())
                &&& n > 0 ==> final(buffer)@.take(n as int) == self.image().subrange(offset as int,offset as int+n)
            };
}

pub(super) enum Error<E> { Offset, Length, Short, Io(E) }

pub(super) open spec fn failed_within<M:Media>(media:&M, offset:u64, len:nat, error:M::Error) -> bool {
    exists|at:u64| offset <= at < offset as int + len && #[trigger] media.io_error(at,error)
}

/// The buffer from a successful read is exactly the requested interval.
/// The next provider call begins after the bytes actually supplied.
pub(super) fn exact<M:Media>(media:&M, offset:u64, buffer:&mut [u8]) -> (out:Result<(),Error<M::Error>>)
    ensures final(buffer).len() == old(buffer).len(),
        out.is_ok() && final(buffer).len() > 0 ==> offset as int + final(buffer).len() <= media.image().len() &&
            final(buffer)@ == media.image().subrange(offset as int,offset as int + final(buffer).len()),
        out matches Err(Error::Short) ==> offset as int + final(buffer).len() > media.image().len(),
        out matches Err(Error::Offset) ==> offset as int + final(buffer).len() > u64::MAX,
        !(out matches Err(Error::Length)),
        out matches Err(Error::Io(e)) ==> failed_within(media,offset,old(buffer)@.len(),e),
{
    let mut filled = 0usize;
    while filled != buffer.len()
        invariant buffer.len() == old(buffer).len(), filled <= buffer.len(),
            filled > 0 ==> offset as int + filled <= media.image().len() &&
                buffer@.take(filled as int) == media.image().subrange(offset as int,offset as int+filled),
        decreases buffer.len()-filled,
    {
        let Some(position) = offset.checked_add(filled as u64) else {return Err(Error::Offset);};
        let ghost before = buffer@;
        let part = &mut buffer[filled..];
        let n = match media.read_at(position,part) {
            Ok(n) => n,
            Err(error) => {
                assert(media.io_error(position,error));
                assert(offset <= position < offset as int + old(buffer).len());
                assert(failed_within(media,offset,old(buffer)@.len(),error));
                return Err(Error::Io(error));
            },

        };
        if n == 0 {return Err(Error::Short);}
        let ghost received = part@;
        proof {
            assert(buffer@.skip(filled as int) =~= received);
            assert(buffer@.take(filled as int) =~= before.take(filled as int));
            assert(buffer@.subrange(filled as int,filled as int+n) =~= received.take(n as int));
            assert(buffer@.take(filled as int+n) =~= media.image().subrange(offset as int,offset as int+filled+n));
        }
        let Some(next) = filled.checked_add(n) else {return Err(Error::Length);};
        filled = next;
    }
    assert(buffer@ =~= buffer@.take(filled as int));
    Ok(())
}

}
