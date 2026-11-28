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

pub(super) enum SpanError<I,E> { Capacity, Read(Error<I>), Consumer(E) }

pub(super) open spec fn interval<M:Media>(media:&M,offset:u64,size:u64,data:&[u8]) -> bool {
    data.len() == size && (size > 0 ==> offset as int + size <= media.image().len() &&
        data@ == media.image().subrange(offset as int,offset as int + size))
}

pub(super) open spec fn span_result<M:Media,T,E,F:FnOnce(&[u8],u64)->Result<T,E>>(
    media:&M,offset:u64,size:u64,consume:F,result:Result<T,E>) -> bool {
    exists|data:&[u8],base:u64| interval(media,offset,size,data) && base == offset &&
        #[trigger] consume.ensures((data,base),result)
}

/// Call the consumer with the completed buffer and its absolute starting offset.
pub(super) fn with_span<M:Media,T,E,F:FnOnce(&[u8],u64)->Result<T,E>>(media:&M,offset:u64,size:u64,
    consume:F) -> (out:Result<T,SpanError<M::Error,E>>)
    requires forall|data:&[u8]| interval(media,offset,size,data) ==> #[trigger] consume.requires((data,offset)),
    ensures match out {
        Ok(value) => span_result(media,offset,size,consume,Ok(value)),
        Err(SpanError::Consumer(error)) => span_result(media,offset,size,consume,Err(error)),
        Err(SpanError::Read(Error::Short)) => offset as int + size > media.image().len(),
        Err(SpanError::Read(Error::Offset)) => offset as int + size > u64::MAX,
        Err(SpanError::Read(Error::Length)) => false,
        Err(SpanError::Read(Error::Io(e))) => failed_within(media,offset,size as nat,e),
        Err(SpanError::Capacity) => true,
    },
{
    let Ok(len) = usize::try_from(size) else {return Err(SpanError::Capacity);};
    let mut data = Vec::new();
    if data.try_reserve_exact(len).is_err() {return Err(SpanError::Capacity);}
    data.resize(len,0);
    let buffer = data.as_mut_slice();
    if let Err(error) = exact(media,offset,buffer) {return Err(SpanError::Read(error));}
    let bytes = data.as_slice();
    assert(interval(media,offset,size,bytes));
    let result = consume(bytes,offset);
    assert(consume.ensures((bytes,offset),result));
    assert(span_result(media,offset,size,consume,result));
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(SpanError::Consumer(error)),
    }
}

}
