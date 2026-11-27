//! Bounds-checked field reads shared by persisted storage formats.
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy)]
pub(crate) enum ReadError { Overflow(usize), Truncated }

/// Advance the cursor only when the entire requested field was present.
pub(crate) fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize)
    -> (read: Result<&'a [u8],ReadError>)
    ensures
        read.is_ok() == (*old(cursor) as int + len <= bytes.len()),
        read matches Ok(field) ==> *final(cursor) as int == *old(cursor) as int + len &&
            field@ == bytes@.subrange(*old(cursor) as int,*final(cursor) as int),
        read.is_err() ==> *final(cursor) == *old(cursor),
        (read matches Err(ReadError::Overflow(_))) == (*old(cursor) as int + len > usize::MAX),
        read matches Err(ReadError::Overflow(n)) ==> n == len,
{
    let Some(end) = cursor.checked_add(len) else { return Err(ReadError::Overflow(len)); };
    if end > bytes.len() { return Err(ReadError::Truncated); }
    let field = &bytes[*cursor..end];
    *cursor = end;
    Ok(field)
}

pub(crate) open spec fn at(bytes: Seq<u8>, offset: int, field: Seq<u8>) -> bool {
    0 <= offset && offset + field.len() <= bytes.len() &&
        bytes.subrange(offset, offset + field.len()) == field
}

pub(crate) proof fn subfield(bytes: Seq<u8>, start: int, whole: Seq<u8>, pos: int, len: int)
    requires at(bytes,start,whole), 0 <= pos, 0 <= len, pos+len <= whole.len(),
    ensures bytes.subrange(start+pos,start+pos+len) == whole.subrange(pos,pos+len),
{
    assert(bytes.subrange(start+pos,start+pos+len) =~= whole.subrange(pos,pos+len)) by {
        assert forall|i: int| 0 <= i < len implies bytes[start+pos+i] == #[trigger] whole[pos+i] by {
            assert(bytes.subrange(start,start+whole.len())[pos+i] == bytes[start+pos+i]);
        }
    }
}

pub(crate) fn fixed<const N: usize>(bytes: &[u8], cursor: &mut usize) -> (value: Result<[u8;N],ReadError>)
    ensures value.is_ok() == (*old(cursor) as int + N <= bytes.len()),
        value matches Ok(array) ==> *final(cursor) as int == *old(cursor) as int + N
            && at(bytes@,*old(cursor) as int,array@),
        value.is_err() ==> *final(cursor) == *old(cursor),
        (value matches Err(ReadError::Overflow(_))) == (*old(cursor) as int + N > usize::MAX),
        value matches Err(ReadError::Overflow(n)) ==> n == N,
{
    let field = take(bytes, cursor, N)?;
    let mut array = [0u8;N];
    array.copy_from_slice(field);
    Ok(array)
}

}
