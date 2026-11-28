//! Preserve header/payload order while preparing vectors and continuing short writes.
use super::arena_frame::PreparedFrame;
#[cfg(verus_keep_ghost)]
use super::arena_frame::prefix;
use vstd::prelude::*;

verus! {

pub(super) trait Part<'a>: Sized {
    spec fn data(&self) -> Seq<u8>;
    fn borrow(bytes:&'a [u8]) -> (out:Self) ensures out.data() == bytes@;
}

pub(super) open spec fn flatten<'a,P:Part<'a>>(parts:Seq<P>,n:nat) -> Seq<u8>
    decreases n,
{
    if n == 0 {Seq::empty()} else {flatten(parts,(n-1) as nat) + parts[n-1].data()}
}

pub(super) fn vectors<'a,P:Part<'a>>(batch:&'a [PreparedFrame]) -> (out:Option<Vec<P>>)
    ensures out matches Some(parts) ==> parts.len() == 2 * batch.len() &&
        flatten(parts@,parts@.len()) == prefix(batch@,batch@.len()),
{
    let mut parts = Vec::new();
    parts.try_reserve_exact(batch.len().checked_mul(2)?).ok()?;
    let mut i = 0usize;
    while i < batch.len()
        invariant i <= batch.len(), parts.len() == 2*i,
            flatten(parts@,parts@.len()) == prefix(batch@,i as nat),
        decreases batch.len()-i,
    {
        let (header,payload) = batch[i].parts();
        let ghost before = parts@;
        parts.push(P::borrow(header));
        parts.push(P::borrow(payload));
        proof {
            reveal_with_fuel(flatten,3);
            same_parts(before,parts@,before.len());
            assert(flatten(parts@,parts@.len()) == flatten(before,before.len()) + header@ + payload@);
        }
        i = i.saturating_add(1);
    }
    Some(parts)
}

proof fn same_parts<'a,P:Part<'a>>(a:Seq<P>,b:Seq<P>,n:nat)
    requires n <= a.len(), n <= b.len(), forall|i:int| 0 <= i < n ==> #[trigger] a[i] == #[trigger] b[i],
    ensures flatten(a,n) == flatten(b,n),
    decreases n,
{
    if n > 0 {same_parts(a,b,(n-1) as nat);}
}

/// The primitive writer reports a prefix of the outstanding slices. Moving
/// their cursor changes only what remains to be sent.
pub(super) trait Cursor {
    type Error;
    spec fn sent(&self) -> Seq<u8>;
    spec fn remaining(&self) -> Seq<u8>;
    fn empty(&self) -> (out:bool) ensures out ==> self.remaining().len() == 0;
    fn write_part(&mut self) -> (out:Result<usize,Self::Error>)
        ensures final(self).remaining() == old(self).remaining(),
            match out {
                Ok(n) => n <= old(self).remaining().len() &&
                    final(self).sent() == old(self).sent()+old(self).remaining().take(n as int),
                Err(_) => final(self).sent() == old(self).sent(),
            };
    fn advance(&mut self,n:usize)
        requires n <= old(self).remaining().len(),
        ensures final(self).sent() == old(self).sent() && final(self).remaining() == old(self).remaining().skip(n as int);
}

pub(super) enum Error<E> { NoProgress, Io(E) }

pub(super) fn transmit<C:Cursor>(cursor:&mut C) -> (out:Result<(),Error<C::Error>>)
    ensures out.is_ok() ==> final(cursor).sent() == old(cursor).sent()+old(cursor).remaining(),
        exists|i:int| 0 <= i <= old(cursor).remaining().len() &&
            final(cursor).sent() == old(cursor).sent()+old(cursor).remaining().take(i) &&
            final(cursor).remaining() == old(cursor).remaining().skip(i),
{
    let ghost input = cursor.remaining();
    let ghost mut consumed:int = 0;
    while !cursor.empty()
        invariant 0 <= consumed <= input.len(), input == old(cursor).remaining(),
            cursor.sent() == old(cursor).sent()+input.take(consumed), cursor.remaining() == input.skip(consumed),
        decreases cursor.remaining().len(),
    {
        let n = match cursor.write_part() {
            Ok(n) => n,
            Err(e) => return Err(Error::Io(e)),
        };
        if n == 0 {return Err(Error::NoProgress);}
        cursor.advance(n);
        proof {
            assert(input.take(consumed)+input.skip(consumed).take(n as int) =~= input.take(consumed+n));
            assert(input.skip(consumed).skip(n as int) =~= input.skip(consumed+n));
            consumed = consumed+n;
        };
    }
    assert(consumed == input.len());
    assert(input.take(consumed) =~= input);
    Ok(())
}

}
