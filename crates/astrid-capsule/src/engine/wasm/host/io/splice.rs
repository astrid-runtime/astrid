//! Bind both resource-table operands and the byte limit to one admitted splice.
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode { Immediate, Blocking }

#[derive(Clone, Copy)]
pub(super) struct Request {
    pub(super) mode: Mode,
    pub(super) destination: u32,
    pub(super) source: u32,
    pub(super) length: u64,
}

pub(super) struct Admitted<G> { request: Request, guard: G }

/// Bound a native read by both the caller's length and the live write permit.
pub(super) fn chunk_limit(length: u64, permit: usize) -> (limit: usize)
    ensures limit as int == if (length as int) < (permit as int) { length as int } else { permit as int },
{
    if (length as u128) < (permit as u128) { length as usize } else { permit }
}

pub(super) enum Chunk<R> {
    Empty,
    Oversized,
    Submitted(usize, R),
}

/// Measure the same buffer that is passed to the writer. The outcome carries
/// the measured size so native accounting never needs a second observation.
pub(super) fn write_chunk<B, R, L: FnOnce(&B) -> usize, F: FnOnce(B) -> R>(
    limit: usize, bytes: B, measure: L, write: F,
) -> (out: Chunk<R>)
    requires measure.requires((&bytes,)),
        forall|n: usize| #[trigger] measure.ensures((&bytes,), n) && 0 < n <= limit ==> write.requires((bytes,)),
    ensures match out {
        Chunk::Empty => measure.ensures((&bytes,), 0),
        Chunk::Oversized => exists|n: usize| #[trigger] measure.ensures((&bytes,), n) && n > limit,
        Chunk::Submitted(n, r) => measure.ensures((&bytes,), n) && 0 < n <= limit && write.ensures((bytes,), r),
    },
{
    let n = measure(&bytes);
    if n == 0 { Chunk::Empty }
    else if n > limit { Chunk::Oversized }
    else { Chunk::Submitted(n, write(bytes)) }
}

impl Request {
    pub(super) fn admit<G,E,F: FnOnce(Request) -> Result<G,E>>(self, check: F)
        -> (out: Result<Admitted<G>, E>)
        requires check.requires((self,)),
        ensures match out {
            Ok(operation) => operation.args() == self && check.ensures((self,), Ok(operation.authority())),
            Err(error) => check.ensures((self,), Err(error)),
        },
    {
        let guard = check(self)?;
        Ok(Admitted { request: self, guard })
    }
}

impl<G> Admitted<G> {
    pub(super) closed spec fn args(&self) -> Request { self.request }
    pub(super) closed spec fn authority(&self) -> G { self.guard }

    pub(super) fn start<'a, T, R, F>(&'a self, mode: Mode, table: T, sink: F) -> (out: Option<R>)
        where F: FnOnce(&'a G, T, Request) -> R,
        requires ({
            let r = self.args();
            r.mode == mode ==> sink.requires((&self.authority(), table, r))
        }),
        ensures ({
            let r = self.args();
            if r.mode == mode {
                out matches Some(value) && sink.ensures((&self.authority(), table, r), value)
            } else { out.is_none() }
        }),
    {
        let r = self.request;
        match (r.mode, mode) {
            (Mode::Immediate, Mode::Immediate) | (Mode::Blocking, Mode::Blocking) =>
                Some(sink(&self.guard, table, r)),
            _ => None,
        }
    }
}
}
