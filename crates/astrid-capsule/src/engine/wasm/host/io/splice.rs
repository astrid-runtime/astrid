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
