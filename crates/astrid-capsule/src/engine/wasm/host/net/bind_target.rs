//! Numeric TCP bind admission and validation of the endpoint reported by the OS.
use vstd::prelude::*;

verus! {
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Address {
    V4(u32),
    V6(u128),
}

#[derive(Clone, Copy)]
pub(super) struct Target {
    address: Address,
    port: u16,
}

impl Address {
    pub(super) open spec fn loopback(self) -> bool {
        match self {
            Self::V4(bits) => bits as int / 0x1000000 == 127,
            Self::V6(bits) => bits == 1,
        }
    }
}

impl Target {
    pub(super) closed spec fn requested(self) -> (Address, u16) {
        (self.address, self.port)
    }

    pub(super) fn admit(address: Address, port: u16) -> (out: Option<Self>)
        ensures if address.loopback() { out matches Some(t) && t.requested() == (address, port) } else { out.is_none() },
    {
        let allowed = match address {
            Address::V4(bits) => bits / 0x1000000 == 127,
            Address::V6(bits) => bits == 1,
        };
        if allowed { Some(Self { address, port }) } else { None }
    }

    pub(super) fn endpoint(self) -> (out: (Address, u16))
        ensures out == self.requested(),
    {
        (self.address, self.port)
    }

    pub(super) fn matches_bound(self, actual: Address, assigned: u16) -> (ok: bool)
        ensures ok == (actual == self.requested().0 && assigned != 0 && (self.requested().1 == 0 || assigned == self.requested().1)),
    {
        let same = match (self.address, actual) {
            (Address::V4(a), Address::V4(b)) => a == b,
            (Address::V6(a), Address::V6(b)) => a == b,
            _ => false,
        };
        same && assigned != 0 && (self.port == 0 || assigned == self.port)
    }

    /// Return the precise OS observation for publication or refusal.
    pub(super) fn confirm<T,F: FnOnce(&T) -> (Address,u16)>(self, observed: T, inspect: F)
        -> (out: Result<T,T>)
        requires inspect.requires((&observed,)),
        ensures exists|a:Address,p:u16| #[trigger] inspect.ensures((&observed,),(a,p))
            && out == if a == self.requested().0 && p != 0 && (self.requested().1 == 0 || p == self.requested().1) {
                Ok(observed)
            } else { Err(observed) },
    {
        let (actual, assigned) = inspect(&observed);
        if self.matches_bound(actual,assigned) { Ok(observed) } else { Err(observed) }
    }

}
}
