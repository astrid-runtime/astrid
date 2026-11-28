//! Canonical hosted root-owner bytes in durable journal and recovery records.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
pub(super) enum Owner {
    System,
    Principal([u8; 32]),
    Fleet([u8; 32]),
}

impl Owner {
    pub(super) open spec fn bytes(self) -> Seq<u8> {
        match self {
            Self::System => seq![0u8],
            Self::Principal(id) => seq![1u8] + id@,
            Self::Fleet(id) => seq![2u8] + id@,
        }
    }

    pub(super) fn encode(self) -> (out: Vec<u8>)
        ensures out@ == self.bytes(),
    {
        let (tag, id) = match self {
            Self::System => return vec![0],
            Self::Principal(id) => (1u8, id),
            Self::Fleet(id) => (2u8, id),
        };
        let mut bytes = Vec::with_capacity(33);
        bytes.push(tag);
        bytes.extend_from_slice(&id);
        bytes
    }
}

pub(super) fn decode(bytes: &[u8]) -> (owner: Option<Owner>)
    ensures
        owner.is_some() == (bytes@ == seq![0u8] ||
            (bytes.len() == 33 && (bytes[0] == 1 || bytes[0] == 2))),
        owner matches Some(o) ==> o.bytes() == bytes@,
{
    if bytes.len() == 1 && bytes[0] == 0 {
        assert(bytes@ =~= seq![0u8]);
        return Some(Owner::System);
    }
    if bytes.len() != 33 || (bytes[0] != 1 && bytes[0] != 2) { return None; }
    let mut id = [0u8; 32];
    let mut i = 0usize;
    while i < 32
        invariant i <= 32, bytes.len() == 33,
            forall|j: int| 0 <= j < i ==> #[trigger] id@[j] == bytes@[j+1],
        decreases 32-i,
    {
        id[i] = bytes[i.saturating_add(1)];
        i = i.saturating_add(1);
    }
    assert(seq![bytes[0]] + id@ =~= bytes@);
    if bytes[0] == 1 { Some(Owner::Principal(id)) } else { Some(Owner::Fleet(id)) }
}

}
