//! Check the native path text before it can enter a sandbox profile.
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::string::StringSliceAdditionalSpecFns;

verus! {

pub(super) open spec fn permitted(byte: u8) -> bool {
    byte != b'"' && byte != 92 && byte != 0
}

pub(super) fn checked(path: &str) -> (out: Option<&str>)
    ensures
        out.is_some() == (forall|i:int| 0 <= i < path.spec_bytes().len() ==>
            permitted(#[trigger] path.spec_bytes()[i])),
        out matches Some(value) ==> value == path,
{
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        invariant
            bytes@ == path.spec_bytes(),
            i <= bytes.len(),
            forall|j:int| 0 <= j < i ==> permitted(#[trigger] bytes@[j]),
        decreases bytes.len() - i,
    {
        if matches!(bytes[i], b'"' | b'\\' | 0) {
            assert(!permitted(path.spec_bytes()[i as int]));
            return None;
        }
        i = i.saturating_add(1);
    }
    Some(path)
}

}
