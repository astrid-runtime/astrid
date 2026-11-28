//! Canonical component rules for paths in the authoritative content namespace.

use vstd::prelude::*;

verus! {

spec fn boundary(path: Seq<u8>, at: int) -> bool {
    at == path.len() || (0 <= at < path.len() && path[at] == b'/')
}

spec fn permitted(path: Seq<u8>, i: int) -> bool {
    &&& path[i] != 0
    &&& path[i] == b'/' ==> i > 0 && !boundary(path, i + 1)
    &&& (i == 0 || path[i - 1] == b'/') && path[i] == b'.' ==> {
        &&& !boundary(path, i + 1)
        &&& i + 1 < path.len() && path[i + 1] == b'.' ==> !boundary(path, i + 2)
    }
}

pub(super) closed spec fn canonical(path: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < path.len() ==> #[trigger] permitted(path, i)
}

/// Check a single component boundary without interpreting ordinary UTF-8 bytes.
#[expect(clippy::arithmetic_side_effects, reason = "Verus checks the bounds of the predecessor and both lookahead indices")]
fn permitted_at(path: &[u8], i: usize) -> (valid: bool)
    requires i < path.len(),
    ensures valid == permitted(path@, i as int),
{
    let byte = path[i];
    if byte == 0 { return false; }
    let next = i + 1;
    if byte == b'/' {
        return i != 0 && next < path.len() && path[next] != b'/';
    }
    if byte != b'.' || (i != 0 && path[i - 1] != b'/') { return true; }
    if next == path.len() || path[next] == b'/' { return false; }
    if path[next] != b'.' { return true; }
    let after = next + 1;
    after < path.len() && path[after] != b'/'
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves the cursor is below the slice length at increment")]
pub(super) fn is_canonical(path: &[u8]) -> (valid: bool)
    ensures valid == canonical(path@),
{
    let mut i = 0;
    while i < path.len()
        invariant i <= path.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] permitted(path@, j),
        decreases path.len() - i,
    {
        if !permitted_at(path, i) {
            assert(!canonical(path@));
            return false;
        }
        i += 1;
    }
    true
}

/// Joining two non-root canonical names preserves each component boundary.
pub(super) proof fn canonical_join(base: Seq<u8>, relative: Seq<u8>)
    requires canonical(base), canonical(relative), base.len() > 0, relative.len() > 0,
    ensures canonical(base.push(b'/') + relative),
{
    let joined = base.push(b'/') + relative;
    assert forall|i: int| 0 <= i < joined.len() implies #[trigger] permitted(joined, i) by {
        if i < base.len() {
            assert(permitted(base, i));
        } else if i == base.len() {
            assert(permitted(relative, 0));
        } else {
            let j = i - base.len() - 1;
            assert(permitted(relative, j));
        }
    }
}

/// Preserve the directory spelling and the entire validated relative suffix.
pub(super) fn join(base: &str, relative: String) -> (path: String)
    ensures path@ == if base@.len() == 0 { relative@ }
        else if relative@.len() == 0 { base@ }
        else { base@.push('/') + relative@ },
{
    if base.is_empty() { return relative; }
    let mut path = base.to_owned();
    if !relative.is_empty() {
        path.push('/');
        path.push_str(relative.as_str());
    }
    path
}

}
