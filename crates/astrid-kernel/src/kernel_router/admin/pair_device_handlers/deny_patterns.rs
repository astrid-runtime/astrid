//! Deny-pattern union used by the hosted pairing-token writer.
use vstd::prelude::*;
verus! {

pub(super) open spec fn has(xs: Seq<String>, key: Seq<char>) -> bool {
    exists|j: int| 0 <= j < xs.len() && #[trigger] xs[j]@ == key
}

fn contains(xs: &[String], key: &str) -> (found: bool)
    ensures found == has(xs@, key@),
{
    let mut j = 0usize;
    while j < xs.len()
        invariant j <= xs.len(), forall|k: int| 0 <= k < j ==> #[trigger] xs@[k]@ != key@,
        decreases xs.len() - j,
    {
        if xs[j].as_str() == key {
            assert(xs@[j as int]@ == key@);
            return true;
        }
        j = j.saturating_add(1);
    }
    false
}

proof fn appended(xs: Seq<String>, value: String)
    ensures forall|key: Seq<char>| #[trigger] has(xs.push(value), key) == (has(xs, key) || key == value@),
{
    assert forall|key: Seq<char>| #[trigger] has(xs.push(value), key) == (has(xs, key) || key == value@) by {
        assert(xs.push(value)[xs.len() as int]@ == value@);
        if has(xs.push(value), key) {
            let j = choose|j: int| 0 <= j < xs.push(value).len() && xs.push(value)[j]@ == key;
            if j < xs.len() { assert(xs[j]@ == key); }
        } else if has(xs, key) {
            let j = choose|j: int| 0 <= j < xs.len() && xs[j]@ == key;
            assert(xs.push(value)[j]@ == key);
        }
    }
}

pub(super) fn inherit(child: &mut Vec<String>, issuer: &[String])
    ensures old(child).len() <= final(child).len() <= old(child).len() + issuer.len(),
        forall|j: int, k: int| old(child).len() <= j < final(child).len() && 0 <= k < j
            ==> #[trigger] final(child)@[j]@ != #[trigger] final(child)@[k]@,
        forall|j: int| 0 <= j < old(child).len() ==> final(child)@[j] == old(child)@[j],
        forall|key: Seq<char>| #[trigger] has(final(child)@, key) == (has(old(child)@, key) || has(issuer@, key)),
{
    let mut i = 0usize;
    while i < issuer.len()
        invariant i <= issuer.len(), old(child).len() <= child.len() <= old(child).len() + i,
            forall|j: int, k: int| old(child).len() <= j < child.len() && 0 <= k < j
                ==> #[trigger] child@[j]@ != #[trigger] child@[k]@,
            forall|j: int| 0 <= j < old(child).len() ==> child@[j] == old(child)@[j],
            forall|key: Seq<char>| #[trigger] has(child@, key) == (has(old(child)@, key) || has(issuer@.take(i as int), key)),
        decreases issuer.len() - i,
    {
        let pattern = &issuer[i];
        if !contains(child, pattern.as_str()) {
            let copy = pattern.clone();
            proof { appended(child@, copy); }
            child.push(copy);
        }
        proof { appended(issuer@.take(i as int), *pattern); }
        assert(issuer@.take(i as int + 1) =~= issuer@.take(i as int).push(*pattern));
        i = i.saturating_add(1);
    }
    assert(issuer@.take(i as int) =~= issuer@);
}
}
