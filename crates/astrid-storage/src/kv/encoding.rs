//! Canonical durable KV entry addresses.

use vstd::prelude::*;

verus! {

pub(super) fn composite(namespace: &[u8], key: &[u8]) -> (address: Vec<u8>)
    ensures address@ == namespace@ + seq![0u8] + key@,
{
    let mut address = Vec::with_capacity(namespace.len().saturating_add(1).saturating_add(key.len()));
    address.extend_from_slice(namespace);
    address.push(0);
    address.extend_from_slice(key);
    address
}

/// Under namespace validation, equal physical addresses identify exactly one
/// namespace and one complete key, including when either is a prefix of another.
pub(super) proof fn address_injective(a: Seq<u8>, k: Seq<u8>, b: Seq<u8>, q: Seq<u8>)
    requires
        !a.contains(0u8),
        !b.contains(0u8),
        a + seq![0u8] + k == b + seq![0u8] + q,
    ensures a == b && k == q,
{
    if a.len() < b.len() {
        assert((a + seq![0u8] + k)[a.len() as int] == 0u8);
        assert(b[a.len() as int] == 0u8);
        assert(b.contains(0u8));
    }
    if b.len() < a.len() {
        assert((b + seq![0u8] + q)[b.len() as int] == 0u8);
        assert(a[b.len() as int] == 0u8);
        assert(a.contains(0u8));
    }
    assert(a.len() == b.len());
    assert((a + seq![0u8] + k).len() == a.len() + 1 + k.len());
    assert((b + seq![0u8] + q).len() == b.len() + 1 + q.len());
    assert(a =~= b) by {
        assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
            assert((a + seq![0u8] + k)[i] == a[i]);
            assert((b + seq![0u8] + q)[i] == b[i]);
        }
    }
    assert(k =~= q) by {
        assert forall|i: int| 0 <= i < k.len() implies k[i] == q[i] by {
            assert((a + seq![0u8] + k)[a.len() + 1 + i] == k[i]);
            assert((b + seq![0u8] + q)[b.len() + 1 + i] == q[i]);
        }
    }
}

}
