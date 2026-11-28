//! Shared signed-challenge encoding and device registration selection.

use vstd::prelude::*;

verus! {

pub(crate) open spec fn transcript(prefix: Seq<char>, principal: Seq<char>, nonce: Seq<char>) -> Seq<char> {
    prefix + principal + seq![':'] + nonce
}

pub(crate) proof fn transcript_injective(prefix: Seq<char>, a: Seq<char>, b: Seq<char>,
    x: Seq<char>, y: Seq<char>)
    requires !a.contains(':'), !b.contains(':'), transcript(prefix, a, x) == transcript(prefix, b, y),
    ensures a == b, x == y,
{
    if a.len() < b.len() {
        let cut = (prefix.len() + a.len()) as int;
        assert(transcript(prefix, a, x)[cut] == ':');
        assert(transcript(prefix, b, y)[cut] == b[a.len() as int]);
        assert(b.contains(b[a.len() as int]));
    }
    if b.len() < a.len() {
        let cut = (prefix.len() + b.len()) as int;
        assert(transcript(prefix, b, y)[cut] == ':');
        assert(transcript(prefix, a, x)[cut] == a[b.len() as int]);
        assert(a.contains(a[b.len() as int]));
    }
    assert(a =~= b) by {
        assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
            let j = prefix.len() + i;
            assert(transcript(prefix, a, x)[j] == a[i]);
            assert(transcript(prefix, b, y)[j] == b[i]);
        }
    }
    assert(transcript(prefix, a, x).len() == prefix.len() + a.len() + 1 + x.len());
    assert(transcript(prefix, b, y).len() == prefix.len() + b.len() + 1 + y.len());
    assert(x.len() == y.len());
    assert(x =~= y) by {
        assert forall|i: int| 0 <= i < x.len() implies x[i] == y[i] by {
            let j = prefix.len() + a.len() + 1 + i;
            assert(transcript(prefix, a, x)[j] == x[i]);
            assert(transcript(prefix, b, y)[j] == y[i]);
        }
    }
}

pub(crate) fn challenge_message(prefix: &str, principal: &str, nonce: &str) -> (message: String)
    ensures
        message@ == transcript(prefix@, principal@, nonce@),
        !principal@.contains(':') ==> forall|p: Seq<char>, n: Seq<char>|
            !p.contains(':') && #[trigger] transcript(prefix@, p, n) == message@
                ==> p == principal@ && n == nonce@,
{
    let mut message = prefix.to_owned();
    message.push_str(principal);
    message.push(':');
    message.push_str(nonce);
    proof {
        assert(message@ == transcript(prefix@, principal@, nonce@));
        if !principal@.contains(':') {
            assert forall|p: Seq<char>, n: Seq<char>| !p.contains(':')
                && #[trigger] transcript(prefix@, p, n) == message@ implies p == principal@ && n == nonce@ by {
                transcript_injective(prefix@, principal@, p, nonce@, n);
            }
        }
    }
    message
}

pub(super) closed spec fn observed<T, S, K: Fn(&T) -> Option<&str>, V: Fn(&S, &str, &[u8]) -> bool>(
    record: &T, signature: &S, message: &[u8], public_key: K, verify: V, accepted: bool,
) -> bool {
    exists|key: Option<&str>| public_key.ensures((record,), key) && match key {
        Some(k) => verify.ensures((signature, k, message), accepted),
        None => !accepted,
    }
}

fn accepts<T, S, K: Fn(&T) -> Option<&str>, V: Fn(&S, &str, &[u8]) -> bool>(
    record: &T, signature: &S, message: &[u8], public_key: &K, verify: &V,
) -> (accepted: bool)
    requires public_key.requires((record,)), forall|k: &str| #[trigger] verify.requires((signature, k, message)),
    ensures observed(record, signature, message, *public_key, *verify, accepted),
{
    match public_key(record) {
        Some(k) => verify(signature, k, message),
        None => false,
    }
}

/// Return the complete record whose public key validated the signature.
pub(super) fn signed_device<'a, T, S, K: Fn(&T) -> Option<&str>, V: Fn(&S, &str, &[u8]) -> bool>(
    records: &'a [T], signature: &S, message: &[u8], public_key: K, verify: V,
) -> (selected: Option<&'a T>)
    requires
        forall|r: &T| #[trigger] public_key.requires((r,)),
        forall|k: &str| #[trigger] verify.requires((signature, k, message)),
    ensures match selected {
        Some(record) => exists|i: int| 0 <= i < records.len()
            && observed(&records@[i], signature, message, public_key, verify, true)
            && *record == records@[i]
            && forall|j: int| 0 <= j < i ==>
                observed(&records@[j], signature, message, public_key, verify, false),
        None => forall|j: int| 0 <= j < records.len() ==>
            observed(&records@[j], signature, message, public_key, verify, false),
    },
{
    let mut i = 0usize;
    while i < records.len()
        invariant
            i <= records.len(),
            forall|r: &T| #[trigger] public_key.requires((r,)),
            forall|k: &str| #[trigger] verify.requires((signature, k, message)),
            forall|j: int| 0 <= j < i ==> observed(&records@[j], signature, message, public_key, verify, false),
        decreases records.len() - i,
    {
        let record = &records[i];
        if accepts(record, signature, message, &public_key, &verify) {
            return Some(record);
        }
        i = i.saturating_add(1);
    }
    None
}

}
