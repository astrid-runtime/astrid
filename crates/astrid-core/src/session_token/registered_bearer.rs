//! Signed transcript for gateway bearers carrying a pairing generation.

use vstd::prelude::*;

verus! {

pub open spec fn encoding(claims: Seq<char>, registration: Seq<char>) -> Seq<char> {
    "astrid.gateway.device.v4\0"@ + claims + seq!['.'] + registration
}

proof fn unique_registration(a: Seq<char>, x: Seq<char>, b: Seq<char>, y: Seq<char>)
    requires
        !x.contains('.'), !y.contains('.'), encoding(a, x) == encoding(b, y),
    ensures a == b, x == y,
{
    let prefix = "astrid.gateway.device.v4\0"@;
    assert(encoding(a, x).len() == prefix.len() + a.len() + 1 + x.len());
    assert(encoding(b, y).len() == prefix.len() + b.len() + 1 + y.len());
    if a.len() < b.len() {
        let i = (prefix.len() + b.len()) as int;
        assert(0 <= i - prefix.len() - a.len() - 1 < x.len());
        assert(encoding(b, y)[i] == '.');
        assert(encoding(a, x)[i] == x[i - prefix.len() - a.len() - 1]);
        assert(x.contains('.'));
    }
    if b.len() < a.len() {
        let i = (prefix.len() + a.len()) as int;
        assert(0 <= i - prefix.len() - b.len() - 1 < y.len());
        assert(encoding(a, x)[i] == '.');
        assert(encoding(b, y)[i] == y[i - prefix.len() - b.len() - 1]);
        assert(y.contains('.'));
    }
    assert(a =~= b) by {
        assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
            assert(encoding(a, x)[prefix.len() + i] == a[i]);
            assert(encoding(b, y)[prefix.len() + i] == b[i]);
        }
    }
    assert(encoding(a, x).len() == prefix.len() + a.len() + 1 + x.len());
    assert(encoding(b, y).len() == prefix.len() + b.len() + 1 + y.len());
    assert(x =~= y) by {
        assert forall|i: int| 0 <= i < x.len() implies x[i] == y[i] by {
            let j = prefix.len() + a.len() + 1 + i;
            assert(encoding(a, x)[j] == x[i]);
            assert(encoding(b, y)[j] == y[i]);
        }
    }
}

/// Construct the signed v4 transcript from the first five wire fields and the
/// canonical registration UUID. Equal transcripts bind equal claims and registrations.
#[must_use]
pub fn registration_transcript(claims: &str, registration: &str) -> (signed: String)
    ensures
        signed@ == encoding(claims@, registration@),
        !registration@.contains('.') ==> forall|c: Seq<char>, r: Seq<char>|
            !r.contains('.') && #[trigger] encoding(c, r) == signed@ ==> c == claims@ && r == registration@,
{
    let mut signed = "astrid.gateway.device.v4\0".to_owned();
    signed.push_str(claims);
    signed.push('.');
    signed.push_str(registration);
    proof {
        assert(signed@ == encoding(claims@, registration@));
        assert forall|c: Seq<char>, r: Seq<char>| !registration@.contains('.') && !r.contains('.')
            && #[trigger] encoding(c, r) == signed@ implies c == claims@ && r == registration@ by {
            unique_registration(c, r, claims@, registration@);
        }
    }
    signed
}

}
