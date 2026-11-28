//! Byte transcript authenticated by the broker's multi-round consent codec.
use vstd::prelude::*;

verus! {

pub(super) open spec fn body(p: Seq<u8>, t: Seq<u8>, a: Seq<u8>) -> Seq<u8> {
    p + seq![0u8] + t + seq![0u8] + a
}

pub(super) open spec fn transcript(p: Seq<u8>, t: Seq<u8>, a: Seq<u8>) -> Seq<u8> {
    b"astrid/mcp/mrtr/v1\0"@ + body(p,t,a)
}

pub(super) trait Digest {
    spec fn bytes(&self) -> Seq<u8>;

    fn absorb(&mut self, chunk: &[u8])
        ensures final(self).bytes() == old(self).bytes() + chunk@;
}

pub(super) fn absorb_context<D: Digest>(digest: &mut D, principal: &[u8], tool: &[u8], arguments: &[u8])
    ensures final(digest).bytes() == old(digest).bytes() + transcript(principal@,tool@,arguments@),
{
    digest.absorb(b"astrid/mcp/mrtr/v1\0");
    digest.absorb(principal);
    digest.absorb(&[0u8]);
    digest.absorb(tool);
    digest.absorb(&[0u8]);
    digest.absorb(arguments);
    assert(final(digest).bytes() =~= old(digest).bytes() + transcript(principal@,tool@,arguments@));
}

/// Claim the same signed continuation that the codec opened for this context.
pub(super) fn open_and_redeem<'a,P,G,E,O,R>(state: &'a str, context: &'a [u8], open: O, redeem: R)
    -> (result: Result<(P,G),E>)
    where O: FnOnce(&'a str,&'a [u8]) -> Result<P,E>, R: FnOnce(&'a str) -> Result<G,E>,
    requires open.requires((state,context)), redeem.requires((state,)),
    ensures match result {
        Ok((pending,guard)) => open.ensures((state,context),Ok(pending)) && redeem.ensures((state,),Ok(guard)),
        Err(error) => open.ensures((state,context),Err(error)) ||
            ((exists|pending:P| #[trigger] open.ensures((state,context),Ok(pending))) && redeem.ensures((state,),Err(error))),
    },
{
    let pending = open(state,context)?;
    let guard = redeem(state)?;
    Ok((pending,guard))
}

/// The first NUL after the domain separates the principal. The last one starts
/// the JSON bytes. Tool identifiers may contain arbitrary bytes in between.
pub(super) proof fn injective(p: Seq<u8>, t: Seq<u8>, a: Seq<u8>,
    q: Seq<u8>, u: Seq<u8>, b: Seq<u8>)
    requires !p.contains(0), !q.contains(0), !a.contains(0), !b.contains(0),
        transcript(p,t,a) == transcript(q,u,b),
    ensures p == q, t == u, a == b,
{
    let domain = b"astrid/mcp/mrtr/v1\0"@;
    let x = body(p,t,a);
    let y = body(q,u,b);
    assert(transcript(p,t,a).len() == domain.len() + x.len());
    assert(transcript(q,u,b).len() == domain.len() + y.len());
    assert(x.len() == y.len());
    assert(x =~= y) by {
        assert forall|i:int| 0 <= i < x.len() implies x[i] == y[i] by {
            assert(transcript(p,t,a)[domain.len()+i] == x[i]);
            assert(transcript(q,u,b)[domain.len()+i] == y[i]);
        }
    }
    if p.len() < q.len() {
        let i = p.len() as int;
        assert(x[i] == 0); assert(y[i] == q[i]); assert(q.contains(q[i]));
    }
    if q.len() < p.len() {
        let i = q.len() as int;
        assert(y[i] == 0); assert(x[i] == p[i]); assert(p.contains(p[i]));
    }
    if a.len() < b.len() {
        let i = x.len() - a.len() - 1;
        let j = b.len() - a.len() - 1;
        assert(x[i] == 0); assert(y[i] == b[j]); assert(b.contains(b[j]));
    }
    if b.len() < a.len() {
        let i = y.len() - b.len() - 1;
        let j = a.len() - b.len() - 1;
        assert(y[i] == 0); assert(x[i] == a[j]); assert(a.contains(a[j]));
    }
    assert(p =~= q) by {
        assert forall|i:int| 0 <= i < p.len() implies p[i] == q[i] by {
            assert(x[i] == p[i]); assert(y[i] == q[i]);
        }
    }
    assert(t =~= u) by {
        assert forall|i:int| 0 <= i < t.len() implies t[i] == u[i] by {
            let j = p.len()+1+i;
            assert(x[j] == t[i]); assert(y[j] == u[i]);
        }
    }
    assert(a =~= b) by {
        assert forall|i:int| 0 <= i < a.len() implies a[i] == b[i] by {
            let j = x.len()-a.len()+i;
            assert(x[j] == a[i]); assert(y[j] == b[i]);
        }
    }
}
}
