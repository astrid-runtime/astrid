//! Equality of consent transcripts commits both sides to the same invocation.
use crate::mrtr_context::{absorb_context, injective, Digest};
use vstd::prelude::*;

verus! {
struct Recorder { data: Vec<u8> }

impl Digest for Recorder {
    closed spec fn bytes(&self) -> Seq<u8> { self.data@ }
    fn absorb(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
    }
}

fn encode(principal: &[u8], tool: &[u8], arguments: &[u8]) -> (out: Vec<u8>)
    ensures out@ == crate::mrtr_context::transcript(principal@, tool@, arguments@),
{
    let mut recorder = Recorder { data: Vec::new() };
    absorb_context(&mut recorder, principal, tool, arguments);
    recorder.data
}

fn same_invocation(p:&[u8], t:&[u8], a:&[u8], q:&[u8], u:&[u8], b:&[u8]) -> (out:(Vec<u8>,Vec<u8>))
    requires !p@.contains(0), !q@.contains(0), !a@.contains(0), !b@.contains(0),
    ensures (out.0@ == out.1@) == (p@ == q@ && t@ == u@ && a@ == b@),
{
    let first = encode(p,t,a);
    let second = encode(q,u,b);
    proof { if first@ == second@ { injective(p@,t@,a@,q@,u@,b@); } }
    (first,second)
}

spec fn valid_principal(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() <= 64 && forall|i:int| 0 <= i < bytes.len() ==> crate::principal_syntax::allowed(#[trigger] bytes[i])
}

/// Discharge the principal delimiter condition using the actual constructor grammar.
fn validated_principal(bytes: &[u8]) -> (accepted:bool)
    ensures accepted == valid_principal(bytes@), accepted ==> !bytes@.contains(0),
{
    if let crate::principal_syntax::Syntax::Valid = crate::principal_syntax::classify(bytes) {
        proof {
            if bytes@.contains(0) {
                let i = choose|i:int| 0 <= i < bytes.len() && bytes@[i] == 0;
                assert(crate::principal_syntax::allowed(bytes@[i]));
            }
        }
        true
    } else { false }
}

fn validated_transcripts(p:&[u8], t:&[u8], a:&[u8], q:&[u8], u:&[u8], b:&[u8])
    -> (out:Option<(Vec<u8>,Vec<u8>)>)
    requires !a@.contains(0), !b@.contains(0),
    ensures out.is_some() == (valid_principal(p@) && valid_principal(q@)),
        out matches Some(pair) ==> ((pair.0@ == pair.1@) == (p@ == q@ && t@ == u@ && a@ == b@)),
{
    if validated_principal(p) && validated_principal(q) {
        Some(same_invocation(p,t,a,q,u,b))
    } else { None }
}

/// Test the composed contract with an opener that checks its supplied state
/// and context and a redemption store that can independently refuse a claim.
fn checked_resume<'a>(state:&'a str, context:&'a [u8], authentic:bool, available:bool)
    -> (result:Result<((&'a str,&'a [u8]),&'a str),u8>)
    ensures result == if !authentic { Err(1u8) } else if !available { Err(2u8) }
        else { Ok(((state,context),state)) },
{
    crate::mrtr_context::open_and_redeem(state,context,
        |token:&'a str, binding:&'a [u8]| -> (r:Result<(&'a str,&'a [u8]),u8>)
            ensures r == if authentic { Ok((token,binding)) } else { Err(1u8) },
        { if authentic { Ok((token,binding)) } else { Err(1) } },
        |token:&'a str| -> (r:Result<&'a str,u8>)
            ensures r == if available { Ok(token) } else { Err(2u8) },
        { if available { Ok(token) } else { Err(2) } })
}

/// Serial lock observations from two callers. Cancellation reopens only the
/// first digest; settlement leaves the latest observed deadline installed.
fn competing_claims<T,E>(entries:&mut std::collections::HashMap<[u8;32],u64>,
    id:[u8;32], first:u64, next:u64, outcome:Result<T,E>) -> (reply:Result<T,E>)
    requires vstd::std_specs::hash::hash_map_inv(old(entries)),
        vstd::std_specs::hash::obeys_key_model::<[u8;32]>(), vstd::laws_eq::obeys_concrete_eq::<[u8;32]>(), !old(entries)@.contains_key(id),
    ensures vstd::std_specs::hash::hash_map_inv(final(entries)),
        reply == outcome,
        final(entries)@ == if outcome.is_ok() { old(entries)@.insert(id,next) } else { old(entries)@ },
{
    let ghost before = entries@;
    let mut claim = crate::mrtr_redemption::reserve(entries,id,first).unwrap();
    let duplicate = crate::mrtr_redemption::reserve(entries,id,next);
    assert(duplicate.is_none());
    let result = claim.finish(outcome);
    if !claim.committed() { claim.on_drop(entries); }
    assert(entries@ =~= if outcome.is_ok() { before.insert(id,next) } else { before });
    result
}

/// Observe the consent input and the complete envelope at the publishing callback.
fn consent_and_publication<'a>(name:&'a str, args:&'a Vec<u8>, id:&'a str)
    -> (out:((&'a str,&'a Vec<u8>),(&'static str,&'a str,(&'a str,&'a str,&'a Vec<u8>))))
    ensures out.0 == (name,args), out.1.0@ == "astrid.v1.request.mcp.tool.call"@,
        out.1.1 == id, out.1.2 == (id,out.0.0,out.0.1),
{
    let invocation = crate::invocation::Invocation::new(name,args);
    let consent = invocation.consent_context();
    let sent = invocation.publish(id,
        |r:&'a str,n:&'a str,a:&'a Vec<u8>| -> (b:(&'a str,&'a str,&'a Vec<u8>))
            ensures b == (r,n,a), { (r,n,a) },
        |t:&'static str,r:&'a str,b:(&'a str,&'a str,&'a Vec<u8>)| -> (s:(&'static str,&'a str,(&'a str,&'a str,&'a Vec<u8>)))
            ensures s == (t,r,b), { (t,r,b) });
    (consent,sent)
}

/// A peer reading the full client frame consumes precisely the first payload,
/// even when the transport has already delivered bytes of subsequent frames.
fn receive_serialized_call(body:&[u8], tail:&[u8], limit:usize, chunk:usize) -> (out:(Vec<u8>,usize))
    requires chunk > 0, body.len() <= u32::MAX, body.len() <= limit,
        4 + body.len() + tail.len() <= usize::MAX,
    ensures out.0@ == body@, out.1 == 4 + body.len(),
{
    use crate::native_frame_segments::{body_prefix, declared, incoming, FrameSegments, Incoming};
    let prefix = body_prefix(body).unwrap();
    let mut stream = Vec::new();
    let mut frame = FrameSegments::new(&prefix,body);
    loop
        invariant chunk > 0, stream@ + frame.remaining() == prefix@ + body@,
        ensures stream@ == prefix@ + body@,
        decreases frame.remaining().len(),
    {
        let offer = frame.next();
        if offer.is_empty() {
            assert(frame.remaining() =~= Seq::<u8>::empty());
            assert(stream@ =~= prefix@ + body@);
            break;
        }
        let count = offer.len().min(chunk);
        assert(0 < count <= frame.offered());
        let (written,_) = offer.split_at(count);
        let ghost remaining = frame.remaining();
        stream.extend_from_slice(written);
        let accepted = frame.accept(count);
        assert(accepted);
        assert(written@ + frame.remaining() =~= remaining);
        assert(stream@ + frame.remaining() =~= prefix@ + body@);
    }
    assert(stream@ =~= prefix@ + body@);
    stream.extend_from_slice(tail);
    assert(stream@.take(4) =~= prefix@);
    assert(declared(stream@) == body.len());
    assert(stream@.subrange(4,4 + body.len()) =~= body@);
    match incoming(&stream,limit) {
        Incoming::Complete { body:payload, consumed } => {
            let mut received = Vec::new();
            received.extend_from_slice(payload);
            (received,consumed)
        },
        _ => { assert(false); (Vec::new(),0) },
    }
}
}
