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
fn competing_claims(entries:&mut std::collections::HashMap<[u8;32],u64>,
    id:[u8;32], first:u64, next:u64, commit:bool)
    requires vstd::std_specs::hash::hash_map_inv(old(entries)),
        vstd::std_specs::hash::obeys_key_model::<[u8;32]>(), vstd::laws_eq::obeys_concrete_eq::<[u8;32]>(), !old(entries)@.contains_key(id),
    ensures vstd::std_specs::hash::hash_map_inv(final(entries)),
        final(entries)@ == if commit { old(entries)@.insert(id,next) } else { old(entries)@ },
{
    let ghost before = entries@;
    let mut claim = crate::mrtr_redemption::reserve(entries,id,first).unwrap();
    let duplicate = crate::mrtr_redemption::reserve(entries,id,next);
    assert(duplicate.is_none());
    if commit { claim.commit(); }
    if !claim.committed() { claim.on_drop(entries); }
    assert(entries@ =~= if commit { before.insert(id,next) } else { before });
}
}
