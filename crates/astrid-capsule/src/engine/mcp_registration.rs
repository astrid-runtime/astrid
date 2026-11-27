//! The manager name of a server belonging to one capsule runtime incarnation.
use vstd::prelude::*;

verus! {

pub(crate) open spec fn decimal(n: u64) -> Seq<char>
    decreases n,
{
    let prefix = if n < 10 { Seq::empty() } else { decimal(n / 10) };
    prefix.push(((48 + n % 10) as u8) as char)
}

/// The last hyphen marks the start of the decimal suffix even if the server contains colons.
pub(crate) proof fn distinct_generations(a: Seq<char>, b: Seq<char>, n: u64, m: u64)
    requires a.push('-') + decimal(n) == b.push('-') + decimal(m),
    ensures n == m,
    decreases n,
{
    reveal_with_fuel(decimal, 2);
    let left = if n < 10 { a.push('-') } else { a.push('-') + decimal(n / 10) };
    let right = if m < 10 { b.push('-') } else { b.push('-') + decimal(m / 10) };
    let encoded = a.push('-') + decimal(n);
    assert(encoded =~= left.push(((48 + n % 10) as u8) as char));
    assert(encoded =~= right.push(((48 + m % 10) as u8) as char));
    assert(left.len() == right.len());
    assert(left =~= right) by {
        assert forall|i:int| 0 <= i < left.len() implies left[i] == right[i] by {
            assert(left[i] == encoded[i]);
            assert(right[i] == encoded[i]);
        }
    }
    assert(encoded.last() == ((48 + n % 10) as u8) as char);
    assert(encoded.last() == ((48 + m % 10) as u8) as char);
    assert(n % 10 == m % 10);
    if n >= 10 && m >= 10 {
        distinct_generations(a, b, n / 10, m / 10);
    } else if n >= 10 {
        assert(left.last() == decimal(n / 10).last());
        assert(decimal(n / 10).last() == ((48 + (n / 10) % 10) as u8) as char);
    } else if m >= 10 {
        assert(right.last() == decimal(m / 10).last());
        assert(decimal(m / 10).last() == ((48 + (m / 10) % 10) as u8) as char);
    }
}

fn append_generation(name: &mut String, n: u64)
    ensures final(name)@ == old(name)@ + decimal(n),
    decreases n,
{
    if n >= 10 {
        append_generation(name, n / 10);
    }
    name.push(((48 + n % 10) as u8) as char);
    assert(final(name)@ =~= old(name)@ + decimal(n));
}

pub(crate) open spec fn prefix(capsule: Seq<char>, server: Seq<char>,
    principal: Option<Seq<char>>) -> Seq<char>
{
    "capsule:"@ + capsule + ":server-"@ + server
        + (match principal { Some(uid) => ":principal-"@ + uid, None => ":system"@ })
        + ":generation"@
}

pub(crate) open spec fn registration(capsule: Seq<char>, server: Seq<char>,
    principal: Option<Seq<char>>, generation: u64) -> Seq<char>
{
    prefix(capsule, server, principal).push('-') + decimal(generation)
}

pub(crate) fn name(capsule: &str, server: &str, principal: Option<&str>, generation: u64)
    -> (result: String)
    ensures result@ == registration(capsule@, server@, match principal { Some(uid) => Some(uid@), None => None }, generation),
{
    let mut result = "capsule:".to_owned();
    result.push_str(capsule);
    result.push_str(":server-");
    result.push_str(server);
    match principal {
        Some(uid) => {
            result.push_str(":principal-");
            result.push_str(uid);
        },
        None => result.push_str(":system"),
    }
    result.push_str(":generation");
    result.push('-');
    append_generation(&mut result, generation);
    result
}

pub(crate) fn runtime_name<'a,I,A,S:Copy,C:Fn(&'a I) -> &'a str,P:Fn(S) -> Option<String>>(
    runtime: &'a super::RegistryId<I,A,S>, server: &str, capsule: C, principal: P,
) -> (out: String)
    requires capsule.requires((&runtime.identity().0.0,)), principal.requires((runtime.identity().0.2,)),
    ensures exists|c:&str, p:Option<String>| capsule.ensures((&runtime.identity().0.0,),c)
        && principal.ensures((runtime.identity().0.2,),p)
        && out@ == registration(c@, server@, match p { Some(uid) => Some(uid@), None => None }, runtime.identity().1),
{
    let key = runtime.key();
    let capsule_text = capsule(key.capsule_id());
    let principal_text = principal(key.scope());
    #[expect(clippy::manual_map, reason = "the pinned verifier checks this match and lacks an Option::as_deref specification")]
    let uid = match &principal_text {
        Some(value) => Some(value.as_str()),
        None => None,
    };
    let out = name(capsule_text, server, uid, runtime.generation());
    proof { assert(capsule.ensures((&runtime.identity().0.0,),capsule_text)); }
    out
}
}
