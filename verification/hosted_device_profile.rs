//! Read the profile admission contract as an exact predicate on live rows.
use crate::device_registration::{self, observed, unique_at};
use crate::device_session_phase::{self as registry, Binding, Entry, Phase};
use vstd::prelude::*;

verus! {

pub(super) struct Registration { fingerprint:String, generation:Option<u128> }

fn fingerprint(record:&Registration) -> (key:&str)
    ensures key@ == record.fingerprint@,
{ record.fingerprint.as_str() }

fn generation(record:&Registration) -> (g:Option<u128>)
    ensures g == record.generation,
{ record.generation }

spec fn eligible(rows:Seq<Registration>,key:&str,expected:Option<u128>,i:int) -> bool {
    &&& 0 <= i < rows.len()
    &&& rows[i].generation == expected
    &&& forall|j:int| 0 <= j < rows.len() ==> ((#[trigger] rows[j]).fingerprint@ == key@) == (i == j)
}

fn resolve<'a>(enabled:bool, keypair:bool,rows:&'a [Registration],key:&str,expected:Option<u128>)
    -> (result:Option<&'a Registration>)
    ensures
        result.is_some() == (enabled && keypair && exists|i:int| eligible(rows@,key,expected,i)),
        result matches Some(record) ==> exists|i:int| eligible(rows@,key,expected,i) && *record == rows@[i],
{
    let result = device_registration::active(enabled,keypair,rows,key,expected,fingerprint,generation);
    assert forall|j:int,b:bool| 0 <= j < rows.len() && #[trigger] observed(fingerprint,rows@[j],key,b)
        implies (rows@[j].fingerprint@ == key@) == b by {};
    if let Some(record) = result {
        let ghost i = choose|i:int| unique_at(rows@,key,fingerprint,i) && *record == rows@[i];
        assert(eligible(rows@,key,expected,i));
    } else if enabled && keypair {
        assert forall|i:int| !eligible(rows@,key,expected,i) by {
            if eligible(rows@,key,expected,i) {
                assert(rows@[i].fingerprint@ == key@);
                assert(!observed(fingerprint,rows@[i],key,false));
                assert forall|a:int,b:int| 0 <= a < b < rows.len() implies
                    !(observed(fingerprint,rows@[a],key,true) && observed(fingerprint,rows@[b],key,true)) by {};
                assert forall|j:int,g:Option<u128>| unique_at(rows@,key,fingerprint,j)
                    && generation.ensures((&rows@[j],),g) implies g == expected by {
                    assert(observed(fingerprint,rows@[j],key,true));
                }
            }
        }
    }
    result
}

spec fn fenced(owner:&str,key:&str,retire:Option<(&str,&str)>) -> bool {
    retire matches Some((who,which)) && who@ == owner@ && which@ == key@
}

fn same_channel(a:&u64,b:&u64) -> (same:bool)
    ensures same == (*a == *b),
{ *a == *b }

/// Append one fresh challenge to a consistent registry. Other channels may
/// already be serving or pending for this principal or any other principal.
fn bind_after_lookup(mut entries:Vec<Entry<u64>>, channel:u64, owner:&str, key:&str,
    retire:Option<(&str,&str)>) -> (accepted:bool)
    requires forall|i:int| 0 <= i < entries.len() ==> (#[trigger] entries@[i]).phase.consistent()
        && entries@[i].signal != channel,
    ensures accepted == !fenced(owner,key,retire),
{
    let ghost n = entries@.len() as int;
    entries.push(Entry { owner:owner.to_string(), phase:Phase::challenge(), signal:channel });
    let ghost before = entries@;
    if let Some((who,which)) = retire {
        let _drains = registry::retire_entries(entries.as_mut_slice(),who,which);
        assert(registry::updated(before[n],entries@[n],who,which));
    }
    assert(entries@[n].phase.excludes(key@) == fenced(owner,key,retire));
    assert forall|j:int| 0 <= j < n implies (#[trigger] entries@[j]).signal != channel by {
        if let Some((who,which)) = retire {
            assert(registry::updated(before[j],entries@[j],who,which));
        }
    }
    let ghost prior = entries@;
    let outcome = registry::bind_registered(entries.as_mut_slice(),&channel,key.to_string(),same_channel);
    assert forall|i:int| 0 <= i < prior.len() && prior[i].signal == channel implies i == n by {};
    match outcome {Binding::Bound => true, _ => false}
}

/// One signed envelope and the profile observed when re-entering its authority.
/// The two sides of a reply can observe different snapshots.
pub(super) struct SignedLookup<'a> {
    enabled:bool, keypair:bool, rows:&'a [Registration], fingerprint:&'a str,
    generation:Option<u128>, principal:&'a str, retirement:Option<(&'a str,&'a str)>,
}

impl SignedLookup<'_> {
    pub(super) closed spec fn permitted(&self) -> bool {
        self.enabled && self.keypair && !fenced(self.principal,self.fingerprint,self.retirement)
            && exists|i:int| eligible(self.rows@,self.fingerprint,self.generation,i)
    }

    pub(super) fn admission(&self) -> (r:Result<Option<u128>,()>)
        ensures r.is_ok() == self.permitted(),
    {
        if resolve(self.enabled,self.keypair,self.rows,self.fingerprint,self.generation).is_some()
            && bind_after_lookup(Vec::new(),0,self.principal,self.fingerprint,self.retirement) { Ok(self.generation) } else { Err(()) }
    }
}

}
