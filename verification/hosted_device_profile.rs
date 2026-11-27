//! Read the profile admission contract as an exact predicate on live rows.
use crate::device_registration::{self, observed, unique_at};
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

/// One signed envelope and the profile observed when re-entering its authority.
/// The two sides of a reply can observe different snapshots.
pub(super) struct SignedLookup<'a> {
    enabled:bool, keypair:bool, rows:&'a [Registration], fingerprint:&'a str,
    generation:Option<u128>, registry_accepts:bool,
}

impl SignedLookup<'_> {
    pub(super) closed spec fn permitted(&self) -> bool {
        self.enabled && self.keypair && self.registry_accepts
            && exists|i:int| eligible(self.rows@,self.fingerprint,self.generation,i)
    }

    pub(super) fn admission(&self) -> (r:Result<Option<u128>,()>)
        ensures r.is_ok() == self.permitted(),
    {
        if resolve(self.enabled,self.keypair,self.rows,self.fingerprint,self.generation).is_some()
            && self.registry_accepts { Ok(self.generation) } else { Err(()) }
    }
}

}
